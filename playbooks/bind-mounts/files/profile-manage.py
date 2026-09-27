#!/usr/bin/env python3
"""Managed by bind-mounts.yml (ansible). Helper: add, replace, or remove ONLY
the managed block owned by this playbook in a user's .bash_profile. Every other
line is preserved; edits are atomic and keep the original owner and mode.

The block carries unique markers (OWN_START/OWN_END), so a stock
ansible.builtin.blockinfile block written by another role is never matched,
counted, edited, or deleted. Two earlier forms are still recognised as ours
and are rewritten with the unique markers by the next apply: a block carrying
the stock markers whose body invokes this playbook's guest script, and the
original marker-less form (the bare hook lines).

Usage: profile-manage.py apply|remove <profile-path> <uid> <gid> <script-path>
Exit codes: 0 = success; 2 = refused (ambiguous markers or bad usage).
"""
import os
import sys
import tempfile

OWN_START = "# BEGIN BIND-MOUNTS MANAGED BLOCK"
OWN_END = "# END BIND-MOUNTS MANAGED BLOCK"
STOCK_START = "# BEGIN ANSIBLE MANAGED BLOCK"
STOCK_END = "# END ANSIBLE MANAGED BLOCK"
HOOK_COMMAND = "bind-mount-on-guest.sh"


def block_lines(script_path):
    """The managed block's lines, invoking the configured guest script."""
    return [
        OWN_START,
        f"if [ -x {script_path} ]; then",
        f"    sudo -n {script_path}",
        "fi",
        OWN_END,
    ]


def marker_block(lines, start, end):
    """Line indexes of the single start/end marker pair, or None if absent.

    Raises ValueError when the pair is duplicated, unpaired, or ordered
    end-before-start: editing around an ill-formed pair would damage lines
    this helper does not own.
    """
    starts = [i for i, line in enumerate(lines) if line == start]
    ends = [i for i, line in enumerate(lines) if line == end]
    if not starts:
        if ends:
            raise ValueError(f"found {end!r} with no {start!r}")
        return None
    if len(starts) > 1 or len(ends) > 1:
        raise ValueError(f"more than one {start!r} block")
    if not ends or ends[0] < starts[0]:
        raise ValueError(f"{start!r} has no closing {end!r}")
    return starts[0], ends[0]


def stock_blocks(lines):
    """Index pairs of the stock-marker blocks, each paired with the next end.

    An unterminated start marker is skipped, so a file that breaks
    blockinfile's own pairing rules costs this helper nothing.
    """
    blocks = []
    i = 0
    while i < len(lines):
        if lines[i] != STOCK_START:
            i += 1
            continue
        end = next((j for j in range(i + 1, len(lines)) if lines[j] == STOCK_END), None)
        if end is None:
            i += 1
            continue
        blocks.append((i, end))
        i = end + 1
    return blocks


def is_ours(lines, block):
    """True when the block's body invokes this playbook's guest script."""
    return any(
        HOOK_COMMAND in line and ("sudo -n " in line or line.startswith("if [ -x "))
        for line in lines[block[0] + 1:block[1]]
    )

def legacy_block(lines):
    """Index pair of the marker-less hook written before this helper used
    markers, or None when there is none."""
    first = next(
        (i for i, line in enumerate(lines)
         if line.startswith("if [ -x ") and HOOK_COMMAND in line),
        None,
    )
    if first is None:
        return None
    last = next(
        (j for j in range(first + 1, min(first + 5, len(lines)))
         if lines[j].rstrip() == "fi"),
        None,
    )
    if last is None:
        raise ValueError("the legacy bind-mount block has no closing 'fi' within 4 lines")
    return first, last


def plan(mode, lines, profile, existed, script_path):
    """Return (new_lines, message) for one edit, or (None, message) when the
    file is already in the wanted state. Raises ValueError when the markers
    are ambiguous."""
    block = block_lines(script_path)
    own = marker_block(lines, OWN_START, OWN_END)
    ours = [pair for pair in stock_blocks(lines) if is_ours(lines, pair)]
    if len(ours) > 1:
        raise ValueError("more than one managed block carries the stock markers")

    if mode == "remove":
        target = own or (ours[0] if ours else None) or legacy_block(lines)
        if target is None:
            return None, f"no managed block in {profile}; nothing to remove"
        return lines[:target[0]] + lines[target[1] + 1:], f"removed managed block from {profile}"

    if own is not None:
        if lines[own[0]:own[1] + 1] == block:
            return None, f"unchanged managed block in {profile}"
        return lines[:own[0]] + block + lines[own[1] + 1:], f"updated managed block in {profile}"
    if ours:
        first, last = ours[0]
        return lines[:first] + block + lines[last + 1:], (
            f"updated managed block in {profile} (migrated the stock markers)")
    legacy = legacy_block(lines)
    if legacy is not None:
        return lines[:legacy[0]] + block + lines[legacy[1] + 1:], (
            f"replaced the legacy bind-mount block in {profile}")
    if not existed:
        return list(block), f"created {profile} with the managed block"
    return lines + [""] + block, f"appended managed block to {profile}"


def main():
    if len(sys.argv) != 6:
        print("usage: profile-manage.py apply|remove <profile-path> <uid> <gid> <script-path>", file=sys.stderr)
        return 2
    mode, profile = sys.argv[1], sys.argv[2]
    owner_uid, owner_gid = int(sys.argv[3]), int(sys.argv[4])
    script_path = sys.argv[5]
    if mode not in ("apply", "remove"):
        print(f"error: unknown mode {mode!r} (use apply or remove)", file=sys.stderr)
        return 2

    existed = os.path.exists(profile)
    if existed:
        with open(profile, encoding="utf-8") as f:
            lines = f.read().splitlines()
    else:
        lines = []

    try:
        new_lines, message = plan(mode, lines, profile, existed, script_path)
    except ValueError as exc:
        print(f"error: {exc} in {profile}; refusing to edit", file=sys.stderr)
        return 2

    if new_lines is not None:
        fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(os.path.abspath(profile)) or ".",
            prefix=".profile-manage.",
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines) + "\n")
        if existed:
            st = os.stat(profile)
            os.chmod(tmp, st.st_mode & 0o7777)
            os.chown(tmp, st.st_uid, st.st_gid)
        else:
            os.chmod(tmp, 0o644)
            os.chown(tmp, owner_uid, owner_gid)
        os.replace(tmp, profile)
    print(message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
