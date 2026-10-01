#!/usr/bin/env python3
"""Managed by bind-mounts.yml (ansible). Helper: ensure ONE guest bind mount.

Idempotent. Refuses to touch any mount it did not create.
Identity check: a bind mount shares the device and inode of its source, so the
helper compares stat(dev, ino) of the target against the share source. (The
guest mount table reports source as 'none' for these binds, so source paths
cannot be compared.)
On an already-mounted target whose readonly state drifted from the request,
the helper remounts the bind read-only or read-write as requested.

Every ensured mount (already mounted, remounted, or mounted now) additionally
prints one machine-readable TRIPLE line carrying the live mountinfo triple of
the target. The triple is read from /proc/self/mountinfo rather than findmnt:
mountinfo is the kernel's own authoritative table (findmnt merely renders it),
one line per mount with fstype, source and root taken straight from the fields
around the '-' separator, no display-column merging or decoration.

TRIPLE line format (stdout, exactly one per ensured mount):

  TRIPLE fstype=<fstype> source=<source> root=<root>

The three values are the mountinfo fields of the TOP layer at the target (the
newest mount there, i.e. the largest mount id, which is what the path resolves
to): the filesystem type, the superblock source string, and the root subpath
inside that filesystem. Each value carries the kernel's mountinfo escaping
(space=\040, tab=\011, newline=\012, backslash=\134), so no field ever
contains whitespace and the line splits cleanly on spaces.

The stale-umount subcommand removes a recorded layer safely: given a target
and a previously recorded triple, it umounts only when the live top layer at
the target is bind-type (its mountinfo root subpath is not '/') and its live
triple equals the recorded triple. A real filesystem mount such as an smolvm
volume mounted at its filesystem root (root '/') is never umounted. On
refusal both triples are printed as LIVE:/RECORDED: lines and nothing is
mutated. It removes at most the one top layer it verified; stack iteration
(pops one at a time, stops at the first mismatch) stays with the caller.

A kernel //deleted mount root (the mounted directory was unlinked, so
mountinfo renders the root with a literal '//deleted' suffix) is umounted
only in the additive deleted-ours form: the host proves the layer ours by
stripping the marker and matching the stripped root against the recorded
root (fstype and source equal besides), and passes that verdict as the
extra argument; without the argument a //deleted layer is refused like any
other mismatch. //deleted remediation necessarily runs on a running
machine: a stopped machine holds no guest binds at all.

Usage: guest-mount-one.py <target> <share-source> <uid> <gid> <readonly>
       guest-mount-one.py stale-umount <target> <fstype> <source> <root>
       guest-mount-one.py stale-umount <target> <fstype> <source> <root> deleted-ours
Exit codes (ensure form): 0 = already mounted (or remounted) or mounted now;
3 = foreign mount (never touched); 4 = empty share source (never bound).
Exit codes (stale-umount form): 0 = the verified bind layer was umounted;
6 = refused, nothing mutated (recorded and live triples differ, or the live
layer is a real filesystem mount with root subpath '/'; both triples printed
as LIVE:/RECORDED: lines); 7 = target not mounted (nothing to remove);
1 = the umount syscall failed (nothing removed); 2 = usage error.
"""
import ctypes
import os
import subprocess
import sys

USAGE_ERR = 2
FOREIGN_RC = 3
EMPTY_SHARE_RC = 4
REFUSED_RC = 6
NOT_MOUNTED_RC = 7

_MNT_DETACH = 2
_MOUNTINFO_ESCAPES = {"\\040": " ", "\\011": "\t", "\\012": "\n", "\\134": "\\"}


def is_mountpoint(path):
    probe = subprocess.run(
        ["findmnt", "-rn", "-o", "TARGET", "-M", path],
        capture_output=True, text=True,
    )
    # Stacked mounts print one line per layer; presence is decided by rc only.
    return probe.returncode == 0


def stat_id(path):
    st = os.stat(path)
    return f"{st.st_dev}:{st.st_ino}"


def top_triple(path):
    """(fstype, source, root) of the top layer at path, escaped as in
    /proc/self/mountinfo; None when the path carries no mount.

    /proc/self/mountinfo line: mount-id parent major:minor root mount-point
    options [optional fields] - fstype source super-options. The top layer is
    the newest mount at the path (largest mount id), which is what the path
    resolves to and what umount would remove.
    """
    best = None
    with open("/proc/self/mountinfo", encoding="utf-8") as table:
        for line in table:
            fields = line.rstrip("\n").split()
            try:
                sep = fields.index("-")
            except ValueError:
                continue
            if len(fields) < sep + 3 or fields[4] != path:
                continue
            try:
                mnt_id = int(fields[0])
            except ValueError:
                continue
            if best is None or mnt_id > best[0]:
                best = (mnt_id, fields[sep + 1], fields[sep + 2], fields[3])
    if best is None:
        return None
    return best[1], best[2], best[3]


def print_triple(path):
    """Emit the machine-readable TRIPLE line for the top layer at path."""
    triple = top_triple(path)
    if triple is None:
        # Only reachable if the mount table changed under us mid-run; the
        # host records the absence and the entry rides the legacy (unrecorded)
        # lane: reported, never removed, re-marked on the next re-mount.
        print(f"warning: {path} has no /proc/self/mountinfo entry; no TRIPLE line emitted", file=sys.stderr)
        return
    print(f"TRIPLE fstype={triple[0]} source={triple[1]} root={triple[2]}")


def cmd_stale_umount(target, recorded, deleted_ours=False):
    live = top_triple(target)
    if live is None:
        print(f"STALE-UMOUNT: {target} is not mounted; nothing to remove", file=sys.stderr)
        return NOT_MOUNTED_RC
    live_line = f"LIVE:     fstype={live[0]} source={live[1]} root={live[2]}"
    recorded_line = f"RECORDED: fstype={recorded[0]} source={recorded[1]} root={recorded[2]}"
    # A guest bind FROM a propagated host-bind submount renders fsroot '/'
    # with source 'none': it is not a real filesystem mount. The triple
    # equality check below licenses the umount only when the recorded triple
    # (proven ours in the ledger) matches the live one, so a real smolvm
    # volume (source 'smolvm0') or any genuine filesystem mount still
    # refuses here.
    propagated_submount = (live[2] == "/" and live[0] == "virtiofs"
                           and live[1] == "none" and recorded[2] == "/"
                           and recorded[0] == "virtiofs"
                           and recorded[1] == "none")
    if live[2] == "/" and not propagated_submount:
        print(f"STALE-UMOUNT-REFUSED: {target} holds a real filesystem mount (mountinfo root subpath '/'); this helper never umounts it", file=sys.stderr)
        print(live_line, file=sys.stderr)
        print(recorded_line, file=sys.stderr)
        return REFUSED_RC
    if deleted_ours:
        # The host proved this //deleted layer ours: the marker stripped
        # from the live root matches the recorded root (fstype and source
        # equal besides), so the equality check below relaxes to the
        # stripped root. Wrong or missing proof takes the refusal path.
        # The //deleted marker also renders inside the SOURCE string
        # ("tmpfs[/del-src//deleted]"): normalize both sides by stripping any
        # "[...]" bracket rendering before comparing, as the root relax
        # already strips the marker from the fsroot.
        if (live[0], live[1].split('[')[0]) != (recorded[0], recorded[1].split('[')[0]) \
                or live[2][:-len('//deleted')] != recorded[2]:
            print(f"STALE-UMOUNT-REFUSED: {target} holds a //deleted layer the host did not prove ours; nothing was changed", file=sys.stderr)
            print(live_line, file=sys.stderr)
            print(recorded_line, file=sys.stderr)
            return REFUSED_RC
    elif live != recorded:
        print(f"STALE-UMOUNT-REFUSED: {target} holds a different layer than the one recorded at mount time; nothing was changed", file=sys.stderr)
        print(live_line, file=sys.stderr)
        print(recorded_line, file=sys.stderr)
        return REFUSED_RC
    # Pin the mount before acting on it: resolve the parent directory to an
    # O_PATH descriptor, then the final component un-followed, so a path
    # swapped between the check above and the syscall cannot redirect the
    # umount elsewhere. umount2(MNT_DETACH) on the pinned fd removes exactly
    # the verified layer, even if a fresh layer was stacked above it in the
    # meantime (the lazy detach makes a covered umount possible without
    # touching the layer above).
    parent_fd = os.open(os.path.dirname(target), os.O_PATH)
    try:
        pinned_fd = os.open(
            os.path.basename(target),
            os.O_PATH | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            link = f"/proc/self/fd/{pinned_fd}".encode()
            ctypes.set_errno(0)
            rc = libc.umount2(ctypes.c_char_p(link), ctypes.c_uint(_MNT_DETACH))
            if rc != 0:
                err = ctypes.get_errno()
                print(f"STALE-UMOUNT-ERROR: umount2 {target} failed: {os.strerror(err)} (errno {err})", file=sys.stderr)
                return 1
        finally:
            os.close(pinned_fd)
    finally:
        os.close(parent_fd)
    print(f"umounted: {target} (recorded fstype={recorded[0]} source={recorded[1]} root={recorded[2]})")
    remaining = top_triple(target)
    if remaining is not None:
        print(f"note: {target} still carries a lower layer; the caller pops layers one at a time", file=sys.stderr)
    return 0


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "stale-umount":
        target = sys.argv[2]
        if not os.path.isabs(target):
            print("usage: guest-mount-one.py stale-umount <target> <fstype> <source> <root>", file=sys.stderr)
            return USAGE_ERR
        return cmd_stale_umount(target, tuple(sys.argv[3:6]))
    if len(sys.argv) == 7 and sys.argv[1] == "stale-umount" and sys.argv[6] == "deleted-ours":
        target = sys.argv[2]
        if not os.path.isabs(target):
            print("usage: guest-mount-one.py stale-umount <target> <fstype> <source> <root> deleted-ours", file=sys.stderr)
            return USAGE_ERR
        return cmd_stale_umount(target, tuple(sys.argv[3:6]), deleted_ours=True)
    if len(sys.argv) != 6:
        print("usage: guest-mount-one.py <target> <share> <uid> <gid> <readonly>", file=sys.stderr)
        print("       guest-mount-one.py stale-umount <target> <fstype> <source> <root>", file=sys.stderr)
        print("       guest-mount-one.py stale-umount <target> <fstype> <source> <root> deleted-ours", file=sys.stderr)
        return USAGE_ERR
    target, share, owner_uid, owner_gid, readonly = sys.argv[1:6]

    if is_mountpoint(target):
        if stat_id(target) == stat_id(share):
            if not os.listdir(share):
                print(f"warning: {target} is mounted but {share} is empty; the host-side bind is probably missing", file=sys.stderr)
            # Stack collapse on the host side is the probe's job; the helper
            # only judges the top layer, which is the live view.
            opts = subprocess.run(
                ["findmnt", "-rn", "-o", "OPTIONS", "-M", target],
                capture_output=True, text=True,
            ).stdout.splitlines()[0]
            ro_now = "ro" in opts.split(",")
            if (readonly == "true") != ro_now:
                subprocess.run(
                    ["mount", "-o", f"remount,{'ro' if readonly == 'true' else 'rw'},bind", target],
                    check=True,
                )
                print(f"remounted: {target} {'read-only' if readonly == 'true' else 'read-write'}")
                print_triple(target)
                return 0
            print(f"ok: {target} already mounted from {share}")
            print_triple(target)
            return 0
        print(f"FOREIGN: {target} is a mountpoint whose content differs from {share}", file=sys.stderr)
        print("FOREIGN: this helper never touches mounts it did not create; unmount it manually", file=sys.stderr)
        return 3

    if not os.listdir(share):
        print(f"EMPTY-SHARE: {share} is empty; the host-side bind is probably missing (did the host reboot?).", file=sys.stderr)
        print("EMPTY-SHARE: remedy: run the playbook on the host, then log in again.", file=sys.stderr)
        print("EMPTY-SHARE: refusing to bind an empty share directory.", file=sys.stderr)
        return 4
    existed = os.path.isdir(target)
    os.makedirs(target, exist_ok=True)
    if not existed:
        os.chown(target, int(owner_uid), int(owner_gid))
    subprocess.run(["mount", "--bind", share, target], check=True)
    if readonly == "true":
        subprocess.run(["mount", "-o", "remount,ro,bind", target], check=True)
    print(f"mounted: {target} from {share}")
    print_triple(target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
