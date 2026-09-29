#!/usr/bin/env python3
"""Managed by bind-mounts.yml (ansible). Helper: verify ONE guest mount.

Identity check compares device and inode of the target against the expected
share source (bind mounts share stat identity with their source). In bind
mode the target's readonly state is also compared against the expectation.

Usage: guest-verify-one.py bind <target> <expected-share-source> <readonly>
       guest-verify-one.py direct <target>
Exit codes: 0 = verified; 1 = not mounted, wrong source, wrong ro state, or
stacked mounts (more than one layer at the target).
"""
import os
import subprocess
import sys


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


def main():
    if len(sys.argv) not in (3, 5):
        print("usage: guest-verify-one.py bind <target> <expected-source> <readonly> | direct <target>", file=sys.stderr)
        return 2
    mode, target = sys.argv[1], sys.argv[2]
    expected = sys.argv[3] if len(sys.argv) > 3 else None

    if not is_mountpoint(target):
        print(f"verify FAIL (guest): {target} is not mounted", file=sys.stderr)
        return 1
    if mode == "bind":
        share, readonly = sys.argv[3], sys.argv[4]
        if stat_id(target) != stat_id(share):
            print(f"verify FAIL (guest): {target} does not match {share} (device:inode differ)", file=sys.stderr)
            return 1
        opts = subprocess.run(
            ["findmnt", "-rn", "-o", "OPTIONS", "-M", target],
            capture_output=True, text=True,
        ).stdout.splitlines()[0]
        ro_now = "ro" in opts.split(",")
        if (readonly == "true") != ro_now:
            print(f"verify FAIL (guest): {target} is {'read-only' if ro_now else 'read-write'} but config wants {'read-only' if readonly == 'true' else 'read-write'}", file=sys.stderr)
            return 1
        layers = [l for l in subprocess.run(
            ["findmnt", "-rn", "-o", "TARGET", "-M", target],
            capture_output=True, text=True,
        ).stdout.splitlines() if l == target]
        if len(layers) > 1:
            print(f"verify FAIL (guest): {target} has {len(layers)} stacked mounts; expected 1", file=sys.stderr)
            return 1
    print(f"verify ok (guest): {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
