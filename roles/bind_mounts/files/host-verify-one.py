#!/usr/bin/env python3
"""Host-side verify for ONE share-tree bind subdirectory.

Read-only observation: it never mounts or unmounts. A target verifies when
it is exactly one layer bound from the configured source (device:inode
identity, as bind mounts share stat identity with their source) and carries
the configured readonly state.

Usage: host-verify-one.py <configured-source> <host-target> <readonly>
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
    if len(sys.argv) != 4:
        print("usage: host-verify-one.py <src> <host-target> <readonly>", file=sys.stderr)
        return 2
    src, target, readonly = sys.argv[1], sys.argv[2], sys.argv[3]

    if not is_mountpoint(target):
        print(f"verify FAIL (host): {target} is not mounted", file=sys.stderr)
        return 1
    if stat_id(src) != stat_id(target):
        print(f"verify FAIL (host): {target} does not match {src} (device:inode differ)", file=sys.stderr)
        return 1
    opts = subprocess.run(
        ["findmnt", "-rn", "-o", "OPTIONS", "-M", target],
        capture_output=True, text=True,
    ).stdout.splitlines()[0]
    ro_now = "ro" in opts.split(",")
    if (readonly == "true") != ro_now:
        print(f"verify FAIL (host): {target} is {'read-only' if ro_now else 'read-write'} but config wants {'read-only' if readonly == 'true' else 'read-write'}", file=sys.stderr)
        return 1
    layers = [l for l in subprocess.run(
        ["findmnt", "-rn", "-o", "TARGET", "-M", target],
        capture_output=True, text=True,
    ).stdout.splitlines() if l == target]
    if len(layers) > 1:
        print(f"verify FAIL (host): {target} has {len(layers)} stacked mounts; expected 1", file=sys.stderr)
        return 1
    print(f"verify ok (host): {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
