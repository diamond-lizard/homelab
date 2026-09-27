#!/usr/bin/env python3
"""Managed by bind-mounts.yml (ansible). Helper: ensure ONE guest bind mount.

Idempotent. Refuses to touch any mount it did not create.
Identity check: a bind mount shares the device and inode of its source, so the
helper compares stat(dev, ino) of the target against the share source. (The
guest mount table reports source as 'none' for these binds, so source paths
cannot be compared.)
On an already-mounted target whose readonly state drifted from the request,
the helper remounts the bind read-only or read-write as requested.

Usage: guest-mount-one.py <target> <share-source> <uid> <gid> <readonly>
Exit codes: 0 = already mounted (or remounted) or mounted now;
3 = foreign mount (never touched); 4 = empty share source (never bound).
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
    if len(sys.argv) != 6:
        print("usage: guest-mount-one.py <target> <share> <uid> <gid> <readonly>", file=sys.stderr)
        return 2
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
                return 0
            print(f"ok: {target} already mounted from {share}")
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
