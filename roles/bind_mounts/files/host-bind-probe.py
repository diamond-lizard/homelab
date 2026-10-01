#!/usr/bin/env python3
"""Host-side bind identity probe for the share tree.

Decides whether the live mount at one share subdirectory is this playbook's
own and what to do about it: 0 = bound from the configured source (or the
top layer is and the stack collapses on a stopped machine); 3 = the stack
holds layers the ledger cannot prove ours; 4 = stale or foreign and the
machine is running; 10 = REMEDIATE, bind the configured source. stdout:
LAYERS:, LAYER-SRC:, RO-STATE:, ALLOW-PREFIX:; stderr carries refusals.
"""
import json
import os
import subprocess
import sys

from host_bind_layers import (deleted_ours, layer_display, layer_forced,
                              layer_label, layer_provable, layer_removable,
                              mount_lines, norm, ro_state, stat_id, subpath)


def refuse_stack(tgt, src, layers, bad, force_named):
    print(f"REFUSED: {tgt} is bound from different content than {src}, and this run", file=sys.stderr)
    print("REFUSED: cannot prove it created every layer of the stack.", file=sys.stderr)
    print("REFUSED:   layers at that path, bottom first:", file=sys.stderr)
    for l in layers:
        print(f"REFUSED:     {layer_display(l)}", file=sys.stderr)
    for l in bad:
        print(f"ALLOW-PREFIX: /{subpath(l)}")
    print("REFUSED: nothing was mounted, unmounted or otherwise changed.", file=sys.stderr)
    print("REFUSED: to rebuild the mount from the configured source, re-run with", file=sys.stderr)
    print("REFUSED:   -e bind_mounts_force_remount=true", file=sys.stderr)
    print("REFUSED: force accepts a layer the playbook cannot prove only when", file=sys.stderr)
    print("REFUSED: its path is named explicitly:", file=sys.stderr)
    print(f"REFUSED:   -e bind_mounts_force_allow_prefixes={force_named}", file=sys.stderr)
    print("REFUSED: to clear it by hand, with the machine stopped:", file=sys.stderr)
    print(f"REFUSED:   sudo umount {tgt}", file=sys.stderr)
    return 3


def main():
    src, tgt, recorded, machine, state, force, share_root, allow_json = sys.argv[1:9]
    try:
        allow_raw = json.loads(allow_json or "[]")
    except ValueError:
        allow_raw = [p for p in (allow_json or "").strip().strip('[]').split(',') if p.strip()]
    labels = (src, recorded, share_root)
    layers = mount_lines(tgt)
    if not layers:
        print("REMEDIATE: not mounted", file=sys.stderr)
        return 10
    print(f"LAYERS: {len(layers)}")
    for l in layers:
        print(f"LAYER-SRC: {layer_display(l)}  {layer_label(l, *labels)}")
    print(f"RO-STATE: {ro_state(tgt)}")
    deleted = any(deleted_ours(l, src, recorded) for l in layers)
    matched = stat_id(src) is not None and stat_id(src) == stat_id(tgt)
    rec_id = stat_id(recorded) if recorded else None
    ours = (rec_id is not None and rec_id == stat_id(tgt)) or deleted
    if matched and len(layers) == 1:
        print(f"OK: {tgt} bound from {src}")
        return 0
    if matched and len(layers) > 1 and state == "running":
        print(f"OK: {tgt} top layer bound from {src}; stack collapses when the machine is stopped")
        return 0
    if state == "running":
        why = ("proven ours, but the source directory was deleted" if deleted
               else "proven ours by ledger" if ours else "not proven by the ledger")
        print(f"ACTION REQUIRED: stale bind at {tgt} ({why}) cannot be replaced while machine {machine} is running.", file=sys.stderr)
        print(f"ACTION REQUIRED:   smolvm machine stop --name {machine}", file=sys.stderr)
        print("ACTION REQUIRED: then re-run; the stale bind is remediated while the machine is stopped.", file=sys.stderr)
        return 4
    bad = [l for l in layers if not (layer_provable(l, src, recorded, share_root)
                                     or layer_forced(l, force, allow_raw, share_root)
                                     or deleted_ours(l, src, recorded))]
    if not (ours or force == "true"):
        wanted = [l for l in layers if not layer_provable(l, src, recorded, share_root)]
        return refuse_stack(tgt, src, layers, wanted,
                            ",".join('/' + subpath(l) for l in wanted))
    for _ in range(10):
        layers = mount_lines(tgt)
        if not layers:
            break
        bad = [l for l in layers if not layer_removable(l, src, recorded, force, share_root, allow_raw)]
        if bad:
            return refuse_stack(tgt, src, layers, bad,
                                ",".join('/' + subpath(l) for l in bad))
        subprocess.run(["umount", tgt], check=True)
    if mount_lines(tgt):
        print(f"REFUSED: {tgt} is still stacked after 10 attempts; stopping", file=sys.stderr)
        return 3
    why = ("collapsed stack" if matched else "the source directory was deleted" if deleted
           else "proven ours by ledger" if ours else "forced by user")
    print(f"REMEDIATED: stale bind at {tgt} cleared ({why}); re-binding from {src}")
    return 10


if __name__ == "__main__":
    sys.exit(main())
