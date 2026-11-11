#!/usr/bin/env python3
"""Host-side bind identity probe for the share tree.

Decides whether the live mount at one share subdirectory is this playbook's
own and what to do about it: 0 = one layer bound from the configured source;
3 = the stack holds layers the ledger cannot prove ours; 4 = stale or foreign
and the machine is running; 5 = a stack of more than one layer whose top layer
is bound from the configured source and the machine is running (never
accepted: libkrun keeps the lower layer pinned, so the stack is collapsed only
while the machine is stopped); 10 = nothing is mounted (or, in apply mode, the
layers were cleared): bind the configured source; 11 = plan mode only: every
layer is removable and the apply form must clear them first; 2 = usage error;
1 = the mount options of the target could not be read (RO-STATE: unknown).
The last argument is the mode: plan only inspects and never unmounts;
apply re-checks every layer right before each umount (run it as root).
stdout: LAYERS:, LAYER-SRC:, RO-STATE:, ALLOW-PREFIX:, REMOVE-NEEDED:,
REMEDIATED:; stderr carries refusals.
"""
import json
import subprocess
import sys

from host_bind_layers import (deleted_ours, layer_context, layer_display,
                              layer_label, layer_provable, layer_removable,
                              mount_layers, ro_state, stat_id)

STACKED_RUNNING_RC = 5


def refuse_stack(tgt, src, layers, bad, force_named):
    print(f"REFUSED: {tgt} is bound from different content than {src}, and this run", file=sys.stderr)
    print("REFUSED: cannot prove it created every layer of the stack.", file=sys.stderr)
    print("REFUSED:   layers at that path, bottom first:", file=sys.stderr)
    for l in layers:
        print(f"REFUSED:     {layer_display(l.source)}", file=sys.stderr)
    for l in bad:
        if l.fsroot is not None:
            print(f"ALLOW-PREFIX: {l.fsroot}")
    print("REFUSED: nothing was mounted, unmounted or otherwise changed.", file=sys.stderr)
    print("REFUSED: to rebuild the mount from the configured source, re-run with", file=sys.stderr)
    print("REFUSED:   -e bind_mounts_force_remount=true", file=sys.stderr)
    print("REFUSED: force accepts a layer the playbook cannot prove only when", file=sys.stderr)
    print("REFUSED: its path is named explicitly:", file=sys.stderr)
    print(f"REFUSED:   -e bind_mounts_force_allow_layer_prefixes={force_named}", file=sys.stderr)
    print("REFUSED: to clear it by hand, with the machine stopped:", file=sys.stderr)
    print(f"REFUSED:   sudo umount {tgt}", file=sys.stderr)
    return 3


def main():
    src, tgt, recorded, machine, state, force, share_root, allow_json, mode = sys.argv[1:10]
    if mode not in ("plan", "apply"):
        print(f"usage error: mode must be plan or apply, got {mode!r}", file=sys.stderr)
        return 2
    try:
        allow_raw = json.loads(allow_json or "[]")
    except ValueError:
        allow_raw = [p for p in (allow_json or "").strip().strip('[]').split(',') if p.strip()]
    if isinstance(allow_raw, str):
        allow_raw = [p for p in allow_raw.split(',') if p.strip()]
    ctx = layer_context(src, recorded, share_root)
    layers = mount_layers(tgt)
    if not layers:
        print("REMEDIATE: not mounted", file=sys.stderr)
        return 10
    print(f"LAYERS: {len(layers)}")
    for l in layers:
        print(f"LAYER-SRC: {layer_display(l.source)}  {layer_label(l, ctx)}")
    ro = ro_state(tgt)
    if ro is None:
        print("RO-STATE: unknown")
        print(f"ERROR: cannot read the mount options of {tgt}", file=sys.stderr)
        return 1
    print(f"RO-STATE: {ro}")
    deleted = any(deleted_ours(l, ctx) for l in layers)
    matched = stat_id(src) is not None and stat_id(src) == stat_id(tgt)
    rec_id = stat_id(recorded) if recorded else None
    ours = (rec_id is not None and rec_id == stat_id(tgt)) or deleted
    if matched and len(layers) == 1:
        print(f"OK: {tgt} bound from {src}")
        return 0
    if matched and len(layers) > 1 and state == "running":
        print(f"ACTION REQUIRED: {tgt} is a stack of {len(layers)} layers and machine {machine} is running; this run will not change it.", file=sys.stderr)
        print(f"ACTION REQUIRED:   smolvm machine stop --name {machine}", file=sys.stderr)
        print("ACTION REQUIRED: then re-run only the mounts selection; the stack is collapsed while the machine is stopped.", file=sys.stderr)
        return STACKED_RUNNING_RC
    if state == "running":
        why = ("proven ours, but the source directory was deleted" if deleted
               else "proven ours by ledger" if ours else "not proven by the ledger")
        print(f"ACTION REQUIRED: stale bind at {tgt} ({why}) cannot be replaced while machine {machine} is running.", file=sys.stderr)
        print(f"ACTION REQUIRED:   smolvm machine stop --name {machine}", file=sys.stderr)
        print("ACTION REQUIRED: then re-run; the stale bind is remediated while the machine is stopped.", file=sys.stderr)
        return 4
    if not (ours or force == "true"):
        wanted = [l for l in layers if not layer_provable(l, ctx)]
        return refuse_stack(tgt, src, layers, wanted,
                            ",".join(l.fsroot for l in wanted if l.fsroot is not None))
    why = ("collapsed stack" if matched else "the source directory was deleted" if deleted
           else "proven ours by ledger" if ours else "forced by user")
    for _ in range(10):
        layers = mount_layers(tgt)
        if not layers:
            break
        bad = [l for l in layers if not layer_removable(l, ctx, force, allow_raw)]
        if bad:
            return refuse_stack(tgt, src, layers, bad,
                                ",".join(l.fsroot for l in bad if l.fsroot is not None))
        if mode == "plan":
            print(f"REMOVE-NEEDED: {tgt} has {len(layers)} layer(s) to clear ({why}); re-binding from {src} follows")
            return 11
        subprocess.run(["umount", tgt], check=True)
    if mount_layers(tgt):
        print(f"REFUSED: {tgt} is still stacked after 10 attempts; stopping", file=sys.stderr)
        return 3
    print(f"REMEDIATED: stale bind at {tgt} cleared ({why}); re-binding from {src}")
    return 10


if __name__ == "__main__":
    sys.exit(main())
