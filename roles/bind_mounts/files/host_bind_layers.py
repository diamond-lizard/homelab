"""Layer predicates for the host-side bind identity probe.

A layer is identified by the pair (MAJ:MIN, FSROOT) the kernel reports for it:
the device and the path of the mount root inside that device's filesystem. The
configured source, the ledger-recorded source and the share root are
translated into the same pair with findmnt -T, so no host path is ever guessed
from a filesystem-relative string. A layer is provable when it is the
configured or the recorded source's pair or sits at or below the share root's
pair; a kernel //deleted layer is ours when its path minus the marker is the
configured or recorded source's pair; force accepts a layer only when its
filesystem-relative path is named in the allow prefixes. A pair that cannot be
determined never matches.
"""
import os
import re
import subprocess
from collections import namedtuple

DELETED = "//deleted"
Layer = namedtuple("Layer", "source majmin fsroot")
Pair = namedtuple("Pair", "majmin fsroot")
Ctx = namedtuple("Ctx", "src recorded share")


def stat_id(path):
    try:
        st = os.stat(path)
        return f"{st.st_dev}:{st.st_ino}"
    except OSError:
        return None


def ro_state(tgt):
    opts = subprocess.run(["findmnt", "-rn", "-o", "OPTIONS", "-M", tgt],
                          capture_output=True, text=True)
    return 'ro' if 'ro' in opts.stdout.splitlines()[0].split(',') else 'rw'


def _unescape(text):
    # findmnt -r writes a space, tab or backslash inside a field as \xNN
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)


def _clean(path):
    # collapse repeated slashes, but keep the kernel's '//deleted' marker intact
    dead = path.endswith(DELETED)
    if dead:
        path = path[:-len(DELETED)]
    out = "/" + "/".join(s for s in path.split("/") if s and s != ".")
    return out + DELETED if dead else out


def mount_layers(tgt):
    # One Layer per mount stacked at tgt, bottom first. SOURCE is only for
    # display; identity is the (MAJ:MIN, FSROOT) pair. A line that does not
    # split into three fields becomes a Layer with no pair, which never matches.
    p = subprocess.run(["findmnt", "-rn", "-o", "SOURCE,MAJ:MIN,FSROOT", "-M", tgt],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return []
    out = []
    for line in p.stdout.splitlines():
        f = line.split()
        if not f:
            continue
        if len(f) == 3:
            out.append(Layer(_unescape(f[0]), f[1], _clean(_unescape(f[2]))))
        else:
            out.append(Layer(line.strip(), None, None))
    return out


def fs_pair(path):
    # The (MAJ:MIN, FSROOT) pair of a host path: the containing mount's device
    # and FSROOT joined with the part of the path below that mount. A path that
    # no longer exists is resolved through its nearest existing ancestor plus
    # the removed remainder. None when it cannot be determined.
    if not path:
        return None
    cur = os.path.realpath(path)
    rest = []
    while True:
        p = subprocess.run(["findmnt", "-rn", "-o", "TARGET,MAJ:MIN,FSROOT", "-T", cur],
                           capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            break
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        rest.insert(0, os.path.basename(cur))
        cur = parent
    f = p.stdout.splitlines()[0].split()
    if len(f) != 3:
        return None
    target, majmin, fsroot = _unescape(f[0]), f[1], _unescape(f[2])
    base = target.rstrip("/")
    if cur != target and not cur.startswith(base + "/"):
        return None
    return Pair(majmin, _clean("/".join([fsroot, cur[len(base):]] + rest)))


def layer_context(src, recorded, share_root):
    return Ctx(fs_pair(src), fs_pair(recorded), fs_pair(share_root))


def _same(layer, root, pair):
    return pair is not None and layer.majmin == pair.majmin and root == pair.fsroot


def is_configured(layer, ctx):
    return layer.fsroot is not None and _same(layer, layer.fsroot, ctx.src)


def is_recorded(layer, ctx):
    return layer.fsroot is not None and _same(layer, layer.fsroot, ctx.recorded)


def in_share(layer, ctx):
    p = ctx.share
    if layer.fsroot is None or p is None or layer.majmin != p.majmin:
        return False
    return layer.fsroot == p.fsroot or layer.fsroot.startswith(p.fsroot.rstrip("/") + "/")


def deleted_ours(layer, ctx):
    # The kernel renders a mount root whose backing directory was unlinked
    # with a literal '//deleted' suffix (fs/d_path.c dentry_path); such a
    # layer is ours when its root minus that suffix is the configured or the
    # ledger-recorded source's pair.
    if layer.fsroot is None or not layer.fsroot.endswith(DELETED):
        return False
    root = layer.fsroot[:-len(DELETED)] or "/"
    return _same(layer, root, ctx.src) or _same(layer, root, ctx.recorded)


def layer_provable(layer, ctx):
    return is_configured(layer, ctx) or is_recorded(layer, ctx) or in_share(layer, ctx)


def layer_forced(layer, force, allow_raw):
    # allow_raw holds filesystem-relative layer paths as the refusal box prints
    # them; whole-segment prefix match, no symlink resolution, no device test.
    if force != "true" or layer.fsroot is None:
        return False
    prefixes = [_clean(str(p)) for p in allow_raw if str(p).strip()]
    return any(layer.fsroot == p or layer.fsroot.startswith(p + "/") for p in prefixes)


def layer_removable(layer, ctx, force, allow_raw):
    return (layer_provable(layer, ctx)
            or layer_forced(layer, force, allow_raw)
            or deleted_ours(layer, ctx))


def layer_label(layer, ctx):
    # Built from the same predicates as layer_provable / deleted_ours, so
    # "(not ours)" appears exactly when none of them holds.
    if is_configured(layer, ctx):
        return "(configured source)"
    if is_recorded(layer, ctx):
        return "(ledger-recorded)"
    if deleted_ours(layer, ctx):
        return "(ours; source directory deleted)"
    if in_share(layer, ctx):
        return "(under the share root)"
    return "(not ours)"


def layer_display(source):
    # Show the path an operator recognizes first; keep the device beside it
    # only while the box line still fits its width.
    if "[" in source and source.endswith("]"):
        dev, path = source.split("[", 1)
        path = path[:-1]
        if len(f"      {path}  ({dev})") <= 69:
            return f"{path}  ({dev})"
        return path
    return source
