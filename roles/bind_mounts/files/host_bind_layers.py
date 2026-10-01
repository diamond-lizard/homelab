"""Layer predicates for the host-side bind identity probe.

The ownership rule lives here: a layer is provable when it sits at or below
the share root or matches the configured or the ledger-recorded source; force
accepts a layer only when its path was named in the allow prefixes; a kernel
//deleted layer is ours when the path minus the marker matches that source.
"""
import os
import subprocess


def stat_id(path):
    try:
        st = os.stat(path)
        return f"{st.st_dev}:{st.st_ino}"
    except OSError:
        return None


def mount_lines(tgt):
    # findmnt renders a bind as device[filesystem-relative path], keeping the
    # source path recoverable; `mount` prints the bare device and loses it.
    p = subprocess.run(["findmnt", "-rn", "-o", "SOURCE", "-M", tgt],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return []
    return [l.strip() for l in p.stdout.splitlines() if l.strip()]


def ro_state(tgt):
    opts = subprocess.run(["findmnt", "-rn", "-o", "OPTIONS", "-M", tgt],
                          capture_output=True, text=True)
    return 'ro' if 'ro' in opts.stdout.splitlines()[0].split(',') else 'rw'
    return 'ro' if 'ro' in opts.split(',') else 'rw'


def subpath(source):
    return source[source.find('[') + 1:-1].lstrip('/') if '[' in source else source.lstrip('/')


def norm(path):
    # findmnt reports a source as it was mounted, so one side of a comparison
    # can be a symlinked path and the other resolved.
    return os.path.realpath('/' + path.lstrip('/'))


def deleted_ours(source, src, recorded):
    # The kernel renders a mount root whose backing directory was unlinked
    # with a literal '//deleted' suffix (fs/d_path.c dentry_path); such a
    # layer is ours when the path minus that suffix matches the configured
    # source or the ledger-recorded source.
    sp = subpath(source)
    if not sp.endswith('//deleted'):
        return False
    stripped = norm(sp[:-len('//deleted')])
    return stripped == norm(subpath(src)) or bool(recorded) and stripped == norm(subpath(recorded))


def layer_provable(source, src, recorded, share_root):
    sp, sr = norm(subpath(source)), norm(share_root.rstrip('/'))
    return (sp == sr or sp.startswith(sr + '/')
            or sp == norm(subpath(src))
            or bool(recorded and sp == norm(subpath(recorded))))


def layer_forced(source, force, allow_raw, share_root):
    prefixes = [norm(str(p).rstrip('/')) for p in allow_raw]
    sp = norm(subpath(source))
    return force == "true" and any(sp == p or sp.startswith(p + '/') for p in prefixes)


def layer_removable(source, src, recorded, force, share_root, allow_raw):
    return (layer_provable(source, src, recorded, share_root)
            or layer_forced(source, force, allow_raw, share_root)
            or deleted_ours(source, src, recorded))


def layer_label(source, src, recorded, share_root):
    sp = subpath(source)
    if sp == subpath(src):
        return "(configured source)"
    if recorded and sp == subpath(recorded):
        return "(ledger-recorded)"
    if deleted_ours(source, src, recorded):
        return "(ours; source directory deleted)"
    spn, srn = norm(sp), norm(share_root.rstrip('/'))
    if spn == srn or spn.startswith(srn + '/'):
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
