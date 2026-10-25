# Verdict codes returned by empty_share_verdict.
SOURCE_EMPTY = "source-empty"
HOST_BIND_REFUSED = "host-bind-refused"
UNEXPLAINED = "unexplained"
UNKNOWN = "unknown"

# host-bind-probe.py exit codes: the live host bind already matches the
# configured source (0) or the run bound it (10); the probe refused to bind
# an unproven stack (3) or a stale bind under a running machine (4).
_BOUND = frozenset({0, 10})
_REFUSED = frozenset({3, 4})

# Observed state of the configured host source directory.
_SRC_STATES = frozenset({"empty", "content", "unreadable"})


class FilterModule(object):
    """Classify why a guest share directory was empty."""

    def filters(self):
        return {"empty_share_verdict": self.empty_share_verdict}

    @staticmethod
    def empty_share_verdict(probe_rc, src_state):
        """Name the likeliest reason the guest helper refused an empty share.

        ``probe_rc`` is the host bind probe's exit code for the mount (None or
        anything unparsable when it is not known); ``src_state`` is one of
        ``empty``, ``content`` or ``unreadable``. When the host bind is in
        place (probe rc 0 or 10) the share subdirectory is the same directory
        as the source, so an empty source explains an empty share. A refused
        probe (rc 3 or 4) means no bind was made. Every other combination,
        and every malformed input, is ``unknown`` or ``unexplained``: this
        diagnosis is advisory, so it never raises and never guesses.
        """
        try:
            rc = int(probe_rc)
        except (TypeError, ValueError):
            return UNKNOWN
        if rc in _REFUSED:
            return HOST_BIND_REFUSED
        if rc not in _BOUND or src_state not in _SRC_STATES:
            return UNKNOWN
        if src_state == "empty":
            return SOURCE_EMPTY
        if src_state == "content":
            return UNEXPLAINED
        return UNKNOWN
