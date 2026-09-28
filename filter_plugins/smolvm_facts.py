import re

_ALPHA_RE = re.compile(r"[A-Za-z]+")
_MOUNT_RE = re.compile(r"^  Mount: (\S+) -> (\S+?)( \(ro\))?$")
# Frozen smolvm state vocabulary; the single shared source for the gate filter.
SMOLVM_STATES = frozenset({"running", "stopped", "created", "failed", "unreachable", "frozen"})
_NOT_RUNNING = frozenset({"stopped", "created"})
_REFUSE = SMOLVM_STATES - _NOT_RUNNING - {"running"}


def _scan(text):
    """Shared pass; returns (sections, rejected). Machine rows (>=6 tokens,
    not the NAME header, not the all-dashes rule line) with a purely
    alphabetic state token become sections; other such rows hit rejected.
    """
    sections: dict = {}
    rejected: list = []
    current = None
    for line in text.splitlines():
        if line[:1].isspace():
            m = _MOUNT_RE.match(line) if current is not None else None
            mount = {"src": m.group(1), "target": m.group(2), "ro": m.group(3) is not None} if m else None
            if mount: sections[current]["mounts"].append(mount)
            continue
        tokens = line.split()
        if len(tokens) < 6 or tokens[0] == "NAME" or tokens[0].strip("-") == "":
            continue
        if not _ALPHA_RE.fullmatch(tokens[1]):
            rejected.append({"name": tokens[0], "state": tokens[1]})
        if tokens[1].isalpha():
            current = tokens[0]
            sections.setdefault(current, {"state": tokens[1], "mounts": []})
    return sections, rejected


def _gate(sections, names):
    """Classify each passed name that is present in ``sections``."""
    out = {}
    for name in names:
        state = sections.get(name, {}).get("state")
        if state is None:
            continue
        cls = "running" if state == "running" else "not-running" if state in _NOT_RUNNING else "refuse" if state in _REFUSE else "unknown"
        record = {"classification": cls, "state": state}
        if cls in ("refuse", "unknown"):
            record["message"] = f"{name}: {state}"
        out[name] = record
    return out


class FilterModule(object):
    """Ansible filters for parsing and validating `smolvm machine ls --verbose` output."""

    def filters(self):
        return {
            "smolvm_ls_sections": self.smolvm_ls_sections,
            "smolvm_unknown_states": self.smolvm_unknown_states,
            "smolvm_rejected_rows": self.smolvm_rejected_rows,
            "smolvm_state_gate": self.smolvm_state_gate,
        }

    @staticmethod
    def smolvm_ls_sections(text):
        """Parse `smolvm machine ls --verbose`; see `_scan` for the row shape.
        Returns ``{"<machine>": {"state": <token>, "mounts": [{"src", "target",
        "ro"}]}}``. Names stored verbatim (renderer-truncated names ending in
        ``...`` stay as rendered); indented ``Mount:`` lines extend the machine.
        """
        return _scan(text)[0]

    @staticmethod
    def smolvm_rejected_rows(text):
        """Report machine-shaped rows (see `_scan`) the parser dropped, as
        {"name", "state"} records with the raw token, distinguishing an absent
        machine from an unparseable one; header, rule, short, and indented
        lines are never reported.
        """
        return _scan(text)[1]

    @staticmethod
    def smolvm_unknown_states(sections, known, only=None):
        """List ``"<machine> (<state>)"`` strings for states outside ``known``;
        ``only`` restricts the report; names missing from ``sections`` are not
        classified. Tokens are verbatim; a run notices renamed/new states here.
        """
        return [
            f"{name} ({sections[name]['state']})"
            for name in sorted(set(sections.keys() if only is None else only))
            if name in sections and sections[name]["state"] not in known
        ]

    @staticmethod
    def smolvm_state_gate(sections, names):
        """Classify machines against the shared vocabulary ``SMOLVM_STATES``.
        Returns ``{name: {"classification": cls, "state": tok}}``: ``running``;
        ``not-running`` (stopped/created); ``refuse`` (failed/unreachable/
        frozen; ``message`` = raw token); ``unknown`` (other alphabetic token;
        ``message`` names both). Names absent from ``sections``: not classified.
        """
        return _gate(sections, names)
