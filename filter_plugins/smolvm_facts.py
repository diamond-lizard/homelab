from __future__ import annotations

import re


class FilterModule(object):
    """Ansible filters for parsing and validating `smolvm machine ls --verbose` output."""

    def filters(self):
        return {
            "smolvm_ls_sections": self.smolvm_ls_sections,
            "smolvm_unknown_states": self.smolvm_unknown_states,
        }

    @staticmethod
    def smolvm_ls_sections(text):
        """Parse `smolvm machine ls --verbose` output.

        Returns a dict keyed by machine name::

            {"<machine>": {"state": "running", "mounts": [
                {"src": "/host/path", "target": "/guest/path", "ro": False},
            ]}}

        Format (verified against real output):

            NAME  STATE  CPUS  MEMORY  MOUNTS  PORTS  STORAGE  OVERLAY
            ----------------------------------------------------------------
            my-vm running  4   8192 MiB  2  0  20 GiB  10 GiB
              PID: 6077                      (only when running)
              Mount: /host/path -> /guest/path[ (ro)]

        Machine rows are the lines that do not start with whitespace and look
        like ``<name> <state> ...`` with at least six columns (MEMORY, STORAGE,
        and OVERLAY each render as two whitespace-separated tokens, so a real
        row has nine). The header row is skipped by name, the rule line by its
        all-dashes first token. Mount lines are indented by two spaces and
        start with the literal ``Mount:``.
        """
        mount_re = re.compile(r"^  Mount: (\S+) -> (\S+?)( \(ro\))?$")
        sections: dict = {}
        current = None
        for line in text.splitlines():
            if not line[:1].isspace():
                tokens = line.split()
                is_machine_row = (
                    len(tokens) >= 6
                    and tokens[0] != "NAME"
                    and tokens[0].strip("-") != ""
                    and tokens[1].isalpha()
                )
                if is_machine_row:
                    current = tokens[0]
                    sections.setdefault(current, {"state": tokens[1], "mounts": []})
                continue
            if current is None:
                continue
            match = mount_re.match(line)
            if match:
                sections[current]["mounts"].append(
                    {
                        "src": match.group(1),
                        "target": match.group(2),
                        "ro": match.group(3) is not None,
                    }
                )
        return sections

    @staticmethod
    def smolvm_unknown_states(sections, known, only=None):
        """List machines whose state is outside the caller's vocabulary.

        Returns ``"<machine> (<state>)"`` strings for every machine whose state
        token is not one of the ``known`` states::

            ["my-vm (hibernating)"]

        ``sections`` is the dict returned by ``smolvm_ls_sections``. ``only``
        restricts the report to those machine names, and names missing from the
        parsed inventory are ignored: pass the machines the run reads state for,
        so a machine the run never touches cannot fail it. The parser stores
        state tokens verbatim, so this filter is how a run notices that smolvm
        renamed or added a state before the running and stopped comparisons in
        the playbook silently pick a branch.
        """
        names = sections.keys() if only is None else only
        return [
            f"{name} ({sections[name]['state']})"
            for name in sorted(set(names))
            if name in sections and sections[name]["state"] not in known
        ]
