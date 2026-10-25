class FilterModule(object):
    """Render a boxed ACTION REQUIRED message as one multi-line string."""

    def filters(self):
        return {"action_box": self.action_box}

    @staticmethod
    def action_box(lines):
        """Join the box lines with newlines, dropping trailing padding.

        ``ansible.builtin.fail`` prints a list-valued ``msg`` as a Python
        repr, which the terminal then wraps mid-word. A single string
        containing real newlines prints as the box it is meant to be. A bare
        string is accepted so a pre-joined box passes through unchanged;
        anything else is a template bug and fails loudly rather than
        printing a garbled box.
        """
        if isinstance(lines, str):
            lines = lines.splitlines()
        elif not isinstance(lines, (list, tuple)):
            raise TypeError(
                "action_box expects a list of lines or a string, got %s" % type(lines).__name__)
        return "\n".join(str(line).rstrip() for line in lines)
