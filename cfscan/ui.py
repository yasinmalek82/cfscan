"""Terminal UI: colours, tables and prompt helpers.

Colour is used only when the terminal supports it (a real TTY, a sane ``TERM``
and no ``NO_COLOR`` variable). Every screen stays readable without colour: the
layout relies on spacing and plain markers rather than escape codes.
"""

from __future__ import annotations

import os
import sys
import textwrap

__all__ = ["Aborted", "Console", "supports_ansi", "visible_width"]

_ANSI_RE = __import__("re").compile(r"\x1b\[[0-9;]*[A-Za-z]")

_STYLES = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "cyan": "\x1b[36m",
}


class Aborted(Exception):
    """Raised when the user cancels input with Ctrl+C or end of input."""


def visible_width(text):
    """The printed width of text, ignoring ANSI escape sequences."""
    return len(_ANSI_RE.sub("", str(text)))


def supports_ansi(stream=None, no_color=False):
    """True when it is safe to emit ANSI colour codes."""
    if no_color:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    term = os.environ.get("TERM", "")
    if not term or term.lower() == "dumb":
        return False
    stream = stream if stream is not None else sys.stdout
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except (ValueError, OSError):
        return False


class Console(object):
    """A tiny wrapper around stdout/stderr/input that tests can drive."""

    def __init__(self, out=None, err=None, input_fn=None, color=None):
        self.out = out if out is not None else sys.stdout
        self.err = err if err is not None else sys.stderr
        self.input_fn = input_fn if input_fn is not None else input
        if color is None:
            color = supports_ansi(self.out)
        self.color = bool(color)
        self._progress_len = 0

    # -- colour -----------------------------------------------------------

    def set_color(self, enabled):
        self.color = bool(enabled)
        return self.color

    def style(self, text, *styles):
        if not self.color or not styles:
            return str(text)
        codes = "".join(_STYLES.get(name, "") for name in styles)
        return f"{codes}{text}{_STYLES['reset']}"

    def _c(self, text, *styles):
        return self.style(text, *styles)

    @property
    def _is_tty(self):
        isatty = getattr(self.out, "isatty", None)
        if not callable(isatty):
            return False
        try:
            return bool(isatty())
        except (ValueError, OSError):
            return False

    @property
    def interactive(self):
        """True when the output really is a terminal, so a prompt is welcome.

        Used to decide whether waiting for the user is helpful (a terminal) or
        would only stall a script (a pipe or a captured stream).
        """
        return self._is_tty

    # -- output -----------------------------------------------------------

    def write(self, text=""):
        self.out.write(text)
        self.out.flush()

    def line(self, text=""):
        self.write(f"{text}\n")

    def blank(self):
        self.line("")

    def info(self, text):
        self.line(f"{self._c('i', 'blue')} {text}" if self.color else f"i {text}")

    def ok(self, text):
        self.line(f"{self._c('+', 'green', 'bold')} {text}" if self.color
                  else f"+ {text}")

    def warn(self, text):
        self.line(f"{self._c('!', 'yellow', 'bold')} {text}" if self.color
                  else f"! {text}")

    def error(self, text):
        self.err.write(f"{self._c('x', 'red', 'bold')} {text}\n"
                       if self.color else f"x {text}\n")
        try:
            self.err.flush()
        except (ValueError, OSError):  # pragma: no cover - closed stream
            pass

    def clear(self):
        """Clear the visible screen, when there is a terminal to clear.

        Only the screen: the sequence used here is the one ``clear`` sends, so
        everything printed before stays in the terminal's scrollback and can
        still be scrolled back to. A pipe or a captured stream gets nothing at
        all, which keeps saved output free of escape codes.
        """
        if not self.color or not self._is_tty:
            return False
        self.write("\x1b[H\x1b[2J")
        return True

    def heading(self, text):
        self.blank()
        self.line(self._c(text, "bold", "cyan"))
        self.line(self._c("-" * max(12, min(visible_width(text), 60)), "dim"))

    def rule(self, width=64):
        self.line(self._c("-" * width, "dim"))

    def bullet(self, text, indent=2):
        self.line(textwrap.fill(str(text), width=96,
                                initial_indent=" " * indent + "- ",
                                subsequent_indent=" " * (indent + 2)))

    def key_value(self, key, value, key_width=18):
        self.line(f"{str(key).ljust(key_width)}: {value}")

    # -- tables -----------------------------------------------------------

    def table(self, headers, rows, aligns=None, highlight_rows=(),
              marker_col=1, marker=" *", legend=None):
        """Render a simple aligned table that works with or without colour."""
        header_cells = [str(item) for item in headers]
        column_count = len(header_cells)
        aligns = list(aligns) if aligns else ["l"] * column_count
        while len(aligns) < column_count:
            aligns.append("l")

        highlight_rows = set(highlight_rows)
        body = []
        for index, row in enumerate(rows):
            cells = [str(item) for item in row]
            highlighted = index in highlight_rows
            if highlighted and cells:
                position = marker_col if marker_col < len(cells) else len(cells) - 1
                cells[position] = cells[position] + marker
            body.append((cells, highlighted))

        widths = [visible_width(cell) for cell in header_cells]
        for cells, _ in body:
            for position, cell in enumerate(cells):
                if position < column_count:
                    widths[position] = max(widths[position], visible_width(cell))

        def render(cells):
            parts = []
            for position in range(column_count):
                cell = cells[position] if position < len(cells) else ""
                padding = widths[position] - visible_width(cell)
                if aligns[position] == "r":
                    parts.append(" " * padding + cell)
                else:
                    parts.append(cell + " " * padding)
            return "  ".join(parts)

        self.line(self._c(render(header_cells), "bold"))
        self.line(self._c("  ".join("-" * width for width in widths), "dim"))
        for cells, highlighted in body:
            line = render(cells)
            if highlighted:
                self.line(self._c(line, "green", "bold"))
            else:
                self.line(line)
        if legend:
            self.blank()
            self.line(self._c(legend, "dim"))

    # -- progress ---------------------------------------------------------

    def progress_line(self, text):
        """Update a single progress line when attached to a terminal."""
        if not self._is_tty:
            return
        text = str(text)
        padding = max(0, self._progress_len - visible_width(text))
        self.out.write("\r" + text + " " * padding)
        self.out.flush()
        self._progress_len = visible_width(text)

    def progress_end(self, text=None):
        if self._is_tty and self._progress_len:
            self.out.write("\r" + " " * self._progress_len + "\r")
            self._progress_len = 0
        if text:
            self.line(text)
        else:
            self.out.flush()

    # -- input ------------------------------------------------------------

    def _read(self, prompt):
        label = f"{prompt}: " if not str(prompt).endswith(" ") else str(prompt)
        # The prompt is written here (instead of letting input() print it) so it
        # always lands in our own output stream and can be captured or muted.
        self.write(label)
        try:
            return self.input_fn("")
        except KeyboardInterrupt:
            self.blank()
            raise Aborted()
        except EOFError:
            raise Aborted()

    def ask_raw(self, prompt):
        return self._read(prompt)

    def ask(self, prompt, default=None, allow_empty=False, validate=None):
        """Ask for a value, re-prompting until it validates."""
        while True:
            label = str(prompt)
            if default is not None:
                label += f" [{default}]"
            elif not allow_empty:
                label += " (required)"
            raw = self._read(label)
            value = raw.strip()
            if not value:
                if default is not None:
                    value = default
                elif allow_empty:
                    value = ""
                else:
                    self.warn("A value is required here.")
                    continue
            if validate is None:
                return value
            try:
                return validate(value)
            except Exception as exc:  # ValidationError and friends
                self.error(str(exc))

    def ask_int(self, prompt, default=None, minimum=None, maximum=None,
                field="value"):
        from .validate import validate_int

        return self.ask(
            prompt,
            default=default,
            validate=lambda value: validate_int(
                value, minimum=minimum, maximum=maximum, field=field
            ),
        )

    def ask_float(self, prompt, default=None, minimum=None, maximum=None,
                  field="value"):
        from .validate import validate_float

        return self.ask(
            prompt,
            default=default,
            validate=lambda value: validate_float(
                value, minimum=minimum, maximum=maximum, field=field
            ),
        )

    def ask_loss(self, prompt, default=None, field="maximum packet loss"):
        from .validate import validate_loss

        shown = default
        if isinstance(default, float) and default <= 1:
            shown = f"{default * 100:g}%"
        return self.ask(
            prompt,
            default=shown,
            validate=lambda value: validate_loss(value, field=field),
        )

    def ask_yes_no(self, prompt, default=True):
        suffix = "[Y/n]" if default else "[y/N]"
        while True:
            raw = self._read(f"{prompt} {suffix}")
            answer = raw.strip().lower()
            if not answer:
                return bool(default)
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self.warn("Please answer 'y' or 'n'.")

    def ask_choice(self, prompt, options, default=None):
        """Ask the user to pick one of ``options`` (a list of key/label pairs)."""
        options = [(str(key), str(label)) for key, label in options]
        keys = [key for key, _ in options]
        while True:
            self.blank()
            self.line(self._c(prompt, "bold"))
            for key, label in options:
                suffix = " (default)" if default is not None and key == str(default) else ""
                self.line(f"  {key}. {label}{suffix}")
            raw = self._read("Enter a number")
            answer = raw.strip()
            if not answer and default is not None:
                return str(default)
            if answer in keys:
                return answer
            self.error("Invalid choice. Please enter one of the numbers listed above.")

    def pause(self, prompt="Press Enter to return to the menu"):
        """Wait for one Enter press. Raises :class:`Aborted` on Ctrl+C/EOF."""
        try:
            self._read(prompt)
        except Aborted:
            raise
