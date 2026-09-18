"""Tests for the terminal UI helpers."""

from __future__ import annotations

import io
import os
import unittest
from unittest import mock

from cfscan.ui import Console, supports_ansi, visible_width


class TtyStream(io.StringIO):
    def isatty(self):
        return True


class SupportsAnsiTests(unittest.TestCase):
    def test_plain_stream_has_no_colour(self):
        self.assertFalse(supports_ansi(io.StringIO()))

    def test_tty_supports_colour(self):
        with mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=False):
            self.assertTrue(supports_ansi(TtyStream()))

    def test_no_color_flag_wins(self):
        with mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=False):
            self.assertFalse(supports_ansi(TtyStream(), no_color=True))

    def test_no_color_environment_variable_is_honoured(self):
        env = {"TERM": "xterm-256color", "NO_COLOR": "1"}
        with mock.patch.dict(os.environ, env, clear=False):
            self.assertFalse(supports_ansi(TtyStream()))

    def test_dumb_terminal_has_no_colour(self):
        with mock.patch.dict(os.environ, {"TERM": "dumb"}, clear=False):
            self.assertFalse(supports_ansi(TtyStream()))


class VisibleWidthTests(unittest.TestCase):
    def test_ignores_ansi_sequences(self):
        self.assertEqual(visible_width("\x1b[32mabc\x1b[0m"), 3)

    def test_counts_plain_text(self):
        self.assertEqual(visible_width("hello"), 5)


class ConsoleOutputTests(unittest.TestCase):
    def make(self, color=False, answers=None):
        from tests.support import ScriptedInput

        out = io.StringIO()
        scripted = ScriptedInput(answers or [])
        return Console(out=out, err=out, input_fn=scripted, color=color), out

    def test_no_colour_output_has_no_escape_codes(self):
        console, out = self.make(color=False)
        console.info("hello")
        console.ok("done")
        console.warn("careful")
        console.error("bad")
        console.heading("Title")
        console.rule()
        self.assertNotIn("\x1b[", out.getvalue())

    def test_remains_readable_without_colour(self):
        console, out = self.make(color=False)
        console.heading("Active profile")
        console.line("Domain: node.example.test")
        text = out.getvalue()
        self.assertIn("Active profile", text)
        self.assertIn("Domain: node.example.test", text)

    def test_colour_output_has_escape_codes(self):
        console, out = self.make(color=True)
        console.ok("done")
        self.assertIn("\x1b[", out.getvalue())

    def test_table_is_aligned_and_marked(self):
        console, out = self.make(color=False)
        console.table(
            ["Rank", "IP", "Sent"],
            [["1", "104.16.0.1", "4"], ["2", "172.67.213.151", "4"]],
            highlight_rows={0},
        )
        lines = [line for line in out.getvalue().splitlines() if line.strip()]
        # header, separator, then one line per row; every line is the same width
        self.assertEqual(len(set(len(line) for line in lines)), 1)
        self.assertIn("*", lines[2])
        self.assertNotIn("*", lines[3])

    def test_table_alignment_ignores_colour_sequences(self):
        console, out = self.make(color=True)
        console.table(
            ["Rank", "IP"],
            [["1", "104.16.0.1"], ["2", "172.67.213.151"]],
            highlight_rows={0},
        )
        plain = out.getvalue()
        stripped = [visible_width(line) for line in plain.splitlines() if line.strip()]
        self.assertEqual(len(set(stripped)), 1)

    def test_table_can_append_legend(self):
        console, out = self.make(color=False)
        console.table(["Rank", "IP"], [["1", "1.1.1.1"]], legend="* recommended IP")
        self.assertIn("* recommended IP", out.getvalue())


class ConsolePromptTests(unittest.TestCase):
    def make(self, answers):
        from tests.support import ScriptedInput

        out = io.StringIO()
        return Console(out=out, err=out, input_fn=ScriptedInput(answers),
                       color=False), out

    def test_ask_uses_default_for_empty_answer(self):
        console, _ = self.make([""])
        self.assertEqual(console.ask("Domain", default="node.example.test"),
                         "node.example.test")

    def test_ask_requires_value_without_default(self):
        console, out = self.make(["", "example.com"])
        self.assertEqual(console.ask("Domain"), "example.com")
        self.assertIn("required", out.getvalue().lower())

    def test_ask_int_reprompts_until_valid(self):
        console, out = self.make(["abc", "0", "7"])
        value = console.ask_int("Attempts", minimum=1, maximum=1000, field="attempts")
        self.assertEqual(value, 7)
        self.assertIn("attempts", out.getvalue())

    def test_ask_int_uses_default(self):
        console, _ = self.make([""])
        self.assertEqual(console.ask_int("Attempts", default=4, minimum=1, maximum=1000),
                         4)

    def test_ask_float_parses_value(self):
        console, _ = self.make(["1000"])
        self.assertEqual(console.ask_float("Max latency", minimum=0, maximum=10000), 1000.0)

    def test_ask_loss_accepts_percentage(self):
        console, _ = self.make(["25%"])
        self.assertAlmostEqual(console.ask_loss("Max loss"), 0.25)

    def test_ask_yes_no_default(self):
        console, _ = self.make([""])
        self.assertTrue(console.ask_yes_no("Continue?", default=True))
        console, _ = self.make(["n"])
        self.assertFalse(console.ask_yes_no("Continue?", default=True))

    def test_ask_reprompts_on_invalid_yes_no(self):
        console, out = self.make(["maybe", "y"])
        self.assertTrue(console.ask_yes_no("Continue?"))
        self.assertIn("Please answer", out.getvalue())

    def test_ask_choice_returns_key(self):
        console, out = self.make(["9", "2"])
        options = [("1", "IPv4"), ("2", "IPv6")]
        self.assertEqual(console.ask_choice("Version", options), "2")
        self.assertIn("Invalid choice", out.getvalue())

    def test_ask_choice_uses_default(self):
        console, _ = self.make([""])
        options = [("1", "IPv4"), ("2", "IPv6")]
        self.assertEqual(console.ask_choice("Version", options, default="1"), "1")

    def test_prompt_text_is_written_to_output(self):
        console, out = self.make(["yes.csv"])
        console.ask("Output filename")
        self.assertIn("Output filename", out.getvalue())

    def test_exhausted_input_raises_abort(self):
        from cfscan.ui import Aborted

        console, _ = self.make([])
        with self.assertRaises(Aborted):
            console.ask("Domain")

    def test_keyboard_interrupt_raises_abort(self):
        from cfscan.ui import Aborted

        def boom(_prompt=""):
            raise KeyboardInterrupt

        out = io.StringIO()
        console = Console(out=out, err=out, input_fn=boom, color=False)
        with self.assertRaises(Aborted):
            console.ask("Domain")


if __name__ == "__main__":
    unittest.main()
