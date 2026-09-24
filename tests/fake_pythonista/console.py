"""Scripted stand-in for Pythonista's ``console``: answers come from ANSWERS."""

LOG = []
ANSWERS = []


class Cancel(Exception):
    pass


def _answer(default):
    if ANSWERS:
        value = ANSWERS.pop(0)
        if value is Cancel:
            raise KeyboardInterrupt
        return value
    return default


def alert(title, message="", *buttons, **kwargs):
    LOG.append(("alert", title, message))
    return _answer(1)


def input_alert(title, message="", input="", ok_button_title="OK", hide_cancel_button=False):
    LOG.append(("input", title, message))
    return _answer(input)


def hud_alert(message, icon="success", duration=1.8):
    LOG.append(("hud", message))


def set_idle_timer_disabled(flag):
    LOG.append(("idle", flag))


def show_activity():
    pass


def hide_activity():
    pass
