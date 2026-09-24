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
    """Like Pythonista: the pressed button (1..n); cancel raises KeyboardInterrupt."""
    LOG.append(("alert", title, message))
    value = _answer(1)
    if not isinstance(value, int) or isinstance(value, bool):
        value = 1
    if value <= 0:
        if kwargs.get("hide_cancel_button"):
            return 1
        raise KeyboardInterrupt
    return min(value, max(1, len(buttons)))


def input_alert(title, message="", input="", ok_button_title="OK", hide_cancel_button=False):
    """Like Pythonista: always text; cancel (None) raises KeyboardInterrupt."""
    LOG.append(("input", title, message))
    value = _answer(input)
    if value is None:
        raise KeyboardInterrupt
    return str(value)


def hud_alert(message, icon="success", duration=1.8):
    LOG.append(("hud", message))


def set_idle_timer_disabled(flag):
    LOG.append(("idle", flag))


def show_activity():
    pass


def hide_activity():
    pass
