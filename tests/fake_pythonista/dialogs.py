"""Scripted stand-in for Pythonista's ``dialogs``: answers come from ANSWERS.

A list answer may be the item text or an int index; None cancels.
"""

LOG = []
ANSWERS = []


def list_dialog(title="", items=None, multiple=False):
    LOG.append(("list", title, list(items or [])))
    if not ANSWERS:
        return None
    answer = ANSWERS.pop(0)
    if isinstance(answer, int) and not isinstance(answer, bool):
        return list(items)[answer]
    if answer is not None and answer not in (items or []):
        raise AssertionError("%r is not one of %r" % (answer, items))
    return answer


def form_dialog(title="", fields=None, sections=None, done_button_title="Done"):
    LOG.append(("form", title, fields, sections))
    for section in sections or []:
        if not isinstance(section, tuple) or len(section) not in (2, 3):
            raise AssertionError("bad section %r" % (section,))
    return ANSWERS.pop(0) if ANSWERS else None
