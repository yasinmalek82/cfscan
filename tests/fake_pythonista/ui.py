"""A stand-in for Pythonista's ``ui`` module, enough to build every screen.

Views keep their attributes and frames so tests can check layout; nothing
is drawn. Only what the app uses exists, so a typo in the app fails here.
"""

ALIGN_LEFT, ALIGN_CENTER, ALIGN_RIGHT = 0, 1, 2
AUTOCAPITALIZE_NONE = 0


class View:
    width = 390.0
    height = 800.0
    x = 0.0
    y = 0.0
    hidden = False
    name = ""

    def __init__(self, *args, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    @property
    def subviews(self):
        return self.__dict__.setdefault("_subviews", [])

    def __setattr__(self, key, value):
        if key == "frame":
            x, y, w, h = value
            if w < 0 or h < 0:
                raise ValueError("negative size %r for %s" % (value, type(self).__name__))
            object.__setattr__(self, "x", x)
            object.__setattr__(self, "y", y)
            object.__setattr__(self, "width", w)
            object.__setattr__(self, "height", h)
        object.__setattr__(self, key, value)

    @property
    def bounds(self):
        return (0, 0, self.width, self.height)

    def add_subview(self, view):
        self.subviews.append(view)

    def remove_subview(self, view):
        self.subviews.remove(view)

    def present(self, *args, **kwargs):
        self.presented = True


class Label(View):
    text = ""


class Button(View):
    title = ""
    enabled = True


class TextField(View):
    text = ""


class TextView(View):
    text = ""


class ScrollView(View):
    content_size = (0, 0)


class TableView(View):
    row_height = 44


class SegmentedControl(View):
    segments = ()
    selected_index = 0


class NavigationView(View):
    def __init__(self, root):
        View.__init__(self)
        self.root = root
        self.pushed = []

    def push_view(self, view):
        self.pushed.append(view)
        view.frame = (0, 0, 390, 760)
        if hasattr(view, "layout"):
            view.layout()

    def pop_view(self):
        if self.pushed:
            self.pushed.pop()


class ButtonItem:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class ListDataSource:
    def __init__(self, items):
        self.items = items
        self.selected_row = -1


def delay(fn, seconds):
    fn()


def get_ui_style():
    return "light"
