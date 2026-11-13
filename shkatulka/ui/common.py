"""Small reusable GTK widgets and helpers."""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Gdk, GLib, Gtk  # noqa: E402

from ..security import Strength, password_strength  # noqa: E402

RESOURCE_DIR = Path(__file__).resolve().parent.parent / "resources"
STYLE_PATH = RESOURCE_DIR / "style.css"
APP_ICON_PATH = RESOURCE_DIR / "io.github.shkatulka.Shkatulka.svg"


_CSS_INSTALLED = False


def install_css() -> None:
    global _CSS_INSTALLED
    if _CSS_INSTALLED:
        return
    display = Gdk.Display.get_default()
    if display is None:
        return
    provider = Gtk.CssProvider()
    try:
        provider.load_from_path(str(STYLE_PATH))
    except GLib.Error:
        return
    Gtk.StyleContext.add_provider_for_display(
        display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )
    _CSS_INSTALLED = True


def label(
    text: str = "",
    *,
    css: str | None = None,
    wrap: bool = False,
    xalign: float = 0.0,
    selectable: bool = False,
) -> Gtk.Label:
    widget = Gtk.Label(label=text)
    widget.set_xalign(xalign)
    widget.set_wrap(wrap)
    widget.set_selectable(selectable)
    if css:
        for name in css.split():
            widget.add_css_class(name)
    return widget


def icon(name: str, size: int = 16) -> Gtk.Image:
    image = Gtk.Image.new_from_icon_name(name)
    image.set_pixel_size(size)
    return image


def app_icon_image(size: int = 96) -> Gtk.Image:
    if APP_ICON_PATH.exists():
        image = Gtk.Image.new_from_file(str(APP_ICON_PATH))
        image.set_pixel_size(size)
        return image
    return icon("channel-secure-symbolic", size)


def password_entry(placeholder: str) -> Gtk.PasswordEntry:
    entry = Gtk.PasswordEntry()
    entry.set_show_peek_icon(True)
    entry.set_property("placeholder-text", placeholder)
    entry.set_hexpand(True)
    return entry


class PasswordStrengthMeter(Gtk.Box):
    """Four-segment visual hint with a text label and a short explanation."""

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self._segments: list[Gtk.Box] = []
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        for _ in range(4):
            segment = Gtk.Box()
            segment.add_css_class("strength-segment")
            segment.set_hexpand(True)
            bar.append(segment)
            self._segments.append(segment)
        self.append(bar)
        self._label = label("", css="caption dim-label", wrap=True)
        self.append(self._label)
        self.update("")

    def update(self, password: str) -> None:
        strength = password_strength(password)
        self._apply(strength)

    def _apply(self, strength: Strength) -> None:
        colours = ("weak", "weak", "fair", "good", "strong")
        for index, segment in enumerate(self._segments):
            for css in ("weak", "fair", "good", "strong", "filled"):
                segment.remove_css_class(css)
            if index < strength.score:
                segment.add_css_class("filled")
                segment.add_css_class(colours[strength.score])
        self._label.set_text(
            f"Надёжность: {strength.label}. {strength.hint}" if strength.bits
            else strength.hint
        )


def text_field(title: str, entry: Gtk.Widget) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    box.append(label(title, css="caption dim-label"))
    box.append(entry)
    return box


def error_label() -> Gtk.Label:
    widget = label("", css="error-label", wrap=True)
    widget.set_visible(False)
    return widget


def show_error(widget: Gtk.Label, message: str) -> None:
    widget.set_text(message)
    widget.set_visible(bool(message))


def make_card_box() -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    box.add_css_class("card-box")
    return box


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if "://" not in value:
        return "https://" + value
    return value


def open_uri(url: str) -> None:
    """Open only http(s) URLs in the user's browser."""

    target = normalize_url(url)
    if not (target.startswith("https://") or target.startswith("http://")):
        return
    launcher = Gtk.UriLauncher.new(uri=target)
    launcher.launch(None, None, lambda *_args: None)


def copy_icon_button(tooltip: str) -> Gtk.Button:
    button = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
    button.set_valign(Gtk.Align.CENTER)
    button.add_css_class("flat")
    button.set_tooltip_text(tooltip)
    return button


def action_icon_button(icon_name: str, tooltip: str) -> Gtk.Button:
    button = Gtk.Button.new_from_icon_name(icon_name)
    button.set_valign(Gtk.Align.CENTER)
    button.add_css_class("flat")
    button.set_tooltip_text(tooltip)
    return button


def menu_button() -> Gtk.MenuButton:
    button = Gtk.MenuButton()
    button.set_icon_name("open-menu-symbolic")
    button.set_tooltip_text("Главное меню")
    button.add_css_class("flat")
    return button
