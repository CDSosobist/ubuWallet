"""Application entry point."""

from __future__ import annotations

import ctypes
import os
import resource
import sys
import traceback

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from .ui.common import RESOURCE_DIR, install_css  # noqa: E402
from .ui.window import APP_ID, MainWindow  # noqa: E402
from .vault import VaultStore  # noqa: E402


def _harden_process() -> None:
    """Best-effort process hardening before any secret is loaded.

    - no core dumps (they could contain keys/plaintext);
    - no ptrace/process_vm_readv by same-UID processes;
    - conservative umask for every file the app creates.
    """

    try:
        os.umask(0o077)
    except OSError:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # PR_SET_DUMPABLE = 4
        libc.prctl(4, 0, 0, 0, 0)
    except Exception:
        pass


class ShkatulkaApplication(Adw.Application):
    def __init__(self) -> None:
        _harden_process()
        super().__init__(
            application_id=APP_ID,
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.store = VaultStore()
        self.window: MainWindow | None = None
        self._error_window: Adw.ApplicationWindow | None = None

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        display = Gdk.Display.get_default()
        if display is not None:
            theme = Gtk.IconTheme.get_for_display(display)
            theme.add_search_path(str(RESOURCE_DIR / "icons" / "hicolor"))
            Gtk.Window.set_default_icon_name(APP_ID)
        install_css()

        self._install_action("quit", self.quit)
        self._install_action("about", self._show_about)
        self.set_accels_for_action("app.quit", ["<Control>q"])
        self.set_accels_for_action("win.lock", ["<Control>l"])
        self.set_accels_for_action("win.settings", ["<Control>comma"])
        self.set_accels_for_action("win.new-password", ["<Control>n"])
        self.set_accels_for_action("win.new-card", ["<Control><Shift>n"])
        self.set_accels_for_action("win.search", ["<Control>f"])

    def _install_action(self, name: str, callback) -> None:
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", lambda *_args: callback())
        self.add_action(action)

    def _show_about(self) -> None:
        if self.window is not None:
            self.window.show_about()

    def do_activate(self) -> None:
        if self.window is not None:
            self.window.present()
            return
        try:
            self.store.acquire_lock()
        except Exception as exc:
            self._show_startup_error(exc)
            return
        try:
            self.window = MainWindow(self)
        except Exception as exc:
            self.store.release_lock()
            self._show_startup_error(exc)
            return
        self.window.present()

    def do_shutdown(self) -> None:
        if self.window is not None:
            try:
                self.window.shutdown()
            except Exception:
                pass
        self.store.release_lock()
        Adw.Application.do_shutdown(self)

    def _show_startup_error(self, exc: Exception) -> None:
        traceback.print_exc()
        if self._error_window is not None:
            self._error_window.present()
            return
        window = Adw.ApplicationWindow(application=self)
        window.set_title("Шкатулка")
        window.set_default_size(520, 360)
        page = Adw.StatusPage()
        page.set_icon_name("dialog-error-symbolic")
        page.set_title("Не удалось запустить Шкатулку")
        page.set_description(GLib.markup_escape_text(str(exc) or "Неизвестная ошибка."))
        button = Gtk.Button(label="Закрыть")
        button.set_halign(Gtk.Align.CENTER)
        button.add_css_class("pill-button")
        button.connect("clicked", lambda *_: self.quit())
        page.set_child(button)
        window.set_content(page)
        self._error_window = window
        window.present()


def main(argv: list[str] | None = None) -> int:
    app = ShkatulkaApplication()
    return app.run(sys.argv if argv is None else argv)


if __name__ == "__main__":
    raise SystemExit(main())
