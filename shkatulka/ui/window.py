"""Main application window: lock state, clipboard hygiene, auto-lock."""

from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path
from typing import Any, Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from ..crypto import InvalidPasswordError  # noqa: E402
from ..vault import (  # noqa: E402
    VaultError,
    VaultSession,
    VaultStore,
    read_backup_file,
)
from .common import install_css, label  # noqa: E402
from .settings import ImportPasswordDialog, SettingsDialog  # noqa: E402
from .unlock import UnlockView  # noqa: E402
from .vaultview import VaultView  # noqa: E402

APP_ID = "io.github.shkatulka.Shkatulka"
APP_VERSION = "1.1.0"


def _activity_clock() -> float:
    """Clock that keeps advancing across suspend (Linux CLOCK_BOOTTIME)."""

    try:
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):
        return time.monotonic()


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, application: Adw.Application) -> None:
        super().__init__(application=application)
        self.set_title("Шкатулка")
        self.set_default_size(1080, 700)
        self.set_size_request(720, 520)
        self.set_icon_name(APP_ID)
        install_css()

        self.store = VaultStore()
        self.session: VaultSession | None = None
        self._vault_view: VaultView | None = None
        self._windows: set[Gtk.Window] = set()
        self._dialogs: set[Adw.Dialog] = set()
        self._task_thread: threading.Thread | None = None
        self._autolock_source: int | None = None
        self._clipboard_source: int | None = None
        self._clipboard_digest: bytes | None = None
        self._last_activity = _activity_clock()
        self._closing = False
        self._lock_pending = False
        self._dbus_subs: list[tuple[Gio.DBusConnection, int]] = []

        self._toolbar_view = Adw.ToolbarView()
        self._lock_header = Adw.HeaderBar()
        self._lock_header.set_show_start_title_buttons(True)
        self._lock_header.set_show_end_title_buttons(True)
        self._lock_header.set_title_widget(label("Шкатулка", css="heading"))
        self._toolbar_view.add_top_bar(self._lock_header)

        self._toast_overlay = Adw.ToastOverlay()
        self._toast_overlay.set_hexpand(True)
        self._toast_overlay.set_vexpand(True)
        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self._stack.set_transition_duration(160)
        self._toast_overlay.set_child(self._stack)
        self._toolbar_view.set_content(self._toast_overlay)
        self.set_content(self._toolbar_view)

        self._build_pages()
        self._create_actions()
        self._install_activity_tracking()
        self._install_session_lock_watchers()
        self.connect("close-request", self._on_close_request)
        self.connect("notify::is-active", self._on_window_active)
        self._show_initial()

    # --------------------------------------------------------------- pages
    def _build_pages(self) -> None:
        self._setup_view = UnlockView(
            mode="create",
            on_create=self._create_vault,
            on_unlock=self._unlock_vault,
            on_forgot=self._show_forgot_help,
            on_import=self._recover_from_backup,
            vault_path=str(self.store.path),
        )
        self._unlock_view = UnlockView(
            mode="unlock",
            on_create=self._create_vault,
            on_unlock=self._unlock_vault,
            on_forgot=self._show_forgot_help,
            on_import=self._recover_from_backup,
            vault_path=str(self.store.path),
        )
        self._stack.add_named(self._setup_view, "setup")
        self._stack.add_named(self._unlock_view, "unlock")

        fatal = Adw.StatusPage()
        fatal.set_icon_name("dialog-error-symbolic")
        fatal.set_title("Не удалось открыть сейф")
        fatal.set_description("Файл сейфа отсутствует, повреждён или небезопасен.")
        close = Gtk.Button(label="Закрыть")
        close.set_halign(Gtk.Align.CENTER)
        close.connect(
            "clicked",
            lambda *_: self.get_application().quit()
            if self.get_application() is not None
            else self.close(),
        )
        fatal.set_child(close)
        self._fatal_page = fatal
        self._stack.add_named(fatal, "fatal")

    def _show_initial(self) -> None:
        self._lock_header.set_visible(True)
        try:
            exists = self.store.exists
        except Exception as exc:
            self._show_fatal(str(exc))
            return
        if exists:
            self._stack.set_visible_child_name("unlock")
            self._unlock_view.focus_password()
        else:
            self._stack.set_visible_child_name("setup")
            self._setup_view.focus_password()

    def _show_fatal(self, message: str) -> None:
        self._lock_header.set_visible(True)
        self._fatal_page.set_description(
            GLib.markup_escape_text(message or "Файл сейфа небезопасен.")
        )
        self._stack.set_visible_child_name("fatal")

    def _on_window_active(self, *_args) -> None:
        if not self.get_property("is-active") or self.session is not None:
            return
        page = self._stack.get_visible_child_name()
        if page == "setup":
            self._setup_view.focus_password()
        elif page == "unlock":
            self._unlock_view.focus_password()

    # -------------------------------------------------------------- actions
    def _create_actions(self) -> None:
        actions = {
            "lock": self._action_lock,
            "settings": self._action_settings,
            "new-password": lambda: self._new_item("password"),
            "new-card": lambda: self._new_item("card"),
            "search": self._action_search,
            "about": self.show_about,
        }
        for name, callback in actions.items():
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", lambda *_args, cb=callback: cb())
            self.add_action(action)

    def _action_lock(self) -> None:
        if self.session is not None:
            self.lock("Вы заблокировали сейф.")

    def _action_settings(self) -> None:
        if self.session is None or self.session.is_locked:
            return
        dialog = SettingsDialog(self)
        self.track_dialog(dialog)
        dialog.present(self)

    def _action_search(self) -> None:
        if self._vault_view is not None:
            self._vault_view.focus_search()

    def _new_item(self, kind: str) -> None:
        if self._vault_view is not None:
            self._vault_view.new_item(kind)

    # --------------------------------------------------------------- create
    def _create_vault(self, password: str) -> None:
        view = self._setup_view
        view.set_busy(True)
        self.note_activity()

        def work() -> VaultSession:
            return VaultSession.create(self.store, password)

        def done(result: Any, error: Exception | None) -> None:
            if error is not None:
                view.show_creation_error(str(error))
                return
            assert isinstance(result, VaultSession)
            view.handle_unlocked()
            self._adopt_session(result)
            self.show_toast("Сейф создан")

        self.run_background(work, done)

    def _unlock_vault(self, password: str) -> None:
        view = self._unlock_view
        view.set_busy(True)
        self.note_activity()

        def work() -> VaultSession:
            return VaultSession.unlock(self.store, password)

        def done(result: Any, error: Exception | None) -> None:
            if error is not None:
                if isinstance(error, InvalidPasswordError):
                    view.handle_wrong_password(str(error))
                else:
                    view.show_unlock_error(str(error))
                return
            assert isinstance(result, VaultSession)
            view.handle_unlocked()
            self._adopt_session(result)
            self.show_toast("Сейф разблокирован")

        self.run_background(work, done)

    def _adopt_session(self, session: VaultSession) -> None:
        if self.session is not None:
            self.session.lock()
        self._close_transients()
        if self._vault_view is not None:
            self._vault_view.shutdown()
            self._stack.remove(self._vault_view)
            self._vault_view = None
        self.session = session
        self._vault_view = VaultView(self, session)
        self._stack.add_named(self._vault_view, "vault")
        self._stack.set_visible_child_name("vault")
        self._lock_header.set_visible(False)
        self.set_title("Шкатулка — сейф")
        self._last_activity = _activity_clock()
        self._start_autolock()

    # ----------------------------------------------------------------- lock
    def lock(self, reason: str = "Сейф заблокирован.") -> None:
        if self.session is None:
            return
        if self._task_thread is not None and self._task_thread.is_alive() and not self._closing:
            # Do not race a background KDF/re-encryption with clearing the key.
            self._lock_pending = True
            self.show_toast("Сейф заблокируется после завершения операции")
            return
        self._close_transients()
        if self._vault_view is not None:
            self._vault_view.shutdown()
            self._stack.remove(self._vault_view)
            self._vault_view = None
        self.session.lock()
        self.session = None
        self._stop_autolock()
        self._clear_clipboard_if_ours(notify=False)
        self.set_title("Шкатулка")
        self._lock_header.set_visible(True)
        self._unlock_view.set_message(reason)
        self._stack.set_visible_child_name("unlock")
        self._unlock_view.focus_password()

    def _on_close_request(self, *_args) -> bool:
        self._closing = True
        self.lock("Сейф закрыт.")
        self._stop_autolock()
        return False

    def shutdown(self) -> None:
        self._closing = True
        self._close_transients()
        if self._vault_view is not None:
            self._vault_view.shutdown()
            self._vault_view = None
        if self.session is not None:
            self.session.lock()
            self.session = None
        self._stop_autolock()
        self._clear_clipboard_if_ours(notify=False)
        for bus, sub in self._dbus_subs:
            try:
                bus.signal_unsubscribe(sub)
            except Exception:
                pass
        self._dbus_subs.clear()

    # ------------------------------------------------------------- auto-lock
    def _start_autolock(self) -> None:
        if self._autolock_source is None:
            self._autolock_source = GLib.timeout_add_seconds(5, self._autolock_tick)

    def _stop_autolock(self) -> None:
        if self._autolock_source is not None:
            GLib.source_remove(self._autolock_source)
            self._autolock_source = None

    def _autolock_tick(self) -> bool:
        if self.session is None:
            self._autolock_source = None
            return False
        timeout = int(self.session.settings.get("auto_lock_seconds", 300))
        if _activity_clock() - self._last_activity >= timeout:
            if self._task_thread is not None and self._task_thread.is_alive():
                # Postpone a fraction of a second: a KDF call is in flight.
                self._last_activity = _activity_clock()
                return True
            self._autolock_source = None
            self.lock("Сейф заблокирован из-за неактивности.")
            return False
        return True

    def reschedule_autolock(self) -> None:
        self._last_activity = _activity_clock()
        if self.session is not None:
            self._start_autolock()

    def note_activity(self) -> None:
        self._last_activity = _activity_clock()

    def _install_activity_tracking(self) -> None:
        self._attach_activity(self)

    def _attach_activity(self, widget: Gtk.Widget) -> None:
        """Reset the idle timer on interaction with the window or a dialog."""

        motion = Gtk.EventControllerMotion()
        motion.connect("motion", lambda *_args: self.note_activity())
        widget.add_controller(motion)

        keys = Gtk.EventControllerKey()
        keys.connect("key-pressed", self._on_key_pressed)
        widget.add_controller(keys)

        click = Gtk.GestureClick()
        click.connect("pressed", lambda *_args: self.note_activity())
        widget.add_controller(click)

    def _on_key_pressed(self, *_args) -> bool:
        self.note_activity()
        return False

    def _install_session_lock_watchers(self) -> None:
        """Best-effort: lock when GNOME locks the screen or the system sleeps."""

        try:
            session_bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        except GLib.Error:
            session_bus = None
        if session_bus is not None:
            try:
                sub = session_bus.signal_subscribe(
                    "org.gnome.ScreenSaver",
                    "org.gnome.ScreenSaver",
                    "ActiveChanged",
                    "/org/gnome/ScreenSaver",
                    None,
                    Gio.DBusSignalFlags.NONE,
                    self._on_screen_saver_changed,
                )
                self._dbus_subs.append((session_bus, sub))
            except GLib.Error:
                pass

        try:
            system_bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        except GLib.Error:
            system_bus = None
        if system_bus is not None:
            try:
                sub = system_bus.signal_subscribe(
                    "org.freedesktop.login1",
                    "org.freedesktop.login1.Manager",
                    "PrepareForSleep",
                    "/org/freedesktop/login1",
                    None,
                    Gio.DBusSignalFlags.NONE,
                    self._on_prepare_for_sleep,
                )
                self._dbus_subs.append((system_bus, sub))
            except GLib.Error:
                pass

    def _on_screen_saver_changed(
        self, _conn, _sender, _path, _iface, _signal, parameters
    ) -> None:
        try:
            active = bool(parameters.unpack()[0])
        except Exception:
            return
        if active and self.session is not None:
            self.lock("Сейф заблокирован вместе с экраном.")

    def _on_prepare_for_sleep(
        self, _conn, _sender, _path, _iface, _signal, parameters
    ) -> None:
        try:
            about_to_sleep = bool(parameters.unpack()[0])
        except Exception:
            return
        if about_to_sleep and self.session is not None:
            self.lock("Сейф заблокирован перед сном системы.")

    # -------------------------------------------------------------- clipboard
    def copy_secret(self, text: str, label_text: str = "Значение") -> None:
        if not text or self.session is None or self.session.is_locked:
            return
        display = Gdk.Display.get_default()
        if display is None:
            self.show_toast("Буфер обмена недоступен")
            return
        clipboard = display.get_clipboard()
        try:
            clipboard.set(text)
        except Exception:
            self.show_toast("Не удалось скопировать значение")
            return
        self._clipboard_digest = hashlib.sha256(text.encode("utf-8")).digest()
        seconds = int(self.session.settings.get("clipboard_seconds", 20))
        if self._clipboard_source is not None:
            GLib.source_remove(self._clipboard_source)
        self._clipboard_source = GLib.timeout_add_seconds(
            seconds, self._clipboard_timer, seconds
        )
        self.note_activity()
        self.show_toast(
            f"{label_text}: скопировано. Буфер очистится через {seconds} с.",
            timeout=4,
        )

    def _clipboard_timer(self, seconds: int) -> bool:
        self._clipboard_source = None
        self._clear_clipboard_if_ours(notify=True)
        return False

    def _clear_clipboard_if_ours(self, *, notify: bool) -> None:
        if self._clipboard_source is not None:
            GLib.source_remove(self._clipboard_source)
            self._clipboard_source = None
        digest = self._clipboard_digest
        self._clipboard_digest = None
        if digest is None:
            return
        display = Gdk.Display.get_default()
        if display is None:
            return
        clipboard = display.get_clipboard()

        def on_text(source: Gdk.Clipboard, result: Gio.AsyncResult) -> None:
            try:
                current = source.read_text_finish(result)
            except GLib.Error:
                return
            if current is None:
                return
            if hashlib.sha256(current.encode("utf-8")).digest() != digest:
                return
            source.set("")
            if notify and not self._closing:
                self.show_toast("Буфер обмена очищен")

        clipboard.read_text_async(None, on_text)

    # ----------------------------------------------------------------- utils
    def show_toast(self, message: str, timeout: int = 3) -> None:
        toast = Adw.Toast.new(message)
        toast.set_use_markup(False)
        toast.set_timeout(timeout)
        self._toast_overlay.add_toast(toast)

    def show_error(self, heading: str, body: str) -> None:
        dialog = Adw.AlertDialog.new(heading, body or "Неизвестная ошибка.")
        dialog.add_response("close", "Понятно")
        dialog.set_close_response("close")
        dialog.set_default_response("close")
        dialog.set_body_use_markup(False)
        self.track_dialog(dialog)
        dialog.present(self)

    def _show_forgot_help(self) -> None:
        dialog = Adw.AlertDialog.new(
            "Восстановление невозможно",
            "Мастер-пароль не хранится и не может быть восстановлен. "
            "Без него файл сейфа остаётся зашифрованным. Если у вас есть "
            "резервная копия и пароль от неё, нажмите «Импортировать копию» "
            "на экране блокировки. Сброса через e-mail или облако не существует.\n\n"
            f"Если это тестовый сейф без ценных данных, закройте приложение "
            f"и переместите файл {self.store.path} в другую папку — после "
            "этого можно создать сейф заново. Не удаляйте старый файл, если "
            "не уверены: данные в нём зашифрованы.",
        )
        dialog.add_response("close", "Понятно")
        dialog.set_close_response("close")
        dialog.set_body_use_markup(False)
        self.track_dialog(dialog)
        dialog.present(self)

    def _recover_from_backup(self) -> None:
        if self.session is not None:
            return
        dialog = Gtk.FileDialog.new()
        dialog.set_title("Открыть резервную копию для восстановления")
        file_filter = Gtk.FileFilter()
        file_filter.set_name("Сейф Шкатулка (*.shk)")
        file_filter.add_pattern("*.shk")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(file_filter)
        dialog.set_filters(filters)
        dialog.set_default_filter(file_filter)

        def on_open(source: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            if self.session is not None:
                return
            try:
                gfile = source.open_finish(result)
            except GLib.Error:
                return
            path = gfile.get_path() if gfile is not None else None
            if not path:
                self.show_error(
                    "Не удалось открыть",
                    "Выберите локальный файл на этом компьютере.",
                )
                return
            try:
                data = read_backup_file(path)
            except VaultError as exc:
                self.show_error("Не удалось прочитать файл", str(exc))
                return
            self._confirm_recovery(path, data)

        dialog.open(self, None, on_open)

    def _confirm_recovery(self, path: str, data: bytes) -> None:
        dialog = Adw.AlertDialog.new(
            "Заменить сейф резервной копией?",
            "Текущий файл сейфа будет перезаписан. Предыдущая версия "
            "сохранится рядом как vault.shk.bak-…; старый пароль больше не "
            "подойдёт, если копия защищена другим паролем.",
        )
        dialog.add_response("cancel", "Отмена")
        dialog.add_response("import", "Продолжить")
        dialog.set_response_appearance("import", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.set_body_use_markup(False)

        def on_response(source: Adw.AlertDialog, response: str) -> None:
            if response != "import" or self.session is not None:
                return
            password_dialog = ImportPasswordDialog(
                self,
                backup_name=Path(path).name,
                data=data,
                recover=True,
            )
            self.track_window(password_dialog)
            password_dialog.present()

        dialog.connect("response", on_response)
        self.track_dialog(dialog)
        dialog.present(self)

    def after_recovery_import(self) -> None:
        self._setup_view.handle_unlocked()
        self._lock_header.set_visible(True)
        self._stack.set_visible_child_name("unlock")
        self._unlock_view.set_message(
            "Резервная копия импортирована. Введите мастер-пароль этой копии."
        )
        self._unlock_view.focus_password()
        self.show_toast("Резервная копия импортирована")

    def import_backup_locked_async(
        self,
        data: bytes,
        password: str,
        callback: Callable[[bool, Exception | None], None],
    ) -> None:
        if self.session is not None:
            callback(False, VaultError("Сначала заблокируйте текущий сейф."))
            return

        def work() -> VaultSession:
            return VaultSession.import_from(self.store, data, password)

        def done(result: Any, error: Exception | None) -> None:
            if error is not None:
                callback(False, error)
                return
            assert isinstance(result, VaultSession)
            # The restored vault is written to disk, but we deliberately do
            # not leave it unlocked: the user must enter its master password.
            result.lock()
            callback(True, None)

        self.run_background(work, done)

    def track_window(self, window: Gtk.Window) -> None:
        self._windows.add(window)
        self._attach_activity(window)
        window.connect("close-request", self._on_tracked_window_closed)

    def _on_tracked_window_closed(self, window: Gtk.Window) -> bool:
        self._windows.discard(window)
        return False

    def track_dialog(self, dialog: Adw.Dialog) -> None:
        self._dialogs.add(dialog)
        try:
            self._attach_activity(dialog)
        except Exception:
            pass
        try:
            dialog.connect("closed", lambda d: self._dialogs.discard(d))
        except TypeError:
            pass

    def _close_transients(self) -> None:
        for window in list(self._windows):
            self._windows.discard(window)
            try:
                window.close()
            except Exception:
                pass
        for dialog in list(self._dialogs):
            self._dialogs.discard(dialog)
            try:
                dialog.force_close()
            except Exception:
                pass

    # ------------------------------------------------------------- background
    def run_background(
        self,
        work: Callable[[], Any],
        callback: Callable[[Any, Exception | None], None],
    ) -> None:
        if self._task_thread is not None and self._task_thread.is_alive():
            callback(None, RuntimeError("Дождитесь завершения другой операции."))
            return
        holder: dict[str, Any] = {}

        def runner() -> None:
            try:
                holder["result"] = work()
            except BaseException as exc:  # keep the UI responsive on any error
                holder["error"] = exc

        thread = threading.Thread(
            target=runner, name="shkatulka-crypto", daemon=True
        )
        self._task_thread = thread
        thread.start()

        def poll() -> bool:
            if thread.is_alive():
                return True
            self._task_thread = None
            if not self.get_visible():
                result = holder.get("result")
                if isinstance(result, VaultSession):
                    result.lock()
                return False
            try:
                callback(holder.get("result"), holder.get("error"))
            except Exception as exc:
                self.show_error("Внутренняя ошибка", str(exc))
            if self._lock_pending and not self._closing:
                self._lock_pending = False
                self.lock("Сейф заблокирован.")
            return False

        GLib.timeout_add(50, poll)

    def change_password_async(
        self,
        current: str,
        new: str,
        callback: Callable[[bool, Exception | None], None],
    ) -> None:
        session = self.session
        if session is None or session.is_locked:
            callback(False, VaultError("Сейф заблокирован."))
            return

        def work() -> None:
            session.change_password(current, new)

        def done(_result: Any, error: Exception | None) -> None:
            callback(error is None, error)

        self.run_background(work, done)

    def import_backup_async(
        self,
        data: bytes,
        password: str,
        callback: Callable[[bool, Exception | None], None],
    ) -> None:
        def work() -> VaultSession:
            return VaultSession.import_from(self.store, data, password)

        def done(result: Any, error: Exception | None) -> None:
            if error is not None:
                callback(False, error)
                return
            assert isinstance(result, VaultSession)
            if self.session is None or self.session.is_locked:
                result.lock()
                callback(
                    False,
                    VaultError(
                        "Сейф был заблокирован во время импорта. "
                        "Разблокируйте его паролем резервной копии."
                    ),
                )
                return
            self._adopt_session(result)
            callback(True, None)

        self.run_background(work, done)

    # ----------------------------------------------------------------- about
    def show_about(self) -> None:
        about = Adw.AboutDialog()
        about.set_application_name("Шкатулка")
        about.set_application_icon(APP_ID)
        about.set_developer_name("Локальный проект")
        about.set_version(APP_VERSION)
        about.set_comments(
            "Локальный сейф паролей и данных банковских карт для Ubuntu.\n"
            "Argon2id + AES-256-GCM. Без облака и сетевых запросов."
        )
        about.set_copyright("© 2026")
        about.set_license_type(Gtk.License.MIT_X11)
        about.add_acknowledgement_section(
            "Безопасность",
            [
                "Argon2id (RFC 9106)",
                "AES-256-GCM (NIST SP 800-38D)",
                "NIST SP 800-63B-4 — политика мастер-пароля",
                "PCI DSS 4.0 — отказ от хранения CVV/CVC",
            ],
        )
        self.track_dialog(about)
        about.present(self)
