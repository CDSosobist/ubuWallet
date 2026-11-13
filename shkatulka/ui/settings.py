"""Settings, master-password change, encrypted backup import/export."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from ..crypto import InvalidPasswordError  # noqa: E402
from ..security import validate_master_password  # noqa: E402
from ..vault import (  # noqa: E402
    AUTO_LOCK_CHOICES,
    CLIPBOARD_CHOICES,
    VaultError,
    read_backup_file,
)
from .common import (  # noqa: E402
    PasswordStrengthMeter,
    error_label,
    icon,
    label,
    show_error,
    text_field,
    password_entry,
)

if TYPE_CHECKING:
    from .window import MainWindow


AUTO_LOCK_LABELS = ("1 минута", "5 минут", "15 минут", "30 минут", "1 час")
CLIPBOARD_LABELS = ("5 секунд", "10 секунд", "20 секунд", "30 секунд", "60 секунд")


class SettingsDialog(Adw.PreferencesDialog):
    def __init__(self, window: "MainWindow") -> None:
        super().__init__()
        self._window = window
        self._session = window.session
        self.set_title("Настройки")

        page = Adw.PreferencesPage()
        self.add(page)

        security = Adw.PreferencesGroup(title="Безопасность")
        page.add(security)

        self._auto_lock = Adw.ComboRow(title="Автоблокировка")
        self._auto_lock.set_model(Gtk.StringList.new(list(AUTO_LOCK_LABELS)))
        current = self._session.settings["auto_lock_seconds"]
        self._auto_lock.set_selected(
            AUTO_LOCK_CHOICES.index(current) if current in AUTO_LOCK_CHOICES else 1
        )
        self._auto_lock.connect("notify::selected", lambda *_: self._auto_lock_changed())
        security.add(self._auto_lock)

        self._clipboard = Adw.ComboRow(title="Очистка буфера обмена")
        self._clipboard.set_model(Gtk.StringList.new(list(CLIPBOARD_LABELS)))
        current_clip = self._session.settings["clipboard_seconds"]
        self._clipboard.set_selected(
            CLIPBOARD_CHOICES.index(current_clip) if current_clip in CLIPBOARD_CHOICES else 2
        )
        self._clipboard.connect("notify::selected", lambda *_: self._clipboard_changed())
        security.add(self._clipboard)

        change_row = Adw.ActionRow(title="Мастер-пароль")
        change_row.set_subtitle("Сменить пароль шифрования сейфа")
        change_button = Gtk.Button(label="Изменить")
        change_button.set_valign(Gtk.Align.CENTER)
        change_button.add_css_class("flat")
        change_button.connect("clicked", lambda *_: self._open_change_password())
        change_row.add_suffix(change_button)
        security.add(change_row)

        security.add(
            _info_row(
                "Ключ шифрования существует только в оперативной памяти, пока сейф "
                "разблокирован. На диск мастер-пароль и ключ не записываются."
            )
        )

        backup = Adw.PreferencesGroup(title="Резервные копии")
        page.add(backup)

        export_row = Adw.ActionRow(title="Экспортировать зашифрованную копию")
        export_row.set_subtitle("Тот же мастер-пароль, отдельный файл")
        export_button = Gtk.Button(label="Сохранить")
        export_button.set_valign(Gtk.Align.CENTER)
        export_button.add_css_class("flat")
        export_button.connect("clicked", lambda *_: self._export_backup())
        export_row.add_suffix(export_button)
        backup.add(export_row)

        import_row = Adw.ActionRow(title="Импортировать копию")
        import_row.set_subtitle("Заменит текущий сейф после подтверждения")
        import_button = Gtk.Button(label="Выбрать")
        import_button.set_valign(Gtk.Align.CENTER)
        import_button.add_css_class("flat")
        import_button.connect("clicked", lambda *_: self._choose_import())
        import_row.add_suffix(import_button)
        backup.add(import_row)

        backup.add(
            _info_row(
                "Резервная копия — это зашифрованный файл сейфа. Храните её отдельно "
                "и помните: без мастер-пароля восстановить данные невозможно."
            )
        )

        about = Adw.PreferencesGroup(title="О программе")
        page.add(about)
        version = Adw.ActionRow(title="Шкатулка", subtitle="Версия 1.1.0")
        about.add(version)
        security_info = Adw.ActionRow(
            title="Модель безопасности",
            subtitle="Argon2id, AES-256-GCM, локальное хранение",
        )
        security_info.set_activatable(True)
        security_info.connect("activated", lambda *_: self._open_security_info())
        about.add(security_info)

    # ------------------------------------------------------------- settings
    def _auto_lock_changed(self) -> None:
        index = self._auto_lock.get_selected()
        if not 0 <= index < len(AUTO_LOCK_CHOICES):
            return
        try:
            self._session.update_settings(auto_lock_seconds=AUTO_LOCK_CHOICES[index])
        except Exception as exc:
            self._window.show_error("Не удалось сохранить настройку", str(exc))
            return
        self._window.reschedule_autolock()
        self._window.note_activity()
        self._window.show_toast("Автоблокировка обновлена")

    def _clipboard_changed(self) -> None:
        index = self._clipboard.get_selected()
        if not 0 <= index < len(CLIPBOARD_CHOICES):
            return
        try:
            self._session.update_settings(clipboard_seconds=CLIPBOARD_CHOICES[index])
        except Exception as exc:
            self._window.show_error("Не удалось сохранить настройку", str(exc))
            return
        self._window.note_activity()
        self._window.show_toast("Очистка буфера обмена обновлена")

    # --------------------------------------------------------------- backup
    def _export_backup(self) -> None:
        dialog = Gtk.FileDialog.new()
        dialog.set_title("Сохранить зашифрованную копию")
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        dialog.set_initial_name(f"shkatulka-backup-{stamp}.shk")
        file_filter = Gtk.FileFilter()
        file_filter.set_name("Сейф Шкатулка (*.shk)")
        file_filter.add_pattern("*.shk")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(file_filter)
        dialog.set_filters(filters)
        dialog.set_default_filter(file_filter)

        def on_save(source: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            if self._session.is_locked:
                return
            try:
                gfile = source.save_finish(result)
            except GLib.Error:
                return
            if gfile is None:
                return
            path = gfile.get_path()
            if not path:
                self._window.show_error(
                    "Не удалось сохранить",
                    "Выберите локальную папку на этом компьютере.",
                )
                return
            try:
                self._session.export_backup(path)
            except Exception as exc:
                self._window.show_error("Не удалось создать копию", str(exc))
                return
            self._window.show_toast("Зашифрованная копия сохранена")

        dialog.save(self._window, None, on_save)

    def _choose_import(self) -> None:
        dialog = Gtk.FileDialog.new()
        dialog.set_title("Открыть зашифрованную копию")
        file_filter = Gtk.FileFilter()
        file_filter.set_name("Сейф Шкатулка (*.shk)")
        file_filter.add_pattern("*.shk")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(file_filter)
        dialog.set_filters(filters)
        dialog.set_default_filter(file_filter)

        def on_open(source: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            if self._session.is_locked:
                return
            try:
                gfile = source.open_finish(result)
            except GLib.Error:
                return
            if gfile is None:
                return
            path = gfile.get_path()
            if not path:
                self._window.show_error(
                    "Не удалось открыть",
                    "Выберите локальный файл на этом компьютере.",
                )
                return
            try:
                data = read_backup_file(path)
            except VaultError as exc:
                self._window.show_error("Не удалось прочитать файл", str(exc))
                return
            self._confirm_import(path, data)

        dialog.open(self._window, None, on_open)

    def _confirm_import(self, path: str, data: bytes) -> None:
        dialog = Adw.AlertDialog.new(
            "Заменить текущий сейф?",
            "Импорт перезапишет открытый сейф содержимым резервной копии. "
            "Предыдущая версия сохранится рядом как vault.shk.bak-…",
        )
        dialog.add_response("cancel", "Отмена")
        dialog.add_response("import", "Продолжить")
        dialog.set_response_appearance("import", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.set_body_use_markup(False)

        def on_response(source: Adw.AlertDialog, response: str) -> None:
            if response != "import" or self._session.is_locked:
                return
            self.close()
            password_dialog = ImportPasswordDialog(
                self._window,
                backup_name=Path(path).name,
                data=data,
            )
            self._window.track_window(password_dialog)
            password_dialog.present()

        dialog.connect("response", on_response)
        self._window.track_dialog(dialog)
        dialog.present(self._window)

    # -------------------------------------------------------------- dialogs
    def _open_change_password(self) -> None:
        dialog = ChangePasswordDialog(self._window)
        self._window.track_window(dialog)
        dialog.present()

    def _open_security_info(self) -> None:
        dialog = SecurityInfoDialog(self._window)
        self._window.track_window(dialog)
        dialog.present()


def _info_row(text: str) -> Gtk.Widget:
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    box.set_margin_start(12)
    box.set_margin_end(12)
    box.set_margin_top(6)
    box.set_margin_bottom(6)
    image = icon("dialog-information-symbolic", 16)
    image.set_valign(Gtk.Align.START)
    box.append(image)
    box.append(label(text, css="caption dim-label", wrap=True))
    return box


class ChangePasswordDialog(Adw.Window):
    def __init__(self, window: "MainWindow") -> None:
        super().__init__()
        self._window = window
        self.set_transient_for(window)
        self.set_modal(True)
        self.set_destroy_with_parent(True)
        self.set_default_size(520, 660)
        self.set_title("Смена мастер-пароля")

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        cancel = Gtk.Button(label="Отмена")
        cancel.connect("clicked", lambda *_: self.close())
        header.pack_start(cancel)
        self._save = Gtk.Button(label="Изменить")
        self._save.add_css_class("suggested-action")
        self._save.connect("clicked", lambda *_: self._submit())
        header.pack_end(self._save)
        toolbar.add_top_bar(header)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        outer.set_margin_top(16)
        outer.set_margin_bottom(20)
        outer.set_margin_start(22)
        outer.set_margin_end(22)

        warning = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        warning.append(icon("dialog-warning-symbolic", 18))
        warning.append(
            label(
                "После смены пароля старые резервные копии можно открыть только "
                "старым паролем. Создайте новую копию.",
                css="warning-label",
                wrap=True,
            )
        )
        outer.append(warning)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.add_css_class("card-box")
        self._current = password_entry("Текущий мастер-пароль")
        card.append(text_field("Текущий пароль", self._current))
        self._new = password_entry("Новый мастер-пароль, минимум 15 символов")
        card.append(text_field("Новый пароль", self._new))
        self._strength = PasswordStrengthMeter()
        card.append(self._strength)
        self._confirm = password_entry("Повторите новый пароль")
        card.append(text_field("Подтверждение", self._confirm))
        self._error = error_label()
        card.append(self._error)
        self._spinner = Gtk.Spinner()
        self._spinner.set_visible(False)
        card.append(self._spinner)
        outer.append(card)
        toolbar.set_content(outer)
        self.set_content(toolbar)

        self._new.connect(
            "notify::text", lambda *_: self._strength.update(self._new.get_text())
        )
        self._confirm.connect("activate", lambda *_: self._submit())
        self.connect("close-request", self._clear)

    def _submit(self) -> None:
        if not self._save.get_sensitive():
            return
        current = self._current.get_text()
        new = self._new.get_text()
        confirm = self._confirm.get_text()
        show_error(self._error, "")
        if not current:
            show_error(self._error, "Введите текущий мастер-пароль.")
            return
        if new != confirm:
            show_error(self._error, "Новые пароли не совпадают.")
            return
        try:
            validate_master_password(new)
        except Exception as exc:
            show_error(self._error, str(exc))
            return
        self._set_busy(True)

        def done(ok: bool, error: Exception | None) -> None:
            self._set_busy(False)
            if not ok:
                show_error(self._error, str(error) if error else "Не удалось сменить пароль.")
                return
            self.close()
            self._window.show_toast("Мастер-пароль изменён")

        self._window.change_password_async(current, new, done)

    def _set_busy(self, busy: bool) -> None:
        for widget in (self._current, self._new, self._confirm, self._save):
            widget.set_sensitive(not busy)
        self._spinner.set_visible(busy)
        if busy:
            self._spinner.start()
        else:
            self._spinner.stop()
        self._save.set_label("Меняем…" if busy else "Изменить")

    def _clear(self, *_args) -> bool:
        self._current.set_text("")
        self._new.set_text("")
        self._confirm.set_text("")
        return False


class ImportPasswordDialog(Adw.Window):
    def __init__(
        self,
        window: "MainWindow",
        *,
        backup_name: str,
        data: bytes,
        recover: bool = False,
    ) -> None:
        super().__init__()
        self._window = window
        self._data = data
        self._recover = recover
        self.set_transient_for(window)
        self.set_modal(True)
        self.set_destroy_with_parent(True)
        self.set_default_size(500, 460)
        self.set_title("Импорт резервной копии")

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        cancel = Gtk.Button(label="Отмена")
        cancel.connect("clicked", lambda *_: self.close())
        header.pack_start(cancel)
        self._import = Gtk.Button(label="Импортировать")
        self._import.add_css_class("destructive-action")
        self._import.connect("clicked", lambda *_: self._submit())
        header.pack_end(self._import)
        toolbar.add_top_bar(header)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        outer.set_margin_top(16)
        outer.set_margin_bottom(20)
        outer.set_margin_start(22)
        outer.set_margin_end(22)
        outer.append(label("Введите пароль резервной копии", css="title-3"))
        outer.append(label(backup_name, css="dim-label", wrap=True))

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.add_css_class("card-box")
        self._password = password_entry("Мастер-пароль резервной копии")
        card.append(text_field("Мастер-пароль", self._password))
        self._error = error_label()
        card.append(self._error)
        self._spinner = Gtk.Spinner()
        self._spinner.set_visible(False)
        card.append(self._spinner)
        outer.append(card)
        toolbar.set_content(outer)
        self.set_content(toolbar)
        self._password.connect("activate", lambda *_: self._submit())
        self.connect("close-request", self._clear)

    def _submit(self) -> None:
        if not self._import.get_sensitive():
            return
        password = self._password.get_text()
        if not password:
            show_error(self._error, "Введите пароль резервной копии.")
            return
        show_error(self._error, "")
        self._set_busy(True)

        def done(ok: bool, error: Exception | None) -> None:
            self._set_busy(False)
            if not ok:
                message = str(error) if error else "Не удалось импортировать сейф."
                if isinstance(error, InvalidPasswordError):
                    message = "Неверный пароль или повреждённая резервная копия."
                show_error(self._error, message)
                return
            self.close()
            if self._recover:
                self._window.after_recovery_import()
            else:
                self._window.show_toast("Сейф импортирован")

        if self._recover:
            self._window.import_backup_locked_async(self._data, password, done)
        else:
            self._window.import_backup_async(self._data, password, done)

    def _set_busy(self, busy: bool) -> None:
        self._password.set_sensitive(not busy)
        self._import.set_sensitive(not busy)
        self._spinner.set_visible(busy)
        if busy:
            self._spinner.start()
            self._import.set_label("Проверяем…")
        else:
            self._spinner.stop()
            self._import.set_label("Импортировать")

    def _clear(self, *_args) -> bool:
        self._password.set_text("")
        self._data = b""
        return False


class SecurityInfoDialog(Adw.Window):
    def __init__(self, window: "MainWindow") -> None:
        super().__init__()
        self.set_transient_for(window)
        self.set_modal(True)
        self.set_destroy_with_parent(True)
        self.set_default_size(640, 720)
        self.set_title("Модель безопасности")

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        close = Gtk.Button(label="Закрыть")
        close.connect("clicked", lambda *_: self.close())
        header.pack_end(close)
        toolbar.add_top_bar(header)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        clamp = Adw.Clamp()
        clamp.set_maximum_size(620)
        scroller.set_child(clamp)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_margin_top(20)
        box.set_margin_bottom(28)
        box.set_margin_start(22)
        box.set_margin_end(22)
        clamp.set_child(box)

        box.append(label("Как защищены данные", css="title-2"))
        sections = (
            (
                "Шифрование",
                "Содержимое сейфа целиком шифруется AES-256-GCM со случайным "
                "96-битным nonce при каждом сохранении. Заголовок файла "
                "аутентифицируется как associated data: изменение параметров "
                "KDF или nonce делает расшифровку невозможной.",
            ),
            (
                "Ключ из мастер-пароля",
                "Argon2id, 64 МиБ памяти, 3 прохода, 4 параллельные линии, "
                "случайная 128-битная соль. Параметры KDF ограничены при "
                "открытии, чтобы повреждённый файл не вызвал исчерпание памяти.",
            ),
            (
                "Локальность",
                "Приложение не содержит сетевого кода и не отправляет данные "
                "в облако. Мастер-пароль и производный ключ не записываются "
                "на диск; ключ обнуляется при блокировке.",
            ),
            (
                "Файлы и права",
                "Каталог сейфа — 0700, файл — 0600. Запись атомарная: временный "
                "файл, fsync, переименование и fsync каталога. Символические "
                "ссылки отклоняются, второй экземпляр приложения блокируется "
                "через flock.",
            ),
            (
                "Карты",
                "Номер карты проверяется по Луну, по умолчанию показывается "
                "только последние 4 цифры. CVV/CVC и PIN не запрашиваются и не "
                "хранятся: PCI DSS 4.0 запрещает сохранять sensitive "
                "authentication data после авторизации.",
            ),
            (
                "Ограничения",
                "Как и любой локальный менеджер, приложение не защищает от "
                "вредоносного ПО, кейлоггера, root-доступа, захвата экрана или "
                "физического доступа к уже разблокированному компьютеру. "
                "Буфер обмена может попасть в историю буфера обмена GNOME; "
                "автоочистка — мера снижения риска, а не гарантия. Python не "
                "даёт гарантированно стереть все копии строк из памяти.",
            ),
        )
        for title, body in sections:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            card.add_css_class("card-box")
            card.append(label(title, css="heading"))
            card.append(label(body, wrap=True, selectable=True))
            box.append(card)

        toolbar.set_content(scroller)
        self.set_content(toolbar)
