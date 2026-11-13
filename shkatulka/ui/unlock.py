"""First-run and unlock screens."""

from __future__ import annotations

import math
import time
from typing import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from ..security import MIN_MASTER_PASSWORD_CHARS, UnlockThrottle  # noqa: E402
from .common import (  # noqa: E402
    PasswordStrengthMeter,
    app_icon_image,
    error_label,
    icon,
    label,
    make_card_box,
    password_entry,
    show_error,
    text_field,
)


class UnlockView(Gtk.Box):
    def __init__(
        self,
        *,
        mode: str,
        on_create: Callable[[str], None],
        on_unlock: Callable[[str], None],
        on_forgot: Callable[[], None],
        on_import: Callable[[], None] | None = None,
        message: str = "",
        vault_path: str = "",
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self._mode = mode
        self._on_create = on_create
        self._on_unlock = on_unlock
        self._on_forgot = on_forgot
        self._on_import = on_import
        self._busy = False
        self._throttle = UnlockThrottle()
        self._cooldown_source: int | None = None
        self._cooldown_until = 0.0
        self._last_error = ""
        self._message_text = message

        scroller = Gtk.ScrolledWindow()
        scroller.set_vexpand(True)
        scroller.set_hexpand(True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.append(scroller)

        clamp = Adw.Clamp()
        clamp.set_maximum_size(460)
        clamp.set_tightening_threshold(380)
        scroller.set_child(clamp)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        outer.set_valign(Gtk.Align.CENTER)
        outer.set_margin_top(36)
        outer.set_margin_bottom(36)
        outer.set_margin_start(24)
        outer.set_margin_end(24)
        clamp.set_child(outer)

        if mode == "create":
            self._build_create(outer)
        else:
            self._build_unlock(outer)

        footer = label(
            "Argon2id · AES-256-GCM · данные не покидают это устройство",
            css="caption dim-label",
            wrap=True,
            xalign=0.5,
        )
        footer.set_halign(Gtk.Align.CENTER)
        outer.append(footer)

    # ------------------------------------------------------------------ UI
    def _build_create(self, outer: Gtk.Box) -> None:
        hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        hero.set_halign(Gtk.Align.CENTER)
        hero.append(app_icon_image(88))
        title = label("Создайте сейф", css="hero-title", xalign=0.5)
        title.set_halign(Gtk.Align.CENTER)
        hero.append(title)
        subtitle = label(
            "Пароли и данные карт шифруются на этом компьютере. "
            "Мастер-пароль не сохраняется нигде.",
            css="hero-subtitle dim-label",
            wrap=True,
            xalign=0.5,
        )
        subtitle.set_halign(Gtk.Align.CENTER)
        hero.append(subtitle)
        outer.append(hero)

        card = make_card_box()
        self._create_password = password_entry("Длинная фраза, минимум 15 символов")
        card.append(text_field("Мастер-пароль", self._create_password))
        card.append(
            label(
                "Регистр, раскладка и пробелы учитываются.",
                css="caption dim-label",
            )
        )

        self._strength = PasswordStrengthMeter()
        card.append(self._strength)

        self._create_confirm = password_entry("Повторите мастер-пароль")
        card.append(text_field("Подтверждение", self._create_confirm))

        self._ack = Gtk.CheckButton(label="Понимаю: пароль нельзя восстановить")
        self._ack.connect("toggled", lambda *_: self._update_create_button())
        card.append(self._ack)

        self._create_error = error_label()
        card.append(self._create_error)

        self._create_button = Gtk.Button(label="Создать сейф")
        self._create_button.add_css_class("suggested-action")
        self._create_button.add_css_class("pill-button")
        self._create_button.set_sensitive(False)
        self._create_button.connect("clicked", lambda *_: self._submit_create())
        card.append(self._create_button)

        self._create_spinner = Gtk.Spinner()
        self._create_spinner.set_visible(False)
        card.append(self._create_spinner)
        outer.append(card)

        warning = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        warning.set_margin_start(4)
        warning.set_margin_end(4)
        warning.append(icon("dialog-warning-symbolic", 16))
        warning.append(
            label(
                "Облака и сброса пароля нет. Сохраните мастер-пароль "
                "в надёжном месте — например, в менеджере паролей на телефоне.",
                css="warning-label",
                wrap=True,
            )
        )
        outer.append(warning)

        if self._on_import is not None:
            self._create_import_link = Gtk.Button(label="Импортировать резервную копию")
            self._create_import_link.add_css_class("flat")
            self._create_import_link.add_css_class("link-button")
            self._create_import_link.set_halign(Gtk.Align.CENTER)
            self._create_import_link.connect("clicked", lambda *_: self._on_import())
            outer.append(self._create_import_link)

        self._create_password.connect(
            "notify::text", lambda *_: self._strength.update(self._create_password.get_text())
        )
        self._create_password.connect(
            "activate", lambda *_: self._create_confirm.grab_focus()
        )
        self._create_confirm.connect("activate", lambda *_: self._submit_create())

    def _build_unlock(self, outer: Gtk.Box) -> None:
        hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        hero.set_halign(Gtk.Align.CENTER)
        lock_image = app_icon_image(88)
        lock_image.add_css_class("vault-locked-icon")
        hero.append(lock_image)
        title = label("Сейф заблокирован", css="hero-title", xalign=0.5)
        title.set_halign(Gtk.Align.CENTER)
        hero.append(title)
        self._unlock_message = label(
            self._message_text or "Введите мастер-пароль, чтобы открыть записи.",
            css="hero-subtitle dim-label",
            wrap=True,
            xalign=0.5,
        )
        self._unlock_message.set_halign(Gtk.Align.CENTER)
        hero.append(self._unlock_message)
        outer.append(hero)

        card = make_card_box()
        self._unlock_password = password_entry("Мастер-пароль")
        card.append(text_field("Мастер-пароль", self._unlock_password))
        card.append(
            label(
                "Пароль чувствителен к регистру, раскладке и пробелам.",
                css="caption dim-label",
            )
        )

        self._unlock_error = error_label()
        card.append(self._unlock_error)

        self._unlock_button = Gtk.Button(label="Разблокировать")
        self._unlock_button.add_css_class("suggested-action")
        self._unlock_button.add_css_class("pill-button")
        self._unlock_button.connect("clicked", lambda *_: self._submit_unlock())
        card.append(self._unlock_button)

        self._unlock_spinner = Gtk.Spinner()
        self._unlock_spinner.set_visible(False)
        card.append(self._unlock_spinner)
        outer.append(card)

        links = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        links.set_halign(Gtk.Align.CENTER)
        forgot = Gtk.Button(label="Забыли мастер-пароль?")
        forgot.add_css_class("flat")
        forgot.add_css_class("link-button")
        forgot.connect("clicked", lambda *_: self._on_forgot())
        links.append(forgot)
        if self._on_import is not None:
            self._unlock_import_link = Gtk.Button(label="Импортировать копию")
            self._unlock_import_link.add_css_class("flat")
            self._unlock_import_link.add_css_class("link-button")
            self._unlock_import_link.connect("clicked", lambda *_: self._on_import())
            links.append(self._unlock_import_link)
        outer.append(links)

        self._unlock_password.connect("activate", lambda *_: self._submit_unlock())

    # --------------------------------------------------------------- actions
    def _update_create_button(self) -> None:
        self._create_button.set_sensitive(self._ack.get_active() and not self._busy)

    def _submit_create(self) -> None:
        if self._busy:
            return
        if not self._ack.get_active():
            show_error(self._create_error, "Подтвердите, что понимаете риск утраты пароля.")
            return
        password = self._create_password.get_text()
        confirm = self._create_confirm.get_text()
        if password != confirm:
            show_error(self._create_error, "Пароли не совпадают.")
            self._create_confirm.grab_focus()
            return
        if len(password) < MIN_MASTER_PASSWORD_CHARS:
            show_error(
                self._create_error,
                f"Мастер-пароль должен содержать минимум "
                f"{MIN_MASTER_PASSWORD_CHARS} символов.",
            )
            self._create_password.grab_focus()
            return
        show_error(self._create_error, "")
        self._on_create(password)

    def _submit_unlock(self) -> None:
        if self._busy:
            return
        remaining = self._throttle.remaining()
        if remaining > 0:
            self._render_cooldown(remaining)
            return
        password = self._unlock_password.get_text()
        if not password:
            show_error(self._unlock_error, "Введите мастер-пароль.")
            return
        show_error(self._unlock_error, "")
        self._on_unlock(password)

    # ----------------------------------------------------------- state from app
    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        if self._mode == "create":
            for widget in (
                self._create_password,
                self._create_confirm,
                self._ack,
                self._create_button,
            ):
                widget.set_sensitive(not busy and (widget is not self._create_button or self._ack.get_active()))
            self._create_spinner.set_visible(busy)
            if busy:
                self._create_spinner.start()
            else:
                self._create_spinner.stop()
            self._create_button.set_label("Создаём…" if busy else "Создать сейф")
            if hasattr(self, "_create_import_link"):
                self._create_import_link.set_sensitive(not busy)
        else:
            self._unlock_password.set_sensitive(not busy)
            self._unlock_button.set_sensitive(not busy and self._throttle.remaining() <= 0)
            self._unlock_spinner.set_visible(busy)
            if busy:
                self._unlock_spinner.start()
            else:
                self._unlock_spinner.stop()
            self._unlock_button.set_label("Проверяем…" if busy else "Разблокировать")
            if not busy:
                self._unlock_button.set_sensitive(self._throttle.remaining() <= 0)
            if hasattr(self, "_unlock_import_link"):
                self._unlock_import_link.set_sensitive(not busy)

    def show_creation_error(self, message: str) -> None:
        self.set_busy(False)
        show_error(self._create_error, message)

    def show_unlock_error(self, message: str) -> None:
        """A non-authentication error (I/O, corrupt file)."""

        self.set_busy(False)
        show_error(self._unlock_error, message)

    def handle_wrong_password(self, message: str) -> None:
        self.set_busy(False)
        delay = self._throttle.register_failure()
        self._last_error = message
        if delay:
            self._cooldown_until = time.monotonic() + delay
            self._start_cooldown()
        else:
            show_error(self._unlock_error, message)
            self._unlock_password.set_text("")
            self._unlock_password.grab_focus()

    def handle_unlocked(self) -> None:
        self._throttle.reset()
        if self._mode == "unlock":
            self._unlock_password.set_text("")
            show_error(self._unlock_error, "")
        else:
            self._create_password.set_text("")
            self._create_confirm.set_text("")
            show_error(self._create_error, "")
        self.set_busy(False)

    def _start_cooldown(self) -> None:
        if self._cooldown_source is not None:
            GLib.source_remove(self._cooldown_source)
        self._unlock_button.set_sensitive(False)
        self._render_cooldown(self._throttle.remaining())
        self._cooldown_source = GLib.timeout_add(250, self._cooldown_tick)

    def _cooldown_tick(self) -> bool:
        remaining = self._throttle.remaining()
        if remaining <= 0:
            self._cooldown_source = None
            self._unlock_button.set_sensitive(not self._busy)
            show_error(
                self._unlock_error,
                f"{self._last_error} Можно попробовать снова.".strip(),
            )
            return False
        self._render_cooldown(remaining)
        return True

    def _render_cooldown(self, remaining: float) -> None:
        seconds = max(1, math.ceil(remaining))
        show_error(
            self._unlock_error,
            f"{self._last_error} Повторите через {seconds} с.".strip(),
        )

    def set_message(self, message: str) -> None:
        if self._mode == "unlock" and hasattr(self, "_unlock_message"):
            self._unlock_message.set_text(
                message or "Введите мастер-пароль, чтобы открыть записи."
            )
            if hasattr(self, "_unlock_error"):
                show_error(self._unlock_error, "")
            if hasattr(self, "_unlock_password"):
                self._unlock_password.set_text("")
            self.set_busy(False)

    def focus_password(self) -> None:
        entry = self._create_password if self._mode == "create" else self._unlock_password

        def focus_once() -> bool:
            entry.grab_focus()
            return False  # remove the idle source; returning True would loop

        GLib.idle_add(focus_once)
