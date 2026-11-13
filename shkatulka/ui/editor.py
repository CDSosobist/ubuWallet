"""Create/edit dialog for password and card records."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from ..models import (  # noqa: E402
    CardItem,
    Item,
    PasswordItem,
    ValidationError,
    clean_cardholder,
    clean_entry_password,
    clean_notes,
    clean_tags,
    clean_title,
    clean_url,
    clean_username,
    masked_pan,
    new_card_item,
    new_password_item,
    normalise_pan,
    validate_expiry,
)
from ..security import (  # noqa: E402
    GeneratorOptions,
    generate_password,
    password_strength,
    sanitize_generator_options,
)
from .common import (  # noqa: E402
    PasswordStrengthMeter,
    error_label,
    icon,
    label,
    show_error,
    text_field,
)


class ItemEditor(Adw.Window):
    def __init__(
        self,
        parent: Gtk.Window,
        *,
        existing: Item | None = None,
        initial_kind: str = "password",
        on_save: Callable[[Item], None],
        copy_secret: Callable[[str, str], None],
    ) -> None:
        super().__init__()
        self._parent = parent
        self._existing = existing
        self._on_save = on_save
        self._copy_secret = copy_secret
        self._kind = existing.kind if existing else initial_kind
        self.set_transient_for(parent)
        self.set_modal(True)
        self.set_destroy_with_parent(True)
        self.set_default_size(640, 700)
        self.set_title("Редактировать запись" if existing else "Новая запись")

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        cancel = Gtk.Button(label="Отмена")
        cancel.connect("clicked", lambda *_: self.close())
        header.pack_start(cancel)
        self._save_button = Gtk.Button(label="Сохранить")
        self._save_button.add_css_class("suggested-action")
        self._save_button.connect("clicked", lambda *_: self._save())
        header.pack_end(self._save_button)
        toolbar.add_top_bar(header)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        outer.set_margin_top(10)
        outer.set_margin_bottom(18)
        outer.set_margin_start(12)
        outer.set_margin_end(12)

        self._error = error_label()
        self._error.set_margin_start(12)
        self._error.set_margin_end(12)
        outer.append(self._error)

        clamp = Adw.Clamp()
        clamp.set_maximum_size(700)
        clamp.set_tightening_threshold(600)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_vexpand(True)
        scroller.set_child(clamp)
        outer.append(scroller)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        clamp.set_child(content)

        page = Adw.PreferencesPage()
        page.set_margin_top(4)
        content.append(page)

        # --- common -----------------------------------------------------
        common = Adw.PreferencesGroup(title="Основное")
        page.add(common)

        self._type_row = Adw.ComboRow(title="Тип записи")
        self._type_row.set_model(Gtk.StringList.new(["Пароль", "Банковская карта"]))
        self._type_row.set_selected(0 if self._kind == "password" else 1)
        if existing is not None:
            self._type_row.set_sensitive(False)
        self._type_row.connect("notify::selected", lambda *_: self._type_changed())
        common.add(self._type_row)

        self._title_row = Adw.EntryRow(title="Название")
        self._title_row.set_max_length(120)
        common.add(self._title_row)

        self._tags_row = Adw.EntryRow(title="Теги")
        self._tags_row.set_max_length(340)
        common.add(self._tags_row)
        tags_caption = label(
            "Необязательно. Несколько тегов — через запятую.",
            css="caption dim-label",
        )
        tags_caption.set_margin_start(12)
        common.add(tags_caption)

        self._favorite_row = Adw.SwitchRow(title="Избранное")
        common.add(self._favorite_row)

        # --- password ---------------------------------------------------
        self._password_group = Adw.PreferencesGroup(title="Учётные данные")
        page.add(self._password_group)

        self._username_row = Adw.EntryRow(title="Логин или e-mail")
        self._username_row.set_max_length(320)
        self._username_row.set_input_hints(
            Gtk.InputHints.PRIVATE | Gtk.InputHints.NO_SPELLCHECK
        )
        self._password_group.add(self._username_row)

        self._password_row = Adw.PasswordEntryRow(title="Пароль")
        self._password_row.set_input_hints(
            Gtk.InputHints.PRIVATE
            | Gtk.InputHints.NO_EMOJI
            | Gtk.InputHints.NO_SPELLCHECK
        )
        self._password_row.connect(
            "notify::text", lambda *_: self._strength.update(self._password_row.get_text())
        )
        generate = Gtk.Button.new_from_icon_name("view-refresh-symbolic")
        generate.add_css_class("flat")
        generate.set_tooltip_text("Сгенерировать надёжный пароль")
        generate.connect("clicked", lambda *_: self._open_generator())
        self._password_row.add_suffix(generate)
        self._password_group.add(self._password_row)

        self._strength = PasswordStrengthMeter()
        self._strength.set_margin_start(12)
        self._strength.set_margin_end(12)
        self._strength.set_margin_bottom(6)
        self._password_group.add(self._strength)

        self._url_row = Adw.EntryRow(title="Сайт")
        self._url_row.set_max_length(2048)
        self._url_row.set_input_purpose(Gtk.InputPurpose.URL)
        self._url_row.set_input_hints(Gtk.InputHints.NO_SPELLCHECK)
        self._password_group.add(self._url_row)

        # --- card -------------------------------------------------------
        self._card_group = Adw.PreferencesGroup(title="Данные карты")
        page.add(self._card_group)

        self._cardholder_row = Adw.EntryRow(title="Владелец карты")
        self._cardholder_row.set_max_length(120)
        self._cardholder_row.set_input_hints(
            Gtk.InputHints.PRIVATE | Gtk.InputHints.NO_SPELLCHECK
        )
        self._card_group.add(self._cardholder_row)

        self._original_number = (
            self._existing.number if isinstance(self._existing, CardItem) else ""
        )
        self._number_editing = self._existing is None
        self._number_row = Adw.EntryRow(title="Номер карты")
        self._number_row.set_max_length(25)
        self._number_row.set_input_purpose(Gtk.InputPurpose.DIGITS)
        self._number_row.set_input_hints(
            Gtk.InputHints.PRIVATE
            | Gtk.InputHints.NO_EMOJI
            | Gtk.InputHints.NO_SPELLCHECK
        )
        self._number_edit_button = Gtk.Button.new_from_icon_name(
            "document-edit-symbolic"
        )
        self._number_edit_button.set_valign(Gtk.Align.CENTER)
        self._number_edit_button.add_css_class("flat")
        self._number_edit_button.set_tooltip_text("Изменить номер карты")
        self._number_edit_button.set_visible(self._existing is not None)
        self._number_edit_button.connect(
            "clicked", lambda *_: self._begin_number_edit()
        )
        self._number_row.add_suffix(self._number_edit_button)
        self._card_group.add(self._number_row)
        self._card_group.add(
            label(
                "При открытии видны только последние 4 цифры. "
                "Нажмите «Изменить», чтобы ввести новый номер.",
                css="caption dim-label",
                wrap=True,
            )
        )

        now = datetime.now(timezone.utc)
        self._month_row = Adw.SpinRow.new_with_range(1, 12, 1)
        self._month_row.set_title("Месяц окончания")
        self._month_row.set_value(12)
        self._card_group.add(self._month_row)

        self._year_row = Adw.SpinRow.new_with_range(2000, 2100, 1)
        self._year_row.set_title("Год окончания")
        self._year_row.set_value(now.year + 3)
        self._card_group.add(self._year_row)

        card_note = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        card_note.set_margin_start(12)
        card_note.set_margin_end(12)
        card_note.set_margin_top(4)
        card_note.append(icon("dialog-information-symbolic", 16))
        card_note.append(
            label(
                "CVV/CVC и PIN не запрашиваются и не хранятся: PCI DSS 4.0 "
                "запрещает сохранять данные аутентификации после авторизации.",
                css="caption dim-label",
                wrap=True,
            )
        )
        self._card_group.add(card_note)

        # --- notes ------------------------------------------------------
        notes_group = Adw.PreferencesGroup(title="Заметки")
        page.add(notes_group)
        notes_frame = Gtk.Frame()
        notes_frame.add_css_class("card")
        notes_scroller = Gtk.ScrolledWindow()
        notes_scroller.set_min_content_height(110)
        notes_scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self._notes_view = Gtk.TextView()
        self._notes_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self._notes_view.set_left_margin(10)
        self._notes_view.set_right_margin(10)
        self._notes_view.set_top_margin(8)
        self._notes_view.set_bottom_margin(8)
        notes_scroller.set_child(self._notes_view)
        notes_frame.set_child(notes_scroller)
        notes_group.add(notes_frame)

        toolbar.set_content(outer)
        self.set_content(toolbar)

        self._populate()
        self._type_changed()
        self._update_title()
        self.connect("close-request", self._on_close_request)

    # --------------------------------------------------------------- data
    def _populate(self) -> None:
        item = self._existing
        if item is None:
            return
        self._title_row.set_text(item.title)
        self._tags_row.set_text(", ".join(item.tags))
        self._favorite_row.set_active(item.favorite)
        buffer = self._notes_view.get_buffer()
        buffer.set_text(item.notes)
        if isinstance(item, PasswordItem):
            self._username_row.set_text(item.username)
            self._password_row.set_text(item.password)
            self._url_row.set_text(item.url)
            self._strength.update(item.password)
        elif isinstance(item, CardItem):
            self._cardholder_row.set_text(item.cardholder)
            # Never prefill the full PAN into the editable field: show only
            # the last four digits and require an explicit replacement.
            self._number_row.set_text(masked_pan(item.number))
            self._number_row.set_editable(False)
            self._number_edit_button.set_visible(True)
            self._month_row.set_value(item.expiry_month)
            self._year_row.set_value(item.expiry_year)

    def _notes(self) -> str:
        buffer = self._notes_view.get_buffer()
        return buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True)

    def _type_changed(self) -> None:
        selected = self._type_row.get_selected()
        self._kind = "card" if selected == 1 else "password"
        self._password_group.set_visible(self._kind == "password")
        self._card_group.set_visible(self._kind == "card")
        self._update_title()

    def _update_title(self) -> None:
        if self._existing:
            self.set_title("Редактировать карту" if self._kind == "card" else "Редактировать пароль")
        else:
            self.set_title("Новая карта" if self._kind == "card" else "Новый пароль")

    # -------------------------------------------------------------- save
    def _save(self) -> None:
        try:
            item = self._build_item()
        except ValidationError as exc:
            show_error(self._error, str(exc))
            return
        except ValueError as exc:
            show_error(self._error, str(exc) or "Проверьте введённые данные.")
            return
        try:
            self._on_save(item)
        except Exception as exc:  # storage error: keep dialog open
            show_error(self._error, str(exc) or "Не удалось сохранить запись.")
            return
        self.close()

    def _build_item(self) -> Item:
        title = clean_title(self._title_row.get_text())
        notes = clean_notes(self._notes())
        tags = clean_tags(self._tags_row.get_text())
        favorite = self._favorite_row.get_active()

        if self._kind == "password":
            item: Item = new_password_item(
                title=title,
                username=clean_username(self._username_row.get_text()),
                password=clean_entry_password(self._password_row.get_text()),
                url=clean_url(self._url_row.get_text()),
                notes=notes,
                tags=tags,
                favorite=favorite,
            )
        else:
            month, year = validate_expiry(
                int(self._month_row.get_value()), int(self._year_row.get_value())
            )
            if self._existing is not None and not self._number_editing:
                number = self._original_number
            else:
                number = normalise_pan(self._number_row.get_text())
            item = new_card_item(
                title=title,
                cardholder=clean_cardholder(self._cardholder_row.get_text()),
                number=number,
                expiry_month=month,
                expiry_year=year,
                notes=notes,
                tags=tags,
                favorite=favorite,
            )
        if self._existing is not None:
            item.id = self._existing.id
        return item

    def _begin_number_edit(self) -> None:
        self._number_editing = True
        self._number_row.set_editable(True)
        self._number_row.set_text("")
        self._number_row.set_title("Новый номер карты")
        self._number_edit_button.set_visible(False)
        self._number_row.grab_focus()

    def _on_close_request(self, *_args) -> bool:
        self._title_row.set_text("")
        self._username_row.set_text("")
        self._password_row.set_text("")
        self._url_row.set_text("")
        self._cardholder_row.set_text("")
        self._number_row.set_text("")
        self._notes_view.get_buffer().set_text("")
        return False

    # ----------------------------------------------------------- generator
    def _open_generator(self) -> None:
        dialog = PasswordGeneratorDialog(
            self,
            on_use=self._use_generated_password,
            copy_secret=self._copy_secret,
        )
        tracker = getattr(self._parent, "track_window", None)
        if tracker is not None:
            tracker(dialog)
        dialog.present()

    def _use_generated_password(self, value: str) -> None:
        self._password_row.set_text(value)
        self._strength.update(value)


class PasswordGeneratorDialog(Adw.Window):
    def __init__(
        self,
        parent: Gtk.Window,
        *,
        on_use: Callable[[str], None],
        copy_secret: Callable[[str, str], None],
    ) -> None:
        super().__init__()
        self._on_use = on_use
        self._copy_secret = copy_secret
        self.set_transient_for(parent)
        self.set_modal(True)
        self.set_destroy_with_parent(True)
        self.set_default_size(520, 620)
        self.set_title("Генератор пароля")

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        close = Gtk.Button(label="Закрыть")
        close.connect("clicked", lambda *_: self.close())
        header.pack_start(close)
        toolbar.add_top_bar(header)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        outer.set_margin_top(12)
        outer.set_margin_bottom(18)
        outer.set_margin_start(18)
        outer.set_margin_end(18)

        self._preview = Gtk.Entry()
        self._preview.set_editable(False)
        self._preview.set_can_focus(True)
        self._preview.add_css_class("mono")
        self._preview.set_hexpand(True)
        outer.append(text_field("Сгенерированный пароль", self._preview))

        self._bits = label("", css="caption dim-label", wrap=True)
        outer.append(self._bits)

        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(title="Параметры")
        page.add(group)
        outer.append(page)

        self._length = Adw.SpinRow.new_with_range(8, 128, 1)
        self._length.set_title("Длина")
        self._length.set_value(24)
        self._length.connect("notify::value", lambda *_: self._regenerate())
        group.add(self._length)

        self._lower = Adw.SwitchRow(title="Строчные буквы")
        self._lower.set_active(True)
        self._lower.connect("notify::active", lambda *_: self._regenerate())
        group.add(self._lower)

        self._upper = Adw.SwitchRow(title="Прописные буквы")
        self._upper.set_active(True)
        self._upper.connect("notify::active", lambda *_: self._regenerate())
        group.add(self._upper)

        self._digits = Adw.SwitchRow(title="Цифры")
        self._digits.set_active(True)
        self._digits.connect("notify::active", lambda *_: self._regenerate())
        group.add(self._digits)

        self._symbols = Adw.SwitchRow(title="Специальные символы")
        self._symbols.set_active(True)
        self._symbols.connect("notify::active", lambda *_: self._regenerate())
        group.add(self._symbols)

        self._ambiguous = Adw.SwitchRow(title="Исключать похожие символы")
        self._ambiguous.set_subtitle("0/O, 1/l/I и подобные")
        self._ambiguous.set_active(True)
        self._ambiguous.connect("notify::active", lambda *_: self._regenerate())
        group.add(self._ambiguous)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        buttons.set_halign(Gtk.Align.END)
        buttons.set_margin_top(6)
        regenerate = Gtk.Button(label="Ещё вариант")
        regenerate.connect("clicked", lambda *_: self._regenerate())
        buttons.append(regenerate)
        copy = Gtk.Button(label="Скопировать")
        copy.connect(
            "clicked",
            lambda *_: self._copy_secret(self._preview.get_text(), "Пароль"),
        )
        buttons.append(copy)
        use = Gtk.Button(label="Использовать")
        use.add_css_class("suggested-action")
        use.connect("clicked", lambda *_: self._use())
        buttons.append(use)
        outer.append(buttons)

        toolbar.set_content(outer)
        self.set_content(toolbar)
        self.connect("close-request", self._clear)
        self._regenerate()

    def _options(self) -> GeneratorOptions:
        return sanitize_generator_options(
            int(self._length.get_value()),
            self._lower.get_active(),
            self._upper.get_active(),
            self._digits.get_active(),
            self._symbols.get_active(),
            self._ambiguous.get_active(),
        )

    def _regenerate(self) -> None:
        options = self._options()
        try:
            value = generate_password(options)
        except ValueError:
            return
        self._preview.set_text(value)
        bits = password_strength(value).bits
        self._bits.set_text(
            f"Оценка энтропии: ≈ {bits:.0f} бит. Пароль создан системным "
            "криптографическим генератором (secrets)."
        )

    def _use(self) -> None:
        value = self._preview.get_text()
        if value:
            self._on_use(value)
        self.close()

    def _clear(self, *_args) -> bool:
        self._preview.set_text("")
        return False
