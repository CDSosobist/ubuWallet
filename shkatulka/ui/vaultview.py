"""Unlocked vault: sidebar, search and record details."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk, Pango  # noqa: E402

from ..models import CardItem, Item, PasswordItem, format_pan  # noqa: E402
from ..vault import VaultSession, format_item_count  # noqa: E402
from .common import (  # noqa: E402
    action_icon_button,
    copy_icon_button,
    icon,
    label,
    make_card_box,
    menu_button,
    normalize_url,
    open_uri,
)
from .editor import ItemEditor  # noqa: E402

if TYPE_CHECKING:
    from .window import MainWindow


class VaultView(Gtk.Box):
    def __init__(self, window: "MainWindow", session: VaultSession) -> None:
        super().__init__()
        self._window = window
        self._session = session
        self._selected_id: str | None = None
        self._rows: dict[str, Adw.ActionRow] = {}
        self._refreshing = False
        self._reveal_timeout: int | None = None
        self._revealed_row: Adw.ActionRow | None = None
        self._revealed_masked: str = ""
        self._revealed_button: Gtk.Button | None = None
        self._revealed_show_tooltip: str = ""
        self._updating_favorite = False
        self.set_hexpand(True)
        self.set_vexpand(True)

        self._split = Adw.NavigationSplitView()
        self._split.set_hexpand(True)
        self._split.set_vexpand(True)
        self._split.set_min_sidebar_width(290)
        self._split.set_max_sidebar_width(370)
        self._split.set_sidebar_width_fraction(0.32)
        self._split.connect("notify::collapsed", lambda *_: self._update_window_controls())
        self.append(self._split)

        self._build_sidebar()
        self._build_content()
        self.refresh()

    # ------------------------------------------------------------- sidebar
    def _build_sidebar(self) -> None:
        page = Adw.NavigationPage(title="Шкатулка")
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_title_widget(label("Шкатулка", css="heading"))

        add_button = Gtk.Button.new_from_icon_name("list-add-symbolic")
        add_button.set_tooltip_text("Новая запись")
        add_button.add_css_class("flat")
        add_button.connect("clicked", lambda *_: self.new_item("password"))
        header.pack_start(add_button)

        menu = menu_button()
        menu.set_menu_model(self._build_menu())
        header.pack_end(menu)
        self._sidebar_controls = Gtk.WindowControls.new(Gtk.PackType.END)
        self._sidebar_controls.set_visible(False)
        header.pack_end(self._sidebar_controls)
        self._sidebar_header = header
        toolbar.add_top_bar(header)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._search = Gtk.SearchEntry()
        self._search.set_placeholder_text("Поиск по сейфу")
        self._search.add_css_class("search-entry")
        self._search.connect("search-changed", lambda *_: self.refresh())
        self._search.connect("stop-search", lambda *_: self._search.set_text(""))
        body.append(self._search)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_vexpand(True)
        self._listbox = Gtk.ListBox()
        self._listbox.add_css_class("navigation-sidebar")
        self._listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._listbox.set_activate_on_single_click(True)
        self._listbox.connect("row-selected", self._on_row_selected)
        scroller.set_child(self._listbox)
        body.append(scroller)

        self._count_label = label("", css="sidebar-footer dim-label")
        body.append(self._count_label)

        toolbar.set_content(body)
        page.set_child(toolbar)
        self._split.set_sidebar(page)

    def _build_menu(self) -> Gio.Menu:
        menu = Gio.Menu()
        menu.append("Новый пароль", "win.new-password")
        menu.append("Новая карта", "win.new-card")
        menu.append("Настройки", "win.settings")
        menu.append("Заблокировать", "win.lock")
        menu.append("О программе", "app.about")
        return menu

    def _build_content(self) -> None:
        page = Adw.NavigationPage(title="Запись")
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        self._back_button = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        self._back_button.set_tooltip_text("Назад к списку")
        self._back_button.add_css_class("flat")
        self._back_button.connect("clicked", lambda *_: self._split.set_show_content(False))
        header.pack_start(self._back_button)

        self._detail_title = label("Запись", css="heading")
        self._detail_title.set_ellipsize(Pango.EllipsizeMode.END)
        self._detail_title.set_max_width_chars(36)
        header.set_title_widget(self._detail_title)

        self._favorite_button = Gtk.ToggleButton()
        self._favorite_button.set_icon_name("emblem-favorite-symbolic")
        self._favorite_button.set_tooltip_text("В избранное")
        self._favorite_button.add_css_class("flat")
        self._favorite_button.add_css_class("favorite-button")
        self._favorite_button.connect("toggled", lambda *_: self._on_favorite_toggled())
        header.pack_end(self._favorite_button)

        self._delete_button = action_icon_button("user-trash-symbolic", "Удалить запись")
        self._delete_button.connect("clicked", lambda *_: self._delete_current())
        header.pack_end(self._delete_button)

        self._edit_button = action_icon_button("document-edit-symbolic", "Редактировать")
        self._edit_button.connect("clicked", lambda *_: self.edit_current())
        header.pack_end(self._edit_button)
        toolbar.add_top_bar(header)

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self._stack.set_transition_duration(120)
        toolbar.set_content(self._stack)

        self._empty_page = Adw.StatusPage()
        self._empty_page.set_icon_name("channel-secure-symbolic")
        self._empty_page.set_title("Сейф пуст")
        self._empty_page.set_description(
            "Добавьте первый пароль или данные карты. Всё будет зашифровано."
        )
        empty_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        empty_actions.set_halign(Gtk.Align.CENTER)
        add_password = Gtk.Button(label="Добавить пароль")
        add_password.add_css_class("suggested-action")
        add_password.add_css_class("pill-button")
        add_password.connect("clicked", lambda *_: self.new_item("password"))
        add_card = Gtk.Button(label="Добавить карту")
        add_card.add_css_class("pill-button")
        add_card.connect("clicked", lambda *_: self.new_item("card"))
        empty_actions.append(add_password)
        empty_actions.append(add_card)
        self._empty_actions = empty_actions
        self._empty_page.set_child(empty_actions)
        self._stack.add_named(self._empty_page, "empty")

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self._detail_scroller = scroller
        clamp = Adw.Clamp()
        clamp.set_maximum_size(760)
        clamp.set_tightening_threshold(640)
        scroller.set_child(clamp)
        self._detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self._detail_box.set_margin_top(18)
        self._detail_box.set_margin_bottom(36)
        self._detail_box.set_margin_start(18)
        self._detail_box.set_margin_end(18)
        clamp.set_child(self._detail_box)
        self._stack.add_named(scroller, "detail")

        self._stack.set_visible_child_name("empty")
        page.set_child(toolbar)
        self._split.set_content(page)
        self._update_window_controls()
        self._set_header_actions(False)

    def _update_window_controls(self) -> None:
        collapsed = self._split.get_collapsed()
        self._back_button.set_visible(collapsed)
        self._sidebar_controls.set_visible(collapsed)

    def _set_header_actions(self, enabled: bool) -> None:
        self._favorite_button.set_sensitive(enabled)
        self._edit_button.set_sensitive(enabled)
        self._delete_button.set_sensitive(enabled)

    # -------------------------------------------------------------- list
    def _on_row_selected(self, _listbox: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if self._refreshing:
            return
        if row is None:
            return
        item_id = getattr(row, "item_id", None)
        if not item_id:
            return
        self._selected_id = item_id
        self._show_item(item_id)
        if self._split.get_collapsed():
            self._split.set_show_content(True)

    def refresh(self) -> None:
        self._cancel_reveal()
        selected = self._selected_id
        query = self._search.get_text() if hasattr(self, "_search") else ""
        items = self._session.vault.sorted_items(query)

        self._refreshing = True
        try:
            child = self._listbox.get_first_child()
            while child is not None:
                next_child = child.get_next_sibling()
                self._listbox.remove(child)
                child = next_child
            self._rows.clear()

            for item in items:
                row = self._make_row(item)
                self._rows[item.id] = row
                self._listbox.append(row)

            total = len(self._session.vault.items)
            self._count_label.set_text(format_item_count(total))

            if not items:
                self._selected_id = None
                self._set_header_actions(False)
                self._detail_title.set_text("Запись")
                self._show_empty_state(query=query, total=total)
                self._count_label.set_text(format_item_count(total))
                return

            target = selected if selected in self._rows else items[0].id
            row = self._rows[target]
            self._listbox.select_row(row)
            self._selected_id = target
        finally:
            self._refreshing = False

        self._show_item(self._selected_id)

    def _make_row(self, item: Item) -> Adw.ActionRow:
        row = Adw.ActionRow()
        row.item_id = item.id  # type: ignore[attr-defined]
        row.set_use_markup(False)
        row.set_title(item.title)
        row.set_subtitle(item.subtitle)
        row.set_subtitle_lines(1)
        row.set_activatable(True)
        icon_name = "credit-card-symbolic" if item.kind == "card" else "dialog-password-symbolic"
        # Adwaita has no credit-card-symbolic; use the smartcard glyph as a
        # dependency-free fallback that still reads as a card.
        if item.kind == "card":
            icon_name = "auth-smartcard-symbolic"
        image = Gtk.Image.new_from_icon_name(icon_name)
        image.set_pixel_size(18)
        image.add_css_class("item-icon")
        row.add_prefix(image)
        if item.favorite:
            star = Gtk.Image.new_from_icon_name("emblem-favorite-symbolic")
            star.set_pixel_size(14)
            star.set_tooltip_text("В избранном")
            star.add_css_class("accent")
            row.add_suffix(star)
        row.set_tooltip_text(item.title)
        return row

    def _show_empty_state(self, *, query: str, total: int) -> None:
        if total == 0:
            self._empty_page.set_title("Сейф пуст")
            self._empty_page.set_description(
                "Добавьте первый пароль или данные карты. Всё будет зашифровано."
            )
            self._empty_page.set_child(self._empty_actions)
        elif query:
            self._empty_page.set_title("Ничего не найдено")
            self._empty_page.set_description("Попробуйте изменить поисковый запрос.")
            reset = Gtk.Button(label="Сбросить поиск")
            reset.add_css_class("pill-button")
            reset.set_halign(Gtk.Align.CENTER)
            reset.connect("clicked", lambda *_: self._search.set_text(""))
            self._empty_page.set_child(reset)
        else:
            self._empty_page.set_title("Выберите запись")
            self._empty_page.set_description("Записи сейфа появятся в этом окне.")
            self._empty_page.set_child(None)
        self._stack.set_visible_child_name("empty")

    # ------------------------------------------------------------ details
    def _show_item(self, item_id: str | None) -> None:
        if item_id is None:
            self._stack.set_visible_child_name("empty")
            self._set_header_actions(False)
            return
        item = self._session.vault.get(item_id)
        if item is None:
            self._stack.set_visible_child_name("empty")
            self._set_header_actions(False)
            return

        self._cancel_reveal()
        self._detail_title.set_text(item.title)
        self._updating_favorite = True
        self._favorite_button.set_active(item.favorite)
        self._updating_favorite = False
        self._set_header_actions(True)
        self._build_detail(item)
        self._stack.set_visible_child_name("detail")
        self._detail_scroller.get_vadjustment().set_value(0)

    def _build_detail(self, item: Item) -> None:
        child = self._detail_box.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self._detail_box.remove(child)
            child = next_child

        hero = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        hero.set_margin_start(6)
        hero.set_margin_end(6)
        hero_image = Gtk.Image.new_from_icon_name(
            "auth-smartcard-symbolic" if isinstance(item, CardItem) else "dialog-password-symbolic"
        )
        hero_image.set_pixel_size(34)
        hero_image.add_css_class("item-icon")
        hero.append(hero_image)
        hero_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        hero_text.set_valign(Gtk.Align.CENTER)
        hero_text.append(label(item.title, css="detail-title", wrap=True, selectable=True))
        subtitle = item.subtitle
        if isinstance(item, CardItem) and item.is_expired:
            subtitle += " · срок истёк"
        hero_text.append(label(subtitle, css="dim-label", wrap=True))
        hero.append(hero_text)
        self._detail_box.append(hero)

        if item.tags:
            tags = Gtk.FlowBox()
            tags.set_selection_mode(Gtk.SelectionMode.NONE)
            tags.set_column_spacing(6)
            tags.set_row_spacing(6)
            tags.set_max_children_per_line(8)
            tags.set_margin_start(6)
            tags.set_margin_end(6)
            for tag in item.tags:
                tags.append(label(tag, css="tag-pill"))
            self._detail_box.append(tags)

        if isinstance(item, PasswordItem):
            self._build_password_detail(item)
        elif isinstance(item, CardItem):
            self._build_card_detail(item)

        if item.notes:
            notes_section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            notes_section.set_margin_top(4)
            notes_section.append(label("Заметки", css="heading"))
            notes_card = make_card_box()
            notes_card.append(label(item.notes, wrap=True, selectable=True))
            notes_section.append(notes_card)
            self._detail_box.append(notes_section)

        meta = Adw.PreferencesGroup(title="Служебное")
        meta.set_margin_top(4)
        created = self._format_date(item.created_at)
        changed = self._format_date(item.updated_at)
        meta.add(self._value_row("Создано", created))
        meta.add(self._value_row("Изменено", changed))
        meta.add(self._value_row("Тип", "Банковская карта" if item.kind == "card" else "Пароль"))
        self._detail_box.append(meta)

        if isinstance(item, CardItem):
            note = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            note.set_margin_start(10)
            note.set_margin_end(10)
            note.append(icon("dialog-information-symbolic", 16))
            note.append(
                label(
                    "CVV/CVC и PIN не хранятся. Для оплаты вводите их каждый раз заново.",
                    css="caption dim-label",
                    wrap=True,
                )
            )
            self._detail_box.append(note)

    def _build_password_detail(self, item: PasswordItem) -> None:
        group = Adw.PreferencesGroup(title="Учётные данные")
        added = False
        if item.username:
            group.add(
                self._value_row(
                    "Логин",
                    item.username,
                    copy_value=item.username,
                    copy_label="Логин",
                    selectable=True,
                )
            )
            added = True
        if item.password:
            masked = "••••••••••••"
            row = self._value_row("Пароль", masked, selectable=True)
            reveal = action_icon_button("view-reveal-symbolic", "Показать пароль")
            # Bind the row at creation time: a bare closure would capture the
            # ``row`` variable, which is reassigned below for the website row.
            reveal.connect(
                "clicked",
                lambda *_args, r=row, m=masked, secret=item.password, b=reveal: self._toggle_reveal(
                    r, m, secret, b, "Показать пароль", "Скрыть пароль"
                ),
            )
            row.add_suffix(reveal)
            row.add_suffix(self._copy_button(item.password, "Пароль"))
            group.add(row)
            added = True
        if item.url:
            row = self._value_row("Сайт", item.url, selectable=True)
            target = normalize_url(item.url)
            if target.startswith(("http://", "https://")):
                open_button = action_icon_button("go-next-symbolic", "Открыть сайт")
                open_button.connect("clicked", lambda *_: open_uri(item.url))
                row.add_suffix(open_button)
            row.add_suffix(self._copy_button(item.url, "Адрес сайта"))
            group.add(row)
            added = True
        if added:
            self._detail_box.append(group)

    def _build_card_detail(self, item: CardItem) -> None:
        group = Adw.PreferencesGroup(title="Данные карты")
        masked = f"•••• {item.number[-4:]}"
        row = self._value_row("Номер карты", masked, selectable=True)
        reveal = action_icon_button("view-reveal-symbolic", "Показать номер")
        reveal.connect(
            "clicked",
            lambda *_args, r=row, m=masked, secret=format_pan(item.number), b=reveal: self._toggle_reveal(
                r, m, secret, b, "Показать номер", "Скрыть номер"
            ),
        )
        row.add_suffix(reveal)
        row.add_suffix(self._copy_button(item.number, "Номер карты"))
        group.add(row)

        if item.cardholder:
            group.add(
                self._value_row(
                    "Владелец",
                    item.cardholder,
                    copy_value=item.cardholder,
                    copy_label="Имя владельца",
                    selectable=True,
                )
            )
        expiry = f"{item.expiry_month:02d}/{item.expiry_year % 100:02d}"
        expiry_row = self._value_row("Срок действия", expiry)
        if item.is_expired:
            expiry_row.add_suffix(label("истёк", css="error-label"))
        group.add(expiry_row)
        group.add(self._value_row("Платёжная система", item.brand))
        self._detail_box.append(group)

    def _value_row(
        self,
        title: str,
        value: str,
        *,
        copy_value: str | None = None,
        copy_label: str = "",
        selectable: bool = False,
    ) -> Adw.ActionRow:
        row = Adw.ActionRow(title=title)
        row.set_use_markup(False)
        row.set_subtitle(value or "—")
        row.set_subtitle_selectable(selectable)
        row.set_subtitle_lines(3)
        if copy_value:
            row.add_suffix(self._copy_button(copy_value, copy_label or title))
        return row

    def _copy_button(self, value: str, label_text: str) -> Gtk.Button:
        button = copy_icon_button(f"Скопировать: {label_text}")
        button.connect(
            "clicked",
            lambda *_: self._window.copy_secret(value, label_text),
        )
        return button

    def _toggle_reveal(
        self,
        row: Adw.ActionRow,
        masked: str,
        secret: str,
        button: Gtk.Button,
        show_tooltip: str,
        hide_tooltip: str,
    ) -> None:
        if self._revealed_row is row:
            self._cancel_reveal()
            return
        self._cancel_reveal()
        row.set_subtitle(secret)
        self._revealed_row = row
        self._revealed_masked = masked
        self._revealed_button = button
        self._revealed_show_tooltip = show_tooltip
        button.set_icon_name("view-conceal-symbolic")
        button.set_tooltip_text(hide_tooltip)
        self._reveal_timeout = GLib.timeout_add_seconds(30, self._hide_reveal)

    def _restore_reveal(self) -> None:
        row = self._revealed_row
        button = self._revealed_button
        if row is not None:
            try:
                if row.get_root() is not None:
                    row.set_subtitle(self._revealed_masked)
            except Exception:
                pass
        if button is not None:
            try:
                if button.get_root() is not None:
                    button.set_icon_name("view-reveal-symbolic")
                    button.set_tooltip_text(self._revealed_show_tooltip)
            except Exception:
                pass
        self._revealed_row = None
        self._revealed_masked = ""
        self._revealed_button = None
        self._revealed_show_tooltip = ""

    def _hide_reveal(self) -> bool:
        self._reveal_timeout = None
        self._restore_reveal()
        return False

    def _cancel_reveal(self) -> None:
        if self._reveal_timeout is not None:
            GLib.source_remove(self._reveal_timeout)
            self._reveal_timeout = None
        self._restore_reveal()

    @staticmethod
    def _format_date(value: str) -> str:
        try:
            return datetime.fromisoformat(value).astimezone().strftime("%d.%m.%Y, %H:%M")
        except ValueError:
            return "—"

    # ------------------------------------------------------------- actions
    def new_item(self, kind: str) -> None:
        if self._session.is_locked:
            return
        editor = ItemEditor(
            self._window,
            initial_kind=kind,
            on_save=self._save_item,
            copy_secret=self._window.copy_secret,
        )
        self._window.track_window(editor)
        editor.present()

    def edit_current(self) -> None:
        if self._session.is_locked or self._selected_id is None:
            return
        item = self._session.vault.get(self._selected_id)
        if item is None:
            return
        editor = ItemEditor(
            self._window,
            existing=item,
            on_save=self._save_item,
            copy_secret=self._window.copy_secret,
        )
        self._window.track_window(editor)
        editor.present()

    def _save_item(self, item: Item) -> None:
        if self._session.is_locked:
            raise RuntimeError("Сейф заблокирован.")
        vault = self._session.vault
        previous = vault.get(item.id)
        added = previous is None
        try:
            if added:
                vault.add(item)
            else:
                vault.replace(item)
            self._session.save()
        except Exception:
            # Keep the in-memory state consistent with the file if the write
            # failed (disk full, revoked permission, I/O error).
            if added:
                vault.items.pop(item.id, None)
            else:
                vault.items[item.id] = previous
            raise
        self._selected_id = item.id
        self.refresh()
        self._window.note_activity()
        self._window.show_toast("Запись сохранена")

    def _on_favorite_toggled(self) -> None:
        if self._updating_favorite or self._session.is_locked or self._selected_id is None:
            return
        item = self._session.vault.get(self._selected_id)
        if item is None:
            return
        old_favorite = item.favorite
        item.favorite = self._favorite_button.get_active()
        try:
            self._session.vault.replace(item)
            self._session.save()
        except Exception as exc:
            item.favorite = old_favorite
            self._updating_favorite = True
            self._favorite_button.set_active(old_favorite)
            self._updating_favorite = False
            self._window.show_error("Не удалось сохранить", str(exc))
            return
        self.refresh()
        self._window.note_activity()

    def _delete_current(self) -> None:
        if self._session.is_locked or self._selected_id is None:
            return
        item = self._session.vault.get(self._selected_id)
        if item is None:
            return
        item_id = item.id
        dialog = Adw.AlertDialog.new(
            "Удалить запись?",
            "Запись будет удалена из сейфа без возможности отмены.",
        )
        dialog.add_response("cancel", "Отмена")
        dialog.add_response("delete", "Удалить")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.set_body_use_markup(False)

        def on_response(_dialog: Adw.AlertDialog, response: str) -> None:
            if response != "delete" or self._session.is_locked:
                return
            try:
                self._session.vault.delete(item_id)
                self._session.save()
            except Exception as exc:
                # The delete mutated memory before the failed write; restore it.
                self._session.vault.items[item_id] = item
                self._window.show_error("Не удалось удалить запись", str(exc))
                return
            self._selected_id = None
            self.refresh()
            self._window.note_activity()
            self._window.show_toast("Запись удалена")

        dialog.connect("response", on_response)
        self._window.track_dialog(dialog)
        dialog.present(self._window)

    def focus_search(self) -> None:
        self._search.grab_focus()

    def shutdown(self) -> None:
        self._cancel_reveal()
        self._detail_box = None  # type: ignore[assignment]
