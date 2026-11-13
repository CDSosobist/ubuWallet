"""Data model and validation for vault entries.

Only two kinds of records exist:

``password``
    Login, password, optional site and notes.
``card``
    Cardholder, PAN, expiry, optional notes.  CVV/CVC and PIN are deliberately
    *not* modelled: PCI DSS 4.0 forbids retaining sensitive authentication
    data after authorisation, and a local wallet has no business storing it.

PANs are validated with the Luhn checksum, normalised to digits and shown
masked by default.  The full number is only ever in the encrypted payload and
in the UI after an explicit reveal.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ClassVar

MAX_TITLE = 120
MAX_NOTES = 20_000
MAX_USERNAME = 320
MAX_PASSWORD = 4_096
MAX_URL = 2_048
MAX_TAGS = 10
MAX_TAG_LEN = 32
MAX_CARDHOLDER = 120
MIN_PAN_DIGITS = 12
MAX_PAN_DIGITS = 19

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_TITLE_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_BIDI_CONTROL_RE = re.compile(r"[\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_WHITESPACE_RE = re.compile(r"\s")


class ValidationError(ValueError):
    """User-facing validation failure."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _require_str(value: Any, field_name: str, max_len: int, *, allow_empty: bool) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"Поле «{field_name}» имеет неверный тип.")
    if len(value) > max_len:
        raise ValidationError(f"Поле «{field_name}» слишком длинное.")
    if not allow_empty and not value.strip():
        raise ValidationError(f"Поле «{field_name}» не может быть пустым.")
    return value


def clean_title(value: Any) -> str:
    value = _require_str(value, "Название", MAX_TITLE, allow_empty=False).strip()
    if _TITLE_CONTROL_RE.search(value) or _BIDI_CONTROL_RE.search(value):
        raise ValidationError("Название содержит недопустимые символы.")
    return value


def clean_notes(value: Any) -> str:
    value = _require_str(value or "", "Заметки", MAX_NOTES, allow_empty=True).strip()
    if _CONTROL_RE.search(value):
        raise ValidationError("Заметки содержат недопустимые символы.")
    return value


def clean_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.split(",")
    elif isinstance(value, list):
        raw = value
    else:
        raise ValidationError("Теги имеют неверный формат.")
    result: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise ValidationError("Теги имеют неверный формат.")
        tag = item.strip()
        if not tag:
            continue
        if len(tag) > MAX_TAG_LEN:
            raise ValidationError(f"Тег длиннее {MAX_TAG_LEN} символов.")
        if _TITLE_CONTROL_RE.search(tag) or _BIDI_CONTROL_RE.search(tag):
            raise ValidationError("Тег содержит недопустимые символы.")
        key = tag.casefold()
        if key not in seen:
            seen.add(key)
            result.append(tag)
    if len(result) > MAX_TAGS:
        raise ValidationError(f"Можно добавить не более {MAX_TAGS} тегов.")
    return result


def clean_username(value: Any) -> str:
    value = _require_str(value or "", "Логин", MAX_USERNAME, allow_empty=True).strip()
    if _CONTROL_RE.search(value) or _BIDI_CONTROL_RE.search(value):
        raise ValidationError("Логин содержит недопустимые символы.")
    return value


def clean_entry_password(value: Any) -> str:
    value = _require_str(value or "", "Пароль", MAX_PASSWORD, allow_empty=True)
    if "\x00" in value:
        raise ValidationError("Пароль содержит недопустимый символ NUL.")
    return value


def clean_url(value: Any) -> str:
    value = _require_str(value or "", "Сайт", MAX_URL, allow_empty=True).strip()
    if _CONTROL_RE.search(value) or _BIDI_CONTROL_RE.search(value):
        raise ValidationError("Адрес сайта содержит недопустимые символы.")
    return value


def clean_cardholder(value: Any) -> str:
    value = _require_str(value or "", "Владелец карты", MAX_CARDHOLDER, allow_empty=True).strip()
    if _CONTROL_RE.search(value) or _BIDI_CONTROL_RE.search(value):
        raise ValidationError("Имя владельца содержит недопустимые символы.")
    return value


def normalise_pan(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError("Номер карты имеет неверный формат.")
    digits = re.sub(r"[\s\-]", "", value)
    if not digits.isdigit():
        raise ValidationError("Номер карты должен содержать только цифры.")
    if not MIN_PAN_DIGITS <= len(digits) <= MAX_PAN_DIGITS:
        raise ValidationError(
            f"Номер карты должен содержать от {MIN_PAN_DIGITS} до {MAX_PAN_DIGITS} цифр."
        )
    if not luhn_valid(digits):
        raise ValidationError("Номер карты не проходит проверку контрольной суммы.")
    return digits


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit():
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        number = int(char)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def validate_expiry(month: Any, year: Any) -> tuple[int, int]:
    if isinstance(month, bool) or not isinstance(month, int):
        raise ValidationError("Месяц окончания указан неверно.")
    if isinstance(year, bool) or not isinstance(year, int):
        raise ValidationError("Год окончания указан неверно.")
    if not 1 <= month <= 12:
        raise ValidationError("Месяц окончания должен быть от 1 до 12.")
    if not 2000 <= year <= 2100:
        raise ValidationError("Год окончания указан неверно.")
    return month, year


def format_pan(number: str) -> str:
    if not number:
        return ""
    if is_amex(number) and len(number) == 15:
        return f"{number[:4]} {number[4:10]} {number[10:]}"
    return " ".join(number[i : i + 4] for i in range(0, len(number), 4))


def masked_pan(number: str) -> str:
    if not number:
        return "Карта"
    return f"•••• {number[-4:]}"


def detect_brand(number: str) -> str:
    if not number:
        return "Карта"
    if is_amex(number):
        return "American Express"
    if number.startswith("4"):
        return "Visa"
    if len(number) >= 2 and 51 <= int(number[:2]) <= 55:
        return "Mastercard"
    if len(number) >= 4 and 2221 <= int(number[:4]) <= 2720:
        return "Mastercard"
    if len(number) >= 4 and 2200 <= int(number[:4]) <= 2204:
        return "МИР"
    if number.startswith(("6011", "65")):
        return "Discover"
    if len(number) >= 4 and 3528 <= int(number[:4]) <= 3589:
        return "JCB"
    if number.startswith("62"):
        return "UnionPay"
    return "Карта"


def is_amex(number: str) -> bool:
    return bool(number) and number[:2] in {"34", "37"}


def _clean_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError("Идентификатор записи повреждён.")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValidationError("Идентификатор записи повреждён.") from exc
    if parsed.version != 4:
        raise ValidationError("Идентификатор записи повреждён.")
    return str(parsed)


def _clean_timestamp(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError("Дата записи повреждена.")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValidationError("Дата записи повреждена.") from exc
    if parsed.tzinfo is None:
        raise ValidationError("Дата записи повреждена.")
    return value


def _clean_bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValidationError("Флаг записи повреждён.")
    return value


@dataclass(repr=False)
class BaseItem:
    id: str
    kind: ClassVar[str] = ""
    title: str
    notes: str
    tags: list[str]
    favorite: bool
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "notes": self.notes,
            "tags": list(self.tags),
            "favorite": self.favorite,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def __repr__(self) -> str:
        # Never let a debugger/log line serialize a password or PAN.
        return f"{type(self).__name__}(id={self.id!r})"

    @property
    def subtitle(self) -> str:
        return ""

    @property
    def search_text(self) -> str:
        return " ".join([self.title, self.notes, *self.tags]).casefold()


@dataclass(repr=False)
class PasswordItem(BaseItem):
    kind: ClassVar[str] = "password"
    username: str = ""
    password: str = ""
    url: str = ""

    @property
    def subtitle(self) -> str:
        return self.username or self.url or "Пароль"

    @property
    def search_text(self) -> str:
        return " ".join(
            [super().search_text, self.username, self.url]
        ).casefold()

    def to_dict(self) -> dict[str, Any]:
        return {
            **super().to_dict(),
            "username": self.username,
            "password": self.password,
            "url": self.url,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PasswordItem":
        item = cls(
            id=_clean_id(data.get("id")),
            title=clean_title(data.get("title")),
            notes=clean_notes(data.get("notes")),
            tags=clean_tags(data.get("tags")),
            favorite=_clean_bool(data.get("favorite")),
            created_at=_clean_timestamp(data.get("created_at")),
            updated_at=_clean_timestamp(data.get("updated_at")),
            username=clean_username(data.get("username")),
            password=clean_entry_password(data.get("password")),
            url=clean_url(data.get("url")),
        )
        return item


@dataclass(repr=False)
class CardItem(BaseItem):
    kind: ClassVar[str] = "card"
    cardholder: str = ""
    number: str = ""
    expiry_month: int = 1
    expiry_year: int = 2000

    @property
    def subtitle(self) -> str:
        return f"{masked_pan(self.number)} · {self.expiry_month:02d}/{self.expiry_year % 100:02d}"

    @property
    def brand(self) -> str:
        return detect_brand(self.number)

    @property
    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        return (self.expiry_year, self.expiry_month) < (now.year, now.month)

    @property
    def search_text(self) -> str:
        return " ".join(
            [
                super().search_text,
                self.cardholder,
                self.number[-4:],
                self.brand,
            ]
        ).casefold()

    def to_dict(self) -> dict[str, Any]:
        return {
            **super().to_dict(),
            "cardholder": self.cardholder,
            "number": self.number,
            "expiry_month": self.expiry_month,
            "expiry_year": self.expiry_year,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CardItem":
        month, year = validate_expiry(
            data.get("expiry_month"), data.get("expiry_year")
        )
        return cls(
            id=_clean_id(data.get("id")),
            title=clean_title(data.get("title")),
            notes=clean_notes(data.get("notes")),
            tags=clean_tags(data.get("tags")),
            favorite=_clean_bool(data.get("favorite")),
            created_at=_clean_timestamp(data.get("created_at")),
            updated_at=_clean_timestamp(data.get("updated_at")),
            cardholder=clean_cardholder(data.get("cardholder")),
            number=normalise_pan(data.get("number")),
            expiry_month=month,
            expiry_year=year,
        )


Item = PasswordItem | CardItem


def item_from_dict(data: dict[str, Any]) -> Item:
    if not isinstance(data, dict):
        raise ValidationError("Запись повреждена.")
    kind = data.get("kind")
    if kind == "password":
        return PasswordItem.from_dict(data)
    if kind == "card":
        return CardItem.from_dict(data)
    raise ValidationError("Неизвестный тип записи.")


def new_password_item(
    *,
    title: str,
    username: str = "",
    password: str = "",
    url: str = "",
    notes: str = "",
    tags: list[str] | None = None,
    favorite: bool = False,
) -> PasswordItem:
    now = utc_now()
    return PasswordItem(
        id=str(uuid.uuid4()),
        title=clean_title(title),
        notes=clean_notes(notes),
        tags=clean_tags(tags or []),
        favorite=bool(favorite),
        created_at=now,
        updated_at=now,
        username=clean_username(username),
        password=clean_entry_password(password),
        url=clean_url(url),
    )


def new_card_item(
    *,
    title: str,
    cardholder: str = "",
    number: str,
    expiry_month: int,
    expiry_year: int,
    notes: str = "",
    tags: list[str] | None = None,
    favorite: bool = False,
) -> CardItem:
    now = utc_now()
    month, year = validate_expiry(expiry_month, expiry_year)
    return CardItem(
        id=str(uuid.uuid4()),
        title=clean_title(title),
        notes=clean_notes(notes),
        tags=clean_tags(tags or []),
        favorite=bool(favorite),
        created_at=now,
        updated_at=now,
        cardholder=clean_cardholder(cardholder),
        number=normalise_pan(number),
        expiry_month=month,
        expiry_year=year,
    )
