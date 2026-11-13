"""Password policy, strength estimation and a CSPRNG-based generator.

The master-password policy follows NIST SP 800-63B-4 as closely as is
reasonable for a local, single-factor application:

* minimum length 15 characters (single-factor authenticator);
* maximum accepted length 1024 bytes (well above the 64-character minimum
  recommendation, and bounded to avoid resource abuse);
* no composition rules (uppercase/digit/symbol requirements);
* no forced periodic rotation;
* a blocklist check against common passwords and trivial repetitions.

Strength estimation is only a UI hint.  It must never be used as the sole
access-control decision.
"""

from __future__ import annotations

import math
import random
import re
import secrets
import time
from dataclasses import dataclass

from .crypto import WeakPasswordError

MIN_MASTER_PASSWORD_CHARS = 15
MAX_PASSWORD_BYTES = 1024

# Small, curated offline blocklist.  It cannot replace a full breached-password
# corpus, but it stops the overwhelmingly common choices and makes the policy
# visible.  Matching is case-insensitive and covers trivial suffixes.
_COMMON_PASSWORDS = {
    "123456", "12345678", "123456789", "1234567890", "111111", "000000",
    "password", "password1", "password123", "password1234", "passw0rd",
    "qwerty", "qwerty123", "qwertyuiop", "abc123", "letmein", "welcome",
    "welcome1", "monkey", "dragon", "sunshine", "princess", "football",
    "iloveyou", "admin", "administrator", "root", "toor", "login",
    "master", "secret", "changeme", "default", "trustno1", "shadow",
    "superman", "batman", "starwars", "whatever", "freedom", "hello",
    "hello123", "test", "test123", "user", "user123", "guest", "guest123",
    "qazwsx", "zaq12wsx", "1q2w3e4r", "1qaz2wsx", "asdfghjkl", "zxcvbnm",
    "qwertyui", "passphrase", "mypassword", "yourpassword", "letmein123",
    "correcthorsebatterystaple", "hunter2", "trustme", "opensesame",
    "пароль", "пароль123", "йцукен", "йцукенгшщз", "привет", "привет123",
    "любовь", "москва", "россия", "школа", "мама", "папа", "дом",
    "qwerty2024", "qwerty2025", "password2024", "password2025",
    "admin123", "root123", "welcome123", "secret123", "master123",
    "iloveyou1", "sunshine1", "princess1", "football1", "baseball",
    "access", "flower", "cookie", "chocolate", "computer", "internet",
    "samsung", "google", "apple", "microsoft", "linux", "ubuntu",
}

_SEQUENCES = (
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)


def _ascii_lower(value: str) -> str:
    return value.strip().lower()


def is_blocklisted(password: str) -> bool:
    normalised = _ascii_lower(password)
    candidates = {normalised, normalised.replace(" ", "")}
    # Remove a short trailing digit/symbol suffix, e.g. "password2025!".
    candidates.add(re.sub(r"[\d!@#$%^&*._+\-]+$", "", normalised))
    return any(candidate in _COMMON_PASSWORDS for candidate in candidates if candidate)


def _has_trivial_pattern(password: str) -> bool:
    if len(set(password)) < 4:
        return True
    # A short block repeated to fill the password ("abcabcabcabcabc").
    for period in range(1, min(5, len(password) // 2 + 1)):
        if password == (password[:period] * (len(password) // period + 1))[: len(password)]:
            return True
    lowered = password.lower()
    for sequence in _SEQUENCES:
        for start in range(0, len(sequence) - 5):
            chunk = sequence[start : start + 6]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def validate_master_password(password: str) -> None:
    """Raise ``WeakPasswordError`` with a user-facing explanation."""

    if not isinstance(password, str) or not password:
        raise WeakPasswordError("Введите мастер-пароль.")
    if len(password) < MIN_MASTER_PASSWORD_CHARS:
        raise WeakPasswordError(
            f"Мастер-пароль должен содержать не менее "
            f"{MIN_MASTER_PASSWORD_CHARS} символов. Лучше использовать длинную фразу."
        )
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise WeakPasswordError("Пароль слишком длинный (максимум 1024 байта).")
    if not password.strip():
        raise WeakPasswordError("Пароль не может состоять только из пробелов.")
    if is_blocklisted(password):
        raise WeakPasswordError(
            "Этот пароль встречается в списках самых распространённых. "
            "Выберите другую фразу."
        )
    if _has_trivial_pattern(password):
        raise WeakPasswordError(
            "Пароль слишком предсказуем: избегайте повторов и простых "
            "последовательностей."
        )


def estimate_entropy(password: str) -> float:
    """Rough entropy estimate in bits (UI hint only)."""

    if not password:
        return 0.0
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^\w\s]", password, re.UNICODE):
        pool += 33
    if re.search(r"\s", password):
        pool += 1
    if re.search(r"[^\x00-\x7f]", password):
        pool += 100
    bits = len(password) * math.log2(max(pool, 2))
    if _has_trivial_pattern(password):
        bits *= 0.35
    # Repeated adjacent characters add much less entropy than independent ones.
    repeats = sum(1 for a, b in zip(password, password[1:]) if a == b)
    bits *= max(0.45, 1.0 - repeats / max(len(password), 1))
    if is_blocklisted(password):
        bits = min(bits, 8.0)
    return max(0.0, bits)


@dataclass(frozen=True)
class Strength:
    score: int  # 0..4
    label: str
    bits: float
    hint: str


def password_strength(password: str) -> Strength:
    bits = estimate_entropy(password)
    if not password:
        return Strength(0, "Пусто", 0.0, "Введите пароль.")
    if is_blocklisted(password):
        return Strength(0, "Очень слабый", bits, "Такой пароль подбирают первым.")
    if bits < 35:
        return Strength(1, "Слабый", bits, "Слишком короткий или предсказуемый.")
    if bits < 60:
        return Strength(2, "Средний", bits, "Для важных аккаунтов лучше длиннее.")
    if bits < 90:
        return Strength(3, "Надёжный", bits, "Хорошая длина и разнообразие.")
    return Strength(4, "Очень надёжный", bits, "Отличный пароль.")


# --------------------------------------------------------------------------
# Generator
# --------------------------------------------------------------------------

LOWER = "abcdefghijkmnopqrstuvwxyz"
UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
DIGITS = "23456789"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = set("O0Il1|`'\"\\ /")


@dataclass(frozen=True)
class GeneratorOptions:
    length: int = 24
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    avoid_ambiguous: bool = True


def _alphabet(options: GeneratorOptions) -> tuple[str, list[str]]:
    classes: list[str] = []
    if options.use_lower:
        classes.append(LOWER)
    if options.use_upper:
        classes.append(UPPER)
    if options.use_digits:
        classes.append(DIGITS)
    if options.use_symbols:
        classes.append(SYMBOLS)
    if not classes:
        classes = [LOWER]
    cleaned: list[str] = []
    for charset in classes:
        if options.avoid_ambiguous:
            charset = "".join(c for c in charset if c not in AMBIGUOUS)
        if charset:
            cleaned.append(charset)
    if not cleaned:
        cleaned = [LOWER]
    return "".join(cleaned), cleaned


def generate_password(options: GeneratorOptions | None = None) -> str:
    options = options or GeneratorOptions()
    if not 8 <= options.length <= 128:
        raise ValueError("Длина пароля должна быть от 8 до 128 символов.")
    alphabet, classes = _alphabet(options)
    if options.length < len(classes):
        raise ValueError("Слишком короткий пароль для выбранных наборов символов.")

    # Guarantee at least one character from every selected class, then fill.
    chars = [secrets.choice(charset) for charset in classes]
    chars.extend(secrets.choice(alphabet) for _ in range(options.length - len(chars)))
    random.SystemRandom().shuffle(chars)
    password = "".join(chars)

    # Vanishingly unlikely, but never return a blocklisted value.
    if is_blocklisted(password):
        return generate_password(options)
    return password


def sanitize_generator_options(
    length: int,
    use_lower: bool,
    use_upper: bool,
    use_digits: bool,
    use_symbols: bool,
    avoid_ambiguous: bool = True,
) -> GeneratorOptions:
    length = max(8, min(128, int(length)))
    if not any((use_lower, use_upper, use_digits, use_symbols)):
        use_lower = True
    return GeneratorOptions(
        length=length,
        use_lower=use_lower,
        use_upper=use_upper,
        use_digits=use_digits,
        use_symbols=use_symbols,
        avoid_ambiguous=avoid_ambiguous,
    )


class UnlockThrottle:
    """In-memory progressive delay for interactive password guessing.

    Offline guessing is limited by Argon2id, not by this class.  The state is
    intentionally not persisted: a local attacker who can modify files could
    reset it anyway, and keeping it in memory avoids extra metadata on disk.
    """

    def __init__(self, max_delay: int = 60, clock=time.monotonic) -> None:
        self.failures = 0
        self._blocked_until = 0.0
        self._max_delay = max_delay
        self._clock = clock

    def remaining(self) -> float:
        return max(0.0, self._blocked_until - self._clock())

    def register_failure(self) -> int:
        self.failures += 1
        if self.failures < 3:
            delay = 0
        else:
            delay = min(2 ** (self.failures - 2), self._max_delay)
        self._blocked_until = self._clock() + delay
        return delay

    def reset(self) -> None:
        self.failures = 0
        self._blocked_until = 0.0
