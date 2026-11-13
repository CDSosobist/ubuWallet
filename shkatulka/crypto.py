"""Cryptographic core of Shkatulka.

Security properties
-------------------
* Key derivation: Argon2id, RFC 9106 second recommended profile
  (64 MiB, 3 passes, 4 lanes), 16-byte random salt per vault.
* Encryption: AES-256-GCM with a fresh 96-bit nonce for every write.
* The authenticated header (format, version, vault id, KDF parameters and
  nonce) is bound to the ciphertext as AEAD associated data.  Changing the
  KDF cost, nonce or vault id therefore makes decryption fail.
* The complete payload is serialised as deterministic UTF-8 JSON and
  encrypted as a single unit, so record boundaries, titles and item counts
  are not visible in the file.

The vault file never contains a password verifier, a key or plaintext.
A wrong password and a modified file are intentionally indistinguishable to
the caller (both fail GCM authentication).
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import json
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = "shkatulka-vault"
FORMAT_VERSION = 1
CIPHER_NAME = "aes-256-gcm"
KDF_NAME = "argon2id"

SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32

# RFC 9106, second recommended option.  Deliberately fixed (not read from an
# untrusted file without bounds) so a malicious vault cannot request 100 GiB
# of memory or hours of CPU.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_PARALLELISM = 4

MAX_VAULT_FILE_BYTES = 32 * 1024 * 1024
MAX_CIPHERTEXT_BYTES = MAX_VAULT_FILE_BYTES - 4096
MAX_PAYLOAD_BYTES = 24 * 1024 * 1024

# Bounds accepted when opening a vault written by another version.  They are
# wide enough for future hardening but narrow enough to prevent a denial of
# service via absurd KDF parameters.
MIN_KDF_TIME_COST = 1
MAX_KDF_TIME_COST = 10
MIN_KDF_MEMORY_KIB = 16 * 1024
MAX_KDF_MEMORY_KIB = 512 * 1024
MIN_KDF_PARALLELISM = 1
MAX_KDF_PARALLELISM = 8


class CryptoError(Exception):
    """Base class for errors safe to show to a user (contains no secrets)."""


class InvalidPasswordError(CryptoError):
    """Authentication failed: wrong password or modified vault file."""


class CorruptVaultError(CryptoError):
    """The file does not have the expected, authenticated format."""


class WeakPasswordError(CryptoError):
    """The master password does not meet the minimum policy."""


@dataclass(frozen=True)
class KdfParams:
    salt: bytes
    time_cost: int = ARGON2_TIME_COST
    memory_kib: int = ARGON2_MEMORY_KIB
    parallelism: int = ARGON2_PARALLELISM
    key_len: int = KEY_BYTES

    @classmethod
    def generate(cls) -> "KdfParams":
        return cls(salt=secrets.token_bytes(SALT_BYTES))

    def to_header(self) -> dict[str, Any]:
        return {
            "name": KDF_NAME,
            "salt": _b64e(self.salt),
            "time_cost": self.time_cost,
            "memory_kib": self.memory_kib,
            "parallelism": self.parallelism,
            "key_len": self.key_len,
        }

    def validate(self) -> None:
        if len(self.salt) < 16 or len(self.salt) > 64:
            raise CorruptVaultError("Некорректная соль KDF.")
        if not MIN_KDF_TIME_COST <= self.time_cost <= MAX_KDF_TIME_COST:
            raise CorruptVaultError("Недопустимая стоимость KDF.")
        if not MIN_KDF_MEMORY_KIB <= self.memory_kib <= MAX_KDF_MEMORY_KIB:
            raise CorruptVaultError("Недопустимый объём памяти KDF.")
        if not MIN_KDF_PARALLELISM <= self.parallelism <= MAX_KDF_PARALLELISM:
            raise CorruptVaultError("Недопустимый параллелизм KDF.")
        if self.key_len != KEY_BYTES:
            raise CorruptVaultError("Недопустимая длина ключа.")


@dataclass(repr=False)
class UnlockedVault:
    """Result of opening a vault.  ``key`` must be zeroised by the caller."""

    payload: dict[str, Any]
    key: bytearray
    kdf: KdfParams
    vault_id: str

    def __repr__(self) -> str:
        return f"UnlockedVault(vault_id={self.vault_id!r}, key=<redacted>)"


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(value: Any, *, what: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 2 * MAX_VAULT_FILE_BYTES:
        raise CorruptVaultError(f"Повреждённое поле «{what}».")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CorruptVaultError(f"Повреждённое поле «{what}».") from exc


def _canonical(obj: Any) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CorruptVaultError("Файл сейфа содержит повторяющиеся поля.")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise CorruptVaultError("Файл сейфа содержит недопустимое число.")


def parse_json_object(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except CorruptVaultError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise CorruptVaultError("Файл сейфа повреждён или не является сейфом.") from exc
    if not isinstance(data, dict):
        raise CorruptVaultError("Файл сейфа повреждён.")
    return data


def zero_bytes(buf: bytearray | None) -> None:
    """Best-effort overwrite of a mutable buffer.

    Python strings and immutable ``bytes`` cannot be reliably wiped, so the
    application keeps the long-lived key in a ``bytearray`` and never logs or
    formats it.  This is defence in depth, not a guarantee against a process
    memory dump while the vault is unlocked.
    """

    if not buf:
        return
    try:
        length = len(buf)
        if length:
            ctypes.memset((ctypes.c_char * length).from_buffer(buf), 0, length)
    except (TypeError, ValueError, BufferError):
        try:
            buf[:] = b"\x00" * len(buf)
        except Exception:
            pass


def derive_key(password: str, params: KdfParams) -> bytearray:
    """Derive a 256-bit key.  Never logs or returns the password."""

    params.validate()
    if not isinstance(password, str) or not password:
        raise WeakPasswordError("Пароль не может быть пустым.")
    password_bytes = bytearray(password.encode("utf-8"))
    if len(password_bytes) > 1024:
        zero_bytes(password_bytes)
        raise WeakPasswordError("Пароль слишком длинный (максимум 1024 байта).")
    try:
        raw = bytearray(
            hash_secret_raw(
                secret=bytes(password_bytes),
                salt=params.salt,
                time_cost=params.time_cost,
                memory_cost=params.memory_kib,
                parallelism=params.parallelism,
                hash_len=params.key_len,
                type=Type.ID,
            )
        )
        try:
            return bytearray(raw)
        finally:
            zero_bytes(raw)
    finally:
        zero_bytes(password_bytes)


def _header_aad(header: dict[str, Any]) -> bytes:
    # Only the immutable, authenticated metadata is covered.  Ciphertext is
    # authenticated by GCM itself; anything outside this set is not trusted.
    return _canonical(
        {
            "format": header["format"],
            "version": header["version"],
            "vault_id": header["vault_id"],
            "kdf": header["kdf"],
            "cipher": header["cipher"],
        }
    )


def seal(
    payload: dict[str, Any],
    key: bytearray,
    *,
    kdf: KdfParams,
    vault_id: str,
) -> bytes:
    """Encrypt a payload into a complete vault file."""

    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
        raise ValueError("invalid key")
    kdf.validate()
    if not _is_uuid4(vault_id):
        raise ValueError("invalid vault id")

    plaintext = _canonical(payload)
    if len(plaintext) > MAX_PAYLOAD_BYTES:
        raise CryptoError("Сейф слишком большой для сохранения.")

    nonce = secrets.token_bytes(NONCE_BYTES)
    header: dict[str, Any] = {
        "format": FORMAT,
        "version": FORMAT_VERSION,
        "vault_id": vault_id,
        "kdf": kdf.to_header(),
        "cipher": {"name": CIPHER_NAME, "nonce": _b64e(nonce)},
    }
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _header_aad(header))
    envelope = {**header, "ciphertext": _b64e(ciphertext)}
    return _canonical(envelope) + b"\n"


def open_envelope(blob: bytes, password: str) -> UnlockedVault:
    """Parse, authenticate and decrypt a vault file.

    The KDF parameters are validated against strict bounds *before* Argon2 is
    invoked, so a hostile file cannot exhaust memory or CPU.
    """

    if not isinstance(blob, (bytes, bytearray)):
        raise CorruptVaultError("Некорректные данные сейфа.")
    if len(blob) > MAX_VAULT_FILE_BYTES:
        raise CorruptVaultError("Файл сейфа слишком большой.")
    data = parse_json_object(bytes(blob))

    if data.get("format") != FORMAT:
        raise CorruptVaultError("Это не файл сейфа «Шкатулка».")
    version = data.get("version")
    if version != FORMAT_VERSION:
        raise CorruptVaultError("Неподдерживаемая версия формата сейфа.")

    vault_id = data.get("vault_id")
    if not isinstance(vault_id, str):
        raise CorruptVaultError("Повреждённый идентификатор сейфа.")
    if not _is_uuid4(vault_id):
        raise CorruptVaultError("Повреждённый идентификатор сейфа.")

    kdf_raw = data.get("kdf")
    if not isinstance(kdf_raw, dict) or set(kdf_raw) != {
        "name",
        "salt",
        "time_cost",
        "memory_kib",
        "parallelism",
        "key_len",
    }:
        raise CorruptVaultError("Повреждённые параметры KDF.")
    if kdf_raw.get("name") != KDF_NAME:
        raise CorruptVaultError("Неподдерживаемый алгоритм KDF.")
    try:
        kdf = KdfParams(
            salt=_b64d(kdf_raw["salt"], what="salt"),
            time_cost=_require_int(kdf_raw["time_cost"]),
            memory_kib=_require_int(kdf_raw["memory_kib"]),
            parallelism=_require_int(kdf_raw["parallelism"]),
            key_len=_require_int(kdf_raw["key_len"]),
        )
    except (TypeError, KeyError) as exc:
        raise CorruptVaultError("Повреждённые параметры KDF.") from exc
    kdf.validate()

    cipher_raw = data.get("cipher")
    if not isinstance(cipher_raw, dict) or set(cipher_raw) != {"name", "nonce"}:
        raise CorruptVaultError("Повреждённые параметры шифрования.")
    if cipher_raw.get("name") != CIPHER_NAME:
        raise CorruptVaultError("Неподдерживаемый алгоритм шифрования.")
    nonce = _b64d(cipher_raw["nonce"], what="nonce")
    if len(nonce) != NONCE_BYTES:
        raise CorruptVaultError("Повреждённый nonce.")

    ciphertext = _b64d(data.get("ciphertext"), what="ciphertext")
    if len(ciphertext) < 17 or len(ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise CorruptVaultError("Повреждённый шифротекст.")

    key = derive_key(password, kdf)
    try:
        plaintext = AESGCM(key).decrypt(
            nonce, ciphertext, _header_aad(data)
        )
    except InvalidTag as exc:
        zero_bytes(key)
        raise InvalidPasswordError(
            "Неверный мастер-пароль или файл сейфа был изменён."
        ) from exc
    except Exception as exc:  # pragma: no cover - defensive
        zero_bytes(key)
        raise CorruptVaultError("Не удалось расшифровать сейф.") from exc

    if len(plaintext) > MAX_PAYLOAD_BYTES:
        zero_bytes(key)
        raise CorruptVaultError("Сейф слишком большой.")
    try:
        payload = parse_json_object(plaintext)
    except CorruptVaultError:
        zero_bytes(key)
        raise

    return UnlockedVault(payload=payload, key=key, kdf=kdf, vault_id=vault_id)


def _is_uuid4(value: str) -> bool:
    try:
        return uuid.UUID(value).version == 4
    except (ValueError, AttributeError, TypeError):
        return False


def _require_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("integer required")
    return value


def password_bytes_for_validation(password: str) -> None:
    """Cheap sanity checks before an expensive KDF call."""

    if not isinstance(password, str) or not password:
        raise WeakPasswordError("Введите мастер-пароль.")
    if len(password.encode("utf-8")) > 1024:
        raise WeakPasswordError("Пароль слишком длинный (максимум 1024 байта).")
