"""Encrypted vault storage and the unlocked session object."""

from __future__ import annotations

import fcntl
import hmac
import os
import stat
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .crypto import (
    CorruptVaultError,
    InvalidPasswordError,
    KdfParams,
    UnlockedVault,
    derive_key,
    open_envelope,
    seal,
    zero_bytes,
)
from .models import Item, ValidationError, item_from_dict, utc_now
from .security import validate_master_password

SCHEMA_VERSION = 1
MAX_ITEMS = 10_000
MAX_BACKUP_BYTES = 32 * 1024 * 1024

AUTO_LOCK_CHOICES = (60, 300, 900, 1800, 3600)
CLIPBOARD_CHOICES = (5, 10, 20, 30, 60)
DEFAULT_SETTINGS = {"auto_lock_seconds": 300, "clipboard_seconds": 20}


class VaultError(Exception):
    """Base class for storage/session errors safe for the UI."""


class VaultExistsError(VaultError):
    pass


class VaultNotFoundError(VaultError):
    pass


class VaultBusyError(VaultError):
    pass


class VaultLockedError(VaultError):
    pass


class UnsafeStorageError(VaultError):
    pass


def default_data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME", "").strip()
    if not base or not os.path.isabs(base):
        base = str(Path.home() / ".local" / "share")
    return Path(base) / "shkatulka"


def default_vault_path() -> Path:
    return default_data_dir() / "vault.shk"


def _check_owner_and_type(path: Path, *, directory: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise
    if stat.S_ISLNK(info.st_mode):
        raise UnsafeStorageError("Хранилище не может быть символической ссылкой.")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise UnsafeStorageError("Каталог хранилища повреждён.")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise UnsafeStorageError("Файл сейфа должен быть обычным файлом.")
    if info.st_uid != os.getuid():
        raise UnsafeStorageError("Файл сейфа принадлежит другому пользователю.")
    return info


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_backup_file(path: Path | str, limit: int = MAX_BACKUP_BYTES) -> bytes:
    """Read a user-selected backup without following links or blocking on FIFOs.

    The size is checked from ``fstat`` before reading, so a huge file cannot
    exhaust memory.  Non-regular files (FIFOs, devices) are rejected; a FIFO
    is opened with O_NONBLOCK first so the UI never hangs.
    """

    target = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(target, flags)
    except OSError as exc:
        raise VaultError("Не удалось открыть файл резервной копии.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise VaultError("Файл резервной копии должен быть обычным файлом.")
        if info.st_size > limit:
            raise VaultError("Файл резервной копии слишком большой.")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise VaultError("Файл резервной копии слишком большой.")
        return data
    except VaultError:
        raise
    except OSError as exc:
        raise VaultError("Не удалось прочитать файл резервной копии.") from exc
    finally:
        if fd != -1:
            os.close(fd)


class VaultStore:
    """Filesystem layer with strict permissions and atomic replacement.

    The parent directory is created with mode 0700 and existing permissive
    permissions are tightened.  The vault is written to a mode-0600 temporary
    file in the same directory, fsynced, atomically renamed and the directory
    entry is fsynced as well.  Symlinked vault files are rejected.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else default_vault_path()
        self._lock_fd: int | None = None

    def __repr__(self) -> str:
        return f"VaultStore(path={str(self.path)!r})"

    @property
    def exists(self) -> bool:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(info.st_mode):
            raise UnsafeStorageError("Файл сейфа не может быть символической ссылкой.")
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeStorageError("Файл сейфа должен быть обычным файлом.")
        return True

    def ensure_parent(self) -> None:
        parent = self.path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = _check_owner_and_type(parent, directory=True)
        if info.st_mode & 0o077:
            os.chmod(parent, 0o700)

    def read(self) -> bytes:
        try:
            parent_info = _check_owner_and_type(self.path.parent, directory=True)
        except FileNotFoundError as exc:
            raise VaultNotFoundError("Файл сейфа не найден.") from exc
        if parent_info.st_mode & 0o077:
            os.chmod(self.path.parent, 0o700)
        info = _check_owner_and_type(self.path, directory=False)
        if info.st_size > 32 * 1024 * 1024:
            raise VaultError("Файл сейфа слишком большой.")
        if info.st_mode & 0o077:
            os.chmod(self.path, 0o600, follow_symlinks=False)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                    raise UnsafeStorageError("Файл сейфа небезопасен.")
                if info.st_size > 32 * 1024 * 1024:
                    raise VaultError("Файл сейфа слишком большой.")
                with os.fdopen(fd, "rb") as handle:
                    fd = -1
                    return handle.read(32 * 1024 * 1024 + 1)
            finally:
                if fd != -1:
                    os.close(fd)
        except UnsafeStorageError:
            raise
        except OSError as exc:
            raise VaultError("Не удалось прочитать файл сейфа.") from exc

    def write(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        if len(data) > 32 * 1024 * 1024:
            raise VaultError("Сейф слишком большой для сохранения.")
        self.ensure_parent()
        parent = self.path.parent
        try:
            if stat.S_ISLNK(self.path.lstat().st_mode):
                raise UnsafeStorageError("Файл сейфа не может быть символической ссылкой.")
        except FileNotFoundError:
            pass
        fd = -1
        tmp_name: str | None = None
        try:
            fd, tmp_name = tempfile.mkstemp(
                prefix=".vault-", suffix=".tmp", dir=str(parent)
            )
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
            tmp_name = None
            os.chmod(self.path, 0o600, follow_symlinks=False)
            _fsync_directory(parent)
        except OSError as exc:
            raise VaultError("Не удалось сохранить сейф на диск.") from exc
        finally:
            if fd != -1:
                os.close(fd)
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass

    def backup_current(self) -> Path | None:
        """Save the current encrypted vault next to itself before replacing it.

        The copy stays encrypted with the current master password.  It is
        intentionally kept outside the vault file name so import/recovery can
        never silently destroy the only copy.
        """

        if not self.exists:
            return None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = self.path.with_name(f"{self.path.name}.bak-{stamp}")
        counter = 1
        while destination.exists():
            destination = self.path.with_name(
                f"{self.path.name}.bak-{stamp}-{counter}"
            )
            counter += 1
        self.copy_to(destination)
        return destination

    def copy_to(self, destination: Path | str) -> None:
        """Atomically write the current encrypted vault to another location."""

        destination = Path(destination)
        try:
            if destination.resolve() == self.path.resolve():
                raise VaultError("Выберите другой файл для резервной копии.")
        except OSError:
            pass
        try:
            if stat.S_ISLNK(destination.lstat().st_mode):
                raise UnsafeStorageError("Нельзя перезаписать символическую ссылку.")
        except FileNotFoundError:
            pass
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = self.read()
        fd = -1
        tmp_name: str | None = None
        try:
            fd, tmp_name = tempfile.mkstemp(
                prefix=".backup-", suffix=".tmp", dir=str(destination.parent)
            )
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, destination)
            tmp_name = None
            os.chmod(destination, 0o600, follow_symlinks=False)
            _fsync_directory(destination.parent)
        except OSError as exc:
            raise VaultError("Не удалось создать резервную копию.") from exc
        finally:
            if fd != -1:
                os.close(fd)
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass

    def acquire_lock(self) -> None:
        """Prevent two processes from writing the same vault concurrently."""

        if self._lock_fd is not None:
            return
        self.ensure_parent()
        lock_path = self.path.with_name(self.path.name + ".lock")
        try:
            fd = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.fchmod(fd, 0o600)
            lock_info = os.fstat(fd)
            if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid():
                os.close(fd)
                raise UnsafeStorageError("Файл блокировки небезопасен.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                raise VaultBusyError(
                    "Сейф уже открыт в другом экземпляре приложения."
                )
        except OSError as exc:
            raise VaultError("Не удалось заблокировать файл сейфа.") from exc
        self._lock_fd = fd

    def release_lock(self) -> None:
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self._lock_fd)
            except OSError:
                pass
            self._lock_fd = None


@dataclass
class Vault:
    items: dict[str, Item]
    settings: dict[str, int]
    created_at: str
    updated_at: str
    revision: int

    @classmethod
    def new(cls) -> "Vault":
        now = utc_now()
        return cls(
            items={},
            settings=dict(DEFAULT_SETTINGS),
            created_at=now,
            updated_at=now,
            revision=1,
        )

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "Vault":
        try:
            schema = payload.get("schema")
            if isinstance(schema, bool) or schema != SCHEMA_VERSION:
                raise ValueError("schema")
            items_raw = payload.get("items")
            settings_raw = payload.get("settings")
            created_at = payload.get("created_at")
            updated_at = payload.get("updated_at")
            revision = payload.get("revision")
            if not isinstance(items_raw, list) or len(items_raw) > MAX_ITEMS:
                raise ValueError("items")
            if not isinstance(settings_raw, dict):
                raise ValueError("settings")
            if not isinstance(created_at, str) or not isinstance(updated_at, str):
                raise ValueError("timestamps")
            for stamp in (created_at, updated_at):
                parsed = datetime.fromisoformat(stamp)
                if parsed.tzinfo is None:
                    raise ValueError("timestamp")
            if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
                raise ValueError("revision")

            settings = dict(DEFAULT_SETTINGS)
            auto_lock = settings_raw.get("auto_lock_seconds", 300)
            clipboard = settings_raw.get("clipboard_seconds", 20)
            if (
                isinstance(auto_lock, bool)
                or not isinstance(auto_lock, int)
                or not 60 <= auto_lock <= 3600
            ):
                raise ValueError("auto lock")
            if (
                isinstance(clipboard, bool)
                or not isinstance(clipboard, int)
                or not 5 <= clipboard <= 120
            ):
                raise ValueError("clipboard")
            settings["auto_lock_seconds"] = auto_lock
            settings["clipboard_seconds"] = clipboard

            items: dict[str, Item] = {}
            for raw in items_raw:
                item = item_from_dict(raw)
                if item.id in items:
                    raise ValueError("duplicate id")
                items[item.id] = item
        except (ValueError, ValidationError, TypeError, KeyError) as exc:
            raise CorruptVaultError("Содержимое сейфа повреждено или несовместимо.") from exc
        return cls(
            items=items,
            settings=settings,
            created_at=created_at,
            updated_at=updated_at,
            revision=revision,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "items": [item.to_dict() for item in self.items.values()],
            "settings": dict(self.settings),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "revision": self.revision,
        }

    def touch(self) -> None:
        self.updated_at = utc_now()
        self.revision += 1

    def add(self, item: Item) -> None:
        if len(self.items) >= MAX_ITEMS:
            raise VaultError("Достигнут предел количества записей.")
        if item.id in self.items:
            raise VaultError("Запись с таким идентификатором уже существует.")
        self.items[item.id] = item
        self.touch()

    def replace(self, item: Item) -> None:
        existing = self.items.get(item.id)
        if existing is None:
            raise VaultError("Запись не найдена.")
        item.created_at = existing.created_at
        item.updated_at = utc_now()
        self.items[item.id] = item
        self.touch()

    def delete(self, item_id: str) -> None:
        if item_id not in self.items:
            raise VaultError("Запись не найдена.")
        del self.items[item_id]
        self.touch()

    def get(self, item_id: str) -> Item | None:
        return self.items.get(item_id)

    def sorted_items(self, query: str = "", kind: str | None = None) -> list[Item]:
        terms = [term.casefold() for term in query.split() if term.strip()]
        result = []
        for item in self.items.values():
            if kind and item.kind != kind:
                continue
            haystack = item.search_text
            if all(term in haystack for term in terms):
                result.append(item)
        result.sort(key=lambda item: (not item.favorite, item.title.casefold()))
        return result

    def update_settings(
        self, *, auto_lock_seconds: int | None = None, clipboard_seconds: int | None = None
    ) -> None:
        if auto_lock_seconds is not None:
            if auto_lock_seconds not in AUTO_LOCK_CHOICES:
                raise VaultError("Недопустимый интервал автоблокировки.")
            self.settings["auto_lock_seconds"] = auto_lock_seconds
        if clipboard_seconds is not None:
            if clipboard_seconds not in CLIPBOARD_CHOICES:
                raise VaultError("Недопустимый интервал очистки буфера обмена.")
            self.settings["clipboard_seconds"] = clipboard_seconds
        self.touch()


class VaultSession:
    """An unlocked vault.  Holds the derived key until ``lock()``."""

    def __init__(
        self,
        store: VaultStore,
        vault: Vault,
        key: bytearray,
        kdf: KdfParams,
        vault_id: str,
    ) -> None:
        self.store = store
        self._vault: Vault | None = vault
        self._key: bytearray | None = key
        self._kdf = kdf
        self._vault_id = vault_id
        # Serialises key/KDF swaps, saves and locking.  Reentrant because
        # change_password() calls verify_master()/vault while holding it.
        self._state_lock = threading.RLock()

    def __repr__(self) -> str:
        return f"VaultSession(locked={self.is_locked})"

    @property
    def is_locked(self) -> bool:
        return self._vault is None or self._key is None

    @property
    def vault(self) -> Vault:
        if self._vault is None:
            raise VaultLockedError("Сейф заблокирован.")
        return self._vault

    @property
    def settings(self) -> dict[str, int]:
        return dict(self.vault.settings)

    @property
    def vault_id(self) -> str:
        return self._vault_id

    @classmethod
    def create(
        cls, store: VaultStore, password: str, *, overwrite: bool = False
    ) -> "VaultSession":
        validate_master_password(password)
        if store.exists and not overwrite:
            raise VaultExistsError("Файл сейфа уже существует.")
        kdf = KdfParams.generate()
        key = derive_key(password, kdf)
        vault = Vault.new()
        vault_id = str(uuid.uuid4())
        try:
            envelope = seal(vault.to_payload(), key, kdf=kdf, vault_id=vault_id)
            store.write(envelope)
        except Exception:
            zero_bytes(key)
            raise
        return cls(store, vault, key, kdf, vault_id)

    @classmethod
    def unlock(cls, store: VaultStore, password: str) -> "VaultSession":
        if not store.exists:
            raise VaultNotFoundError("Файл сейфа не найден.")
        blob = store.read()
        return cls._from_blob(store, blob, password)

    @classmethod
    def _from_blob(
        cls, store: VaultStore, blob: bytes, password: str
    ) -> "VaultSession":
        unlocked: UnlockedVault | None = None
        try:
            unlocked = open_envelope(blob, password)
            vault = Vault.from_payload(unlocked.payload)
        except Exception:
            if unlocked is not None:
                zero_bytes(unlocked.key)
            raise
        return cls(store, vault, unlocked.key, unlocked.kdf, unlocked.vault_id)

    @classmethod
    def import_from(
        cls, store: VaultStore, blob: bytes, password: str
    ) -> "VaultSession":
        """Validate a backup and replace the current vault with it.

        The caller is responsible for asking the user before calling this.
        Imported data is re-encrypted with a fresh salt and with this
        version's Argon2id profile, so an old or weak backup cannot downgrade
        the protection of the restored vault.
        """

        unlocked = open_envelope(blob, password)
        try:
            vault = Vault.from_payload(unlocked.payload)
            new_kdf = KdfParams.generate()
            new_key = derive_key(password, new_kdf)
            new_vault_id = str(uuid.uuid4())
            try:
                envelope = seal(
                    vault.to_payload(),
                    new_key,
                    kdf=new_kdf,
                    vault_id=new_vault_id,
                )
                # Preserve the previous encrypted file before replacing it.
                # If this fails, abort before touching the live vault.
                store.backup_current()
                store.write(envelope)
            except Exception:
                zero_bytes(new_key)
                raise
        finally:
            zero_bytes(unlocked.key)
        return cls(store, vault, new_key, new_kdf, new_vault_id)

    def verify_master(self, password: str) -> bool:
        with self._state_lock:
            if self.is_locked:
                raise VaultLockedError("Сейф заблокирован.")
            key = self._key
            kdf = self._kdf
        assert key is not None
        candidate = derive_key(password, kdf)
        try:
            return hmac.compare_digest(candidate, key)
        finally:
            zero_bytes(candidate)

    def save(self) -> None:
        with self._state_lock:
            if self.is_locked:
                raise VaultLockedError("Сейф заблокирован.")
            vault = self.vault
            vault.touch()
            envelope = seal(
                vault.to_payload(),
                self._key,  # type: ignore[arg-type]
                kdf=self._kdf,
                vault_id=self._vault_id,
            )
            self.store.write(envelope)

    def change_password(self, current_password: str, new_password: str) -> None:
        validate_master_password(new_password)
        if not self.verify_master(current_password):
            raise InvalidPasswordError("Текущий мастер-пароль неверен.")

        new_kdf = KdfParams.generate()
        new_key = derive_key(new_password, new_kdf)
        with self._state_lock:
            if self.is_locked:
                zero_bytes(new_key)
                raise VaultLockedError("Сейф заблокирован.")
            old_key = self._key
            try:
                vault = self.vault
                vault.touch()
                envelope = seal(
                    vault.to_payload(),
                    new_key,
                    kdf=new_kdf,
                    vault_id=self._vault_id,
                )
                self.store.write(envelope)
            except Exception:
                zero_bytes(new_key)
                raise
            # Swap key and KDF together while no save()/lock() can observe a
            # mismatched pair.
            self._key = new_key
            self._kdf = new_kdf
        zero_bytes(old_key)

    def export_backup(self, destination: Path | str) -> None:
        with self._state_lock:
            if self.is_locked:
                raise VaultLockedError("Сейф заблокирован.")
            # Do not silently export stale data if a UI edit has not been saved.
            self.save()
            self.store.copy_to(destination)

    def update_settings(
        self, *, auto_lock_seconds: int | None = None, clipboard_seconds: int | None = None
    ) -> None:
        self.vault.update_settings(
            auto_lock_seconds=auto_lock_seconds,
            clipboard_seconds=clipboard_seconds,
        )
        self.save()

    def lock(self) -> None:
        with self._state_lock:
            vault = self._vault
            if vault is not None:
                # Drop references to plaintext objects.  Python cannot reliably
                # wipe immutable strings; zeroising the key makes the ciphertext
                # inaccessible and the objects become garbage.
                vault.items.clear()
            self._vault = None
            zero_bytes(self._key)
            self._key = None

    def __del__(self) -> None:  # pragma: no cover - interpreter shutdown
        try:
            self.lock()
        except Exception:
            pass


def format_item_count(count: int) -> str:
    """Russian pluralisation for the sidebar footer."""

    if count % 10 == 1 and count % 100 != 11:
        word = "запись"
    elif count % 10 in (2, 3, 4) and count % 100 not in (12, 13, 14):
        word = "записи"
    else:
        word = "записей"
    return f"{count} {word}"
