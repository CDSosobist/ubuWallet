import base64
import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from shkatulka.crypto import CorruptVaultError, InvalidPasswordError, KdfParams, derive_key, seal
from shkatulka.models import new_card_item, new_password_item
from shkatulka.vault import (
    MAX_BACKUP_BYTES,
    Vault,
    VaultBusyError,
    VaultError,
    VaultSession,
    VaultStore,
    format_item_count,
    read_backup_file,
)

MASTER = "correct horse battery staple 42"
NEW_MASTER = "another very long passphrase 99"


class VaultTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.shk"
        self.store = VaultStore(self.path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def make_session(self) -> VaultSession:
        return VaultSession.create(self.store, MASTER)


class VaultStorageTests(VaultTestCase):
    def test_create_save_unlock(self) -> None:
        session = self.make_session()
        self.assertTrue(self.store.exists)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        session.vault.add(
            new_password_item(
                title="GitHub",
                username="octocat",
                password="s3cret-password",
                url="https://github.com",
            )
        )
        session.vault.add(
            new_card_item(
                title="Visa",
                number="4111111111111111",
                expiry_month=12,
                expiry_year=2030,
            )
        )
        session.save()
        session.lock()
        self.assertFalse(self.store.read().find(b"GitHub") >= 0)
        self.assertNotIn(b"4111111111111111", self.store.read())

        reopened = VaultSession.unlock(self.store, MASTER)
        titles = {item.title for item in reopened.vault.sorted_items()}
        self.assertEqual(titles, {"GitHub", "Visa"})
        self.assertEqual(len(reopened.vault.items), 2)
        reopened.lock()

    def test_wrong_password(self) -> None:
        self.make_session().lock()
        with self.assertRaises(InvalidPasswordError):
            VaultSession.unlock(self.store, "wrong master password")

    def test_tampered_file(self) -> None:
        session = self.make_session()
        session.vault.add(new_password_item(title="A", password="secret"))
        session.save()
        envelope = json.loads(self.path.read_bytes())
        raw = bytearray(base64.b64decode(envelope["ciphertext"]))
        raw[0] ^= 0x01
        envelope["ciphertext"] = base64.b64encode(bytes(raw)).decode()
        self.path.write_bytes(json.dumps(envelope).encode())
        with self.assertRaises(InvalidPasswordError):
            VaultSession.unlock(self.store, MASTER)

    def test_vault_not_found(self) -> None:
        from shkatulka.vault import VaultNotFoundError

        with self.assertRaises(VaultNotFoundError):
            VaultSession.unlock(self.store, MASTER)

    def test_symlink_rejected(self) -> None:
        session = self.make_session()
        session.lock()
        link = Path(self.tmp.name) / "link.shk"
        link.symlink_to(self.path)
        store = VaultStore(link)
        from shkatulka.vault import UnsafeStorageError

        with self.assertRaises(UnsafeStorageError):
            store.exists
        with self.assertRaises(UnsafeStorageError):
            store.read()

    def test_permissions_are_hardened_on_read(self) -> None:
        session = self.make_session()
        session.lock()
        os.chmod(self.path, 0o644)
        os.chmod(self.path.parent, 0o755)
        self.store.read()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)

    def test_atomic_write_leaves_no_temporary_files(self) -> None:
        session = self.make_session()
        session.save()
        leftovers = list(self.path.parent.glob(".vault-*.tmp"))
        self.assertEqual(leftovers, [])

    def test_exclusive_file_lock(self) -> None:
        first = VaultStore(self.path)
        second = VaultStore(self.path)
        first.acquire_lock()
        try:
            with self.assertRaises(VaultBusyError):
                second.acquire_lock()
        finally:
            first.release_lock()
        second.acquire_lock()
        second.release_lock()

    def test_export_copy_and_permissions(self) -> None:
        session = self.make_session()
        session.vault.add(new_password_item(title="A", password="secret"))
        session.save()
        backup = Path(self.tmp.name) / "backup" / "vault-backup.shk"
        session.export_backup(backup)
        self.assertTrue(backup.exists())
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(backup.read_bytes(), self.path.read_bytes())
        with self.assertRaises(VaultError):
            session.export_backup(self.path)
        session.lock()

    def test_import_replaces_store(self) -> None:
        source = self.make_session()
        source.vault.add(new_password_item(title="Imported", password="secret"))
        source.save()
        backup = Path(self.tmp.name) / "backup.shk"
        source.export_backup(backup)
        source.lock()

        target_path = Path(self.tmp.name) / "target.shk"
        target_store = VaultStore(target_path)
        target = VaultSession.create(target_store, MASTER)
        target.vault.add(new_password_item(title="Old", password="old"))
        target.save()
        target.lock()

        data = backup.read_bytes()
        imported = VaultSession.import_from(target_store, data, MASTER)
        titles = {item.title for item in imported.vault.items.values()}
        self.assertEqual(titles, {"Imported"})
        # Import must re-encrypt with the current Argon2id profile.
        self.assertEqual(imported._kdf.memory_kib, 64 * 1024)
        self.assertNotEqual(target_path.read_bytes(), data)
        imported.lock()

        # The pre-import vault must be preserved as an encrypted .bak file.
        backups = sorted(target_path.parent.glob(target_path.name + ".bak-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)
        old_store = VaultStore(backups[0])
        old_session = VaultSession.unlock(old_store, MASTER)
        self.assertEqual(
            {item.title for item in old_session.vault.items.values()}, {"Old"}
        )
        old_session.lock()
        reopened = VaultSession.unlock(target_store, MASTER)
        self.assertEqual({item.title for item in reopened.vault.items.values()}, {"Imported"})
        reopened.lock()

    def test_import_wrong_password_does_not_replace(self) -> None:
        target = self.make_session()
        target.vault.add(new_password_item(title="Keep", password="secret"))
        target.save()
        target.lock()
        before = self.path.read_bytes()

        source_path = Path(self.tmp.name) / "source.shk"
        source_store = VaultStore(source_path)
        source = VaultSession.create(source_store, NEW_MASTER)
        source.vault.add(new_password_item(title="Other", password="other"))
        source.save()
        blob = source_path.read_bytes()
        source.lock()

        with self.assertRaises(InvalidPasswordError):
            VaultSession.import_from(self.store, blob, MASTER)
        self.assertEqual(self.path.read_bytes(), before)
        reopened = VaultSession.unlock(self.store, MASTER)
        self.assertEqual({item.title for item in reopened.vault.items.values()}, {"Keep"})
        reopened.lock()


class SessionTests(VaultTestCase):
    def test_lock_zeroes_key(self) -> None:
        session = self.make_session()
        key_ref = session._key
        self.assertIsNotNone(key_ref)
        session.lock()
        self.assertTrue(session.is_locked)
        self.assertEqual(bytes(key_ref), b"\x00" * 32)

    def test_change_password(self) -> None:
        session = self.make_session()
        session.vault.add(new_password_item(title="A", password="secret"))
        session.save()
        with self.assertRaises(InvalidPasswordError):
            session.change_password("wrong", NEW_MASTER)
        session.change_password(MASTER, NEW_MASTER)
        session.lock()
        with self.assertRaises(InvalidPasswordError):
            VaultSession.unlock(self.store, MASTER)
        reopened = VaultSession.unlock(self.store, NEW_MASTER)
        self.assertEqual(len(reopened.vault.items), 1)
        reopened.lock()

    def test_concurrent_save_and_change_password(self) -> None:
        session = self.make_session()
        session.vault.add(new_password_item(title="A", password="secret"))
        session.save()
        errors: list[Exception] = []

        def saver() -> None:
            try:
                for _ in range(5):
                    session.save()
            except Exception as exc:  # pragma: no cover - failure detail
                errors.append(exc)

        worker = threading.Thread(target=saver)
        worker.start()
        session.change_password(MASTER, NEW_MASTER)
        worker.join()
        self.assertEqual(errors, [])
        session.lock()
        reopened = VaultSession.unlock(self.store, NEW_MASTER)
        self.assertEqual({item.title for item in reopened.vault.items.values()}, {"A"})
        reopened.lock()

    def test_settings_persist_and_validate(self) -> None:
        session = self.make_session()
        session.update_settings(auto_lock_seconds=900, clipboard_seconds=30)
        session.lock()
        reopened = VaultSession.unlock(self.store, MASTER)
        self.assertEqual(reopened.settings["auto_lock_seconds"], 900)
        self.assertEqual(reopened.settings["clipboard_seconds"], 30)
        with self.assertRaises(VaultError):
            reopened.update_settings(auto_lock_seconds=123)
        with self.assertRaises(VaultError):
            reopened.update_settings(clipboard_seconds=999)
        reopened.lock()

    def test_corrupt_authenticated_payload_is_rejected(self) -> None:
        session = self.make_session()
        payload = session.vault.to_payload()
        payload["items"] = [{"kind": "password", "id": "bad"}]
        key = session._key
        assert key is not None
        blob = seal(payload, key, kdf=session._kdf, vault_id=session.vault_id)
        self.path.write_bytes(blob)
        session.lock()
        with self.assertRaises(CorruptVaultError):
            VaultSession.unlock(self.store, MASTER)

    def test_duplicate_ids_are_rejected(self) -> None:
        session = self.make_session()
        item = new_password_item(title="A", password="secret")
        payload = session.vault.to_payload()
        payload["items"] = [item.to_dict(), item.to_dict()]
        key = session._key
        assert key is not None
        self.path.write_bytes(seal(payload, key, kdf=session._kdf, vault_id=session.vault_id))
        session.lock()
        with self.assertRaises(CorruptVaultError):
            VaultSession.unlock(self.store, MASTER)

    def test_lock_is_idempotent(self) -> None:
        session = self.make_session()
        session.lock()
        session.lock()
        self.assertTrue(session.is_locked)
        with self.assertRaises(Exception):
            _ = session.vault


class BackupReaderTests(unittest.TestCase):
    def test_reads_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "backup.shk"
            path.write_bytes(b"encrypted")
            self.assertEqual(read_backup_file(path), b"encrypted")

    def test_rejects_large_file_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "huge.shk"
            with open(path, "wb") as handle:
                handle.truncate(MAX_BACKUP_BYTES + 1)
            with self.assertRaises(VaultError):
                read_backup_file(path)

    def test_rejects_fifo_without_blocking(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fifo.shk"
            os.mkfifo(path)
            with self.assertRaises(VaultError):
                read_backup_file(path)

    def test_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.shk"
            real.write_bytes(b"data")
            link = Path(tmp) / "link.shk"
            link.symlink_to(real)
            with self.assertRaises(VaultError):
                read_backup_file(link)

    def test_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(VaultError):
                read_backup_file(Path(tmp) / "missing.shk")


class VaultModelTests(unittest.TestCase):
    def test_sorting_favorites_and_search(self) -> None:
        vault = Vault.new()
        vault.add(new_password_item(title="Beta", username="b", tags=["work"]))
        vault.add(new_password_item(title="Alpha", favorite=True))
        vault.add(new_card_item(title="Card", number="4111111111111111", expiry_month=1, expiry_year=2030))
        ordered = vault.sorted_items()
        self.assertEqual(ordered[0].title, "Alpha")
        self.assertEqual([item.title for item in vault.sorted_items("work")], ["Beta"])
        self.assertEqual([item.title for item in vault.sorted_items("1111")], ["Card"])
        self.assertEqual([item.title for item in vault.sorted_items(kind="card")], ["Card"])

    def test_settings_validation(self) -> None:
        vault = Vault.new()
        vault.update_settings(auto_lock_seconds=60)
        with self.assertRaises(VaultError):
            vault.update_settings(auto_lock_seconds=61)
        with self.assertRaises(VaultError):
            vault.update_settings(clipboard_seconds=4)

    def test_item_count_pluralisation(self) -> None:
        self.assertEqual(format_item_count(0), "0 записей")
        self.assertEqual(format_item_count(1), "1 запись")
        self.assertEqual(format_item_count(2), "2 записи")
        self.assertEqual(format_item_count(5), "5 записей")
        self.assertEqual(format_item_count(21), "21 запись")
        self.assertEqual(format_item_count(22), "22 записи")


if __name__ == "__main__":
    unittest.main()
