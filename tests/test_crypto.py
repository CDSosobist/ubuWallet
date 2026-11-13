import base64
import json
import secrets
import unittest
import uuid

from shkatulka.crypto import (
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    CorruptVaultError,
    InvalidPasswordError,
    KdfParams,
    derive_key,
    open_envelope,
    seal,
    zero_bytes,
)


def cheap_kdf() -> KdfParams:
    return KdfParams(
        salt=secrets.token_bytes(16),
        time_cost=1,
        memory_kib=16 * 1024,
        parallelism=1,
    )


PAYLOAD = {"schema": 1, "items": [], "title": "Пример", "nested": {"a": [1, 2, 3]}}


class CryptoRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kdf = cheap_kdf()
        self.key = derive_key("correct horse battery staple", self.kdf)
        self.vault_id = str(uuid.uuid4())

    def tearDown(self) -> None:
        zero_bytes(self.key)

    def test_roundtrip_and_metadata(self) -> None:
        blob = seal(PAYLOAD, self.key, kdf=self.kdf, vault_id=self.vault_id)
        self.assertNotIn(b"correct horse", blob)
        self.assertNotIn(b'"title"', blob)
        opened = open_envelope(blob, "correct horse battery staple")
        try:
            self.assertEqual(opened.payload, PAYLOAD)
            self.assertEqual(opened.vault_id, self.vault_id)
            self.assertEqual(opened.kdf, self.kdf)
            self.assertEqual(len(opened.key), 32)
        finally:
            zero_bytes(opened.key)

    def test_wrong_password_is_rejected(self) -> None:
        blob = seal(PAYLOAD, self.key, kdf=self.kdf, vault_id=self.vault_id)
        with self.assertRaises(InvalidPasswordError):
            open_envelope(blob, "wrong password")

    def test_nonce_and_ciphertext_are_fresh(self) -> None:
        first = json.loads(seal(PAYLOAD, self.key, kdf=self.kdf, vault_id=self.vault_id))
        second = json.loads(seal(PAYLOAD, self.key, kdf=self.kdf, vault_id=self.vault_id))
        self.assertNotEqual(first["cipher"]["nonce"], second["cipher"]["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])

    def test_ciphertext_tampering_is_rejected(self) -> None:
        data = json.loads(seal(PAYLOAD, self.key, kdf=self.kdf, vault_id=self.vault_id))
        raw = bytearray(base64.b64decode(data["ciphertext"]))
        raw[0] ^= 0x01
        data["ciphertext"] = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(InvalidPasswordError):
            open_envelope(json.dumps(data).encode(), "correct horse battery staple")

    def test_header_tampering_is_rejected(self) -> None:
        data = json.loads(seal(PAYLOAD, self.key, kdf=self.kdf, vault_id=self.vault_id))
        data["kdf"]["time_cost"] = 2
        with self.assertRaises(InvalidPasswordError):
            open_envelope(json.dumps(data).encode(), "correct horse battery staple")

    def test_vault_id_tampering_is_rejected(self) -> None:
        data = json.loads(seal(PAYLOAD, self.key, kdf=self.kdf, vault_id=self.vault_id))
        data["vault_id"] = str(uuid.uuid4())
        with self.assertRaises(InvalidPasswordError):
            open_envelope(json.dumps(data).encode(), "correct horse battery staple")

    def test_utf8_password(self) -> None:
        password = "длинная парольная фраза с эмодзи 🔐 и пробелами"
        key = derive_key(password, self.kdf)
        try:
            blob = seal(PAYLOAD, key, kdf=self.kdf, vault_id=self.vault_id)
            opened = open_envelope(blob, password)
            zero_bytes(opened.key)
            self.assertEqual(opened.payload, PAYLOAD)
        finally:
            zero_bytes(key)

    def test_default_kdf_profile(self) -> None:
        params = KdfParams.generate()
        self.assertEqual(params.time_cost, ARGON2_TIME_COST)
        self.assertEqual(params.memory_kib, ARGON2_MEMORY_KIB)
        self.assertEqual(params.parallelism, ARGON2_PARALLELISM)
        self.assertEqual(len(params.salt), 16)


class CryptoParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kdf = cheap_kdf()
        self.key = derive_key("correct horse battery staple", self.kdf)
        self.vault_id = str(uuid.uuid4())

    def tearDown(self) -> None:
        zero_bytes(self.key)

    def _blob(self) -> dict:
        return json.loads(seal(PAYLOAD, self.key, kdf=self.kdf, vault_id=self.vault_id))

    def test_wrong_format(self) -> None:
        data = self._blob()
        data["format"] = "other"
        with self.assertRaises(CorruptVaultError):
            open_envelope(json.dumps(data).encode(), "x")

    def test_unsupported_version(self) -> None:
        data = self._blob()
        data["version"] = 99
        with self.assertRaises(CorruptVaultError):
            open_envelope(json.dumps(data).encode(), "x")

    def test_huge_kdf_memory_rejected_before_derivation(self) -> None:
        data = self._blob()
        data["kdf"]["memory_kib"] = 1024 * 1024 * 1024
        with self.assertRaises(CorruptVaultError):
            open_envelope(json.dumps(data).encode(), "x")

    def test_bad_salt_base64(self) -> None:
        data = self._blob()
        data["kdf"]["salt"] = "***"
        with self.assertRaises(CorruptVaultError):
            open_envelope(json.dumps(data).encode(), "x")

    def test_duplicate_json_keys_rejected(self) -> None:
        raw = b'{"format":"shkatulka-vault","format":"shkatulka-vault"}'
        with self.assertRaises(CorruptVaultError):
            open_envelope(raw, "x")

    def test_nan_rejected(self) -> None:
        with self.assertRaises(CorruptVaultError):
            open_envelope(b'{"format": NaN}', "x")

    def test_oversized_blob_rejected(self) -> None:
        with self.assertRaises(CorruptVaultError):
            open_envelope(b" " * (32 * 1024 * 1024 + 1), "x")

    def test_ciphertext_minimum_length(self) -> None:
        data = self._blob()
        data["ciphertext"] = base64.b64encode(b"short").decode()
        with self.assertRaises(CorruptVaultError):
            open_envelope(json.dumps(data).encode(), "x")

    def test_missing_ciphertext(self) -> None:
        data = self._blob()
        data.pop("ciphertext")
        with self.assertRaises(CorruptVaultError):
            open_envelope(json.dumps(data).encode(), "x")

    def test_zero_bytes(self) -> None:
        value = bytearray(b"secret-material")
        zero_bytes(value)
        self.assertEqual(value, bytearray(len(value)))

    def test_unlocked_repr_redacts_key(self) -> None:
        key = bytearray(b"K" * 32)
        from shkatulka.crypto import UnlockedVault

        unlocked = UnlockedVault(payload={}, key=key, kdf=self.kdf, vault_id=self.vault_id)
        self.assertNotIn("KKKK", repr(unlocked))
        self.assertIn("redacted", repr(unlocked))


if __name__ == "__main__":
    unittest.main()
