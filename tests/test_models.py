import unittest
import uuid
from datetime import datetime, timezone

from shkatulka.models import (
    CardItem,
    PasswordItem,
    ValidationError,
    clean_tags,
    clean_title,
    detect_brand,
    format_pan,
    item_from_dict,
    luhn_valid,
    masked_pan,
    new_card_item,
    new_password_item,
    normalise_pan,
    validate_expiry,
)


class PanTests(unittest.TestCase):
    def test_luhn(self) -> None:
        self.assertTrue(luhn_valid("4111111111111111"))
        self.assertTrue(luhn_valid("5555555555554444"))
        self.assertTrue(luhn_valid("378282246310005"))
        self.assertFalse(luhn_valid("4111111111111112"))
        self.assertFalse(luhn_valid("not-digits"))

    def test_normalise_pan(self) -> None:
        self.assertEqual(normalise_pan("4111 1111-1111 1111"), "4111111111111111")
        with self.assertRaises(ValidationError):
            normalise_pan("4111 1111 1111 1112")
        with self.assertRaises(ValidationError):
            normalise_pan("123")
        with self.assertRaises(ValidationError):
            normalise_pan("4111abcd11111111")

    def test_brand_detection(self) -> None:
        self.assertEqual(detect_brand("4111111111111111"), "Visa")
        self.assertEqual(detect_brand("5555555555554444"), "Mastercard")
        self.assertEqual(detect_brand("2221000000000009"), "Mastercard")
        self.assertEqual(detect_brand("2200000000000004"), "МИР")
        self.assertEqual(detect_brand("378282246310005"), "American Express")
        self.assertEqual(detect_brand("6011111111111117"), "Discover")
        self.assertEqual(detect_brand("3530111333300000"), "JCB")
        self.assertEqual(detect_brand("6211111111111111"), "UnionPay")
        self.assertEqual(detect_brand("9999999999999999"), "Карта")

    def test_masking_and_formatting(self) -> None:
        self.assertEqual(masked_pan("4111111111111111"), "•••• 1111")
        self.assertEqual(format_pan("4111111111111111"), "4111 1111 1111 1111")
        self.assertEqual(format_pan("378282246310005"), "3782 822463 10005")
        self.assertNotIn("4111", masked_pan("4111111111111111"))


class ExpiryTests(unittest.TestCase):
    def test_valid(self) -> None:
        self.assertEqual(validate_expiry(12, 2030), (12, 2030))

    def test_invalid(self) -> None:
        for month, year in ((0, 2030), (13, 2030), (12, 1999), (12, 2101), (True, 2030)):
            with self.assertRaises(ValidationError):
                validate_expiry(month, year)


class TagTitleTests(unittest.TestCase):
    def test_tags_are_trimmed_and_deduplicated(self) -> None:
        self.assertEqual(clean_tags(" work, dev, Work ,, "), ["work", "dev"])

    def test_tag_limits(self) -> None:
        with self.assertRaises(ValidationError):
            clean_tags(["x" * 33])
        with self.assertRaises(ValidationError):
            clean_tags([str(i) for i in range(11)])

    def test_title_control_chars(self) -> None:
        with self.assertRaises(ValidationError):
            clean_title("bad\x00title")
        with self.assertRaises(ValidationError):
            clean_title("   ")
        with self.assertRaises(ValidationError):
            clean_title("x" * 121)

    def test_bidi_override_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            clean_title("bank\u202egnp.exe")
        with self.assertRaises(ValidationError):
            clean_tags(["safe\u2066link"])


class ItemTests(unittest.TestCase):
    def test_password_roundtrip(self) -> None:
        item = new_password_item(
            title="GitHub",
            username="octocat",
            password="s3cret",
            url="https://github.com",
            notes="2FA on",
            tags=["work", "dev"],
            favorite=True,
        )
        data = item.to_dict()
        loaded = item_from_dict(data)
        self.assertIsInstance(loaded, PasswordItem)
        self.assertEqual(loaded.to_dict(), data)
        self.assertEqual(loaded.subtitle, "octocat")
        self.assertIn("github", loaded.search_text)

    def test_card_roundtrip(self) -> None:
        item = new_card_item(
            title="Visa",
            cardholder="IVAN IVANOV",
            number="4111 1111 1111 1111",
            expiry_month=12,
            expiry_year=2030,
            notes="Travel",
            tags=["bank"],
            favorite=False,
        )
        data = item.to_dict()
        loaded = item_from_dict(data)
        self.assertIsInstance(loaded, CardItem)
        self.assertEqual(loaded.number, "4111111111111111")
        self.assertEqual(loaded.brand, "Visa")
        self.assertFalse(loaded.is_expired)
        self.assertIn("1111", loaded.search_text)
        self.assertNotIn("4111111111111111", loaded.subtitle)

    def test_expired_card(self) -> None:
        item = new_card_item(
            title="Old",
            number="4111111111111111",
            expiry_month=1,
            expiry_year=2000,
        )
        self.assertTrue(item.is_expired)

    def test_unknown_kind(self) -> None:
        with self.assertRaises(ValidationError):
            item_from_dict({"kind": "note"})

    def test_duplicate_id_validation_is_not_in_model(self) -> None:
        item = new_password_item(title="A")
        with self.assertRaises(ValidationError):
            PasswordItem.from_dict({**item.to_dict(), "id": "not-a-uuid"})

    def test_id_is_uuid4(self) -> None:
        item = new_password_item(title="A")
        self.assertEqual(uuid.UUID(item.id).version, 4)

    def test_no_cvv_field(self) -> None:
        self.assertNotIn("cvv", CardItem.__dataclass_fields__)
        self.assertNotIn("cvc", CardItem.__dataclass_fields__)
        self.assertNotIn("pin", CardItem.__dataclass_fields__)

    def test_repr_redacts_secrets(self) -> None:
        password = new_password_item(title="Mail", username="user", password="TOPSECRET")
        card = new_card_item(
            title="Visa",
            cardholder="IVAN",
            number="4111111111111111",
            expiry_month=12,
            expiry_year=2030,
        )
        self.assertNotIn("TOPSECRET", repr(password))
        self.assertNotIn("4111111111111111", repr(card))
        self.assertNotIn("user", repr(password))


if __name__ == "__main__":
    unittest.main()
