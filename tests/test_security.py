import unittest

from shkatulka.crypto import WeakPasswordError
from shkatulka.security import (
    GeneratorOptions,
    UnlockThrottle,
    generate_password,
    is_blocklisted,
    password_strength,
    sanitize_generator_options,
    validate_master_password,
)


class MasterPasswordPolicyTests(unittest.TestCase):
    def test_accepts_long_passphrase(self) -> None:
        validate_master_password("mango orchard window lantern")
        validate_master_password("correct horse battery staple 42")

    def test_minimum_length(self) -> None:
        with self.assertRaises(WeakPasswordError):
            validate_master_password("short pass")
        validate_master_password("mangowindowlamp")

    def test_blocklist(self) -> None:
        self.assertTrue(is_blocklisted("Password2025!"))
        self.assertTrue(is_blocklisted("  PASSWORD  "))
        with self.assertRaises(WeakPasswordError):
            validate_master_password("password123456789")
        with self.assertRaises(WeakPasswordError):
            validate_master_password("qwertyuiopasdfgh")

    def test_trivial_repetition(self) -> None:
        for value in ("aaaaaaaaaaaaaaaa", "abababababababab", "abcabcabcabcabc"):
            with self.assertRaises(WeakPasswordError):
                validate_master_password(value)

    def test_no_composition_rule(self) -> None:
        validate_master_password("mango orchard window")

    def test_whitespace_only(self) -> None:
        with self.assertRaises(WeakPasswordError):
            validate_master_password(" " * 16)

    def test_max_bytes(self) -> None:
        with self.assertRaises(WeakPasswordError):
            validate_master_password("x" * 1025)

    def test_password_strength_order(self) -> None:
        weak = password_strength("abc")
        medium = password_strength("mango-orchard-window-42")
        strong = password_strength("mango-Orchard!window#42-Lantern")
        self.assertLess(weak.score, medium.score)
        self.assertLessEqual(medium.score, strong.score)
        self.assertEqual(password_strength("password").score, 0)


class GeneratorTests(unittest.TestCase):
    def test_default_length_and_classes(self) -> None:
        for _ in range(20):
            value = generate_password()
            self.assertEqual(len(value), 24)
            self.assertTrue(any(c.islower() for c in value))
            self.assertTrue(any(c.isupper() for c in value))
            self.assertTrue(any(c.isdigit() for c in value))
            self.assertTrue(any(not c.isalnum() for c in value))

    def test_custom_options(self) -> None:
        options = GeneratorOptions(
            length=40,
            use_lower=True,
            use_upper=False,
            use_digits=True,
            use_symbols=False,
        )
        value = generate_password(options)
        self.assertEqual(len(value), 40)
        self.assertTrue(any(c.islower() for c in value))
        self.assertTrue(any(c.isdigit() for c in value))
        self.assertFalse(any(c.isupper() for c in value))
        self.assertFalse(any(not c.isalnum() for c in value))

    def test_ambiguous_characters_excluded(self) -> None:
        options = GeneratorOptions(length=80, avoid_ambiguous=True)
        for _ in range(10):
            value = generate_password(options)
            for char in "O0Il1|`'\"\\ /":
                self.assertNotIn(char, value)

    def test_unique_values(self) -> None:
        values = {generate_password() for _ in range(50)}
        self.assertEqual(len(values), 50)

    def test_invalid_lengths(self) -> None:
        with self.assertRaises(ValueError):
            generate_password(GeneratorOptions(length=7))
        with self.assertRaises(ValueError):
            generate_password(GeneratorOptions(length=129))

    def test_sanitize_options(self) -> None:
        options = sanitize_generator_options(1, False, False, False, False)
        self.assertEqual(options.length, 8)
        self.assertTrue(options.use_lower)
        options = sanitize_generator_options(999, True, True, True, True)
        self.assertEqual(options.length, 128)


class ThrottleTests(unittest.TestCase):
    def test_progressive_delay(self) -> None:
        now = [100.0]
        throttle = UnlockThrottle(clock=lambda: now[0])
        self.assertEqual(throttle.register_failure(), 0)
        self.assertEqual(throttle.register_failure(), 0)
        self.assertEqual(throttle.register_failure(), 2)
        self.assertAlmostEqual(throttle.remaining(), 2)
        now[0] += 2
        self.assertEqual(throttle.remaining(), 0)
        self.assertEqual(throttle.register_failure(), 4)
        for _ in range(6):
            throttle.register_failure()
        self.assertLessEqual(throttle.remaining(), 60)

    def test_reset(self) -> None:
        throttle = UnlockThrottle()
        for _ in range(5):
            throttle.register_failure()
        throttle.reset()
        self.assertEqual(throttle.failures, 0)
        self.assertEqual(throttle.remaining(), 0)


if __name__ == "__main__":
    unittest.main()
