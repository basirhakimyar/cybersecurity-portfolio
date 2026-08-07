import unittest
from password_checker import PasswordStrengthChecker


class TestPasswordStrengthChecker(unittest.TestCase):

    def setUp(self):
        self.user = "TestUser"

    def test_strong_password(self):
        checker = PasswordStrengthChecker(self.user, "K!m7Q#v2R@x9")
        report = checker.password_analyzer()
        self.assertIn("Overall Strength: Very Strong", report)
        self.assertIn("Final Score: 100/100", report)

    def test_common_password(self):
        report = PasswordStrengthChecker(self.user, "password123").password_analyzer()
        self.assertIn("Overall Strength: Weak", report)
        self.assertIn("CRITICAL: This is a very common password!", report)

    def test_too_short_password(self):
        report = PasswordStrengthChecker(self.user, "Ab1!").password_analyzer()
        self.assertIn("Overall Strength: Weak", report)
        self.assertIn("CRITICAL: Password is too short!", report)

    def test_username_inside_password(self):
        report = PasswordStrengthChecker(self.user, "SafeTestUser2026!").password_analyzer()
        self.assertIn("Username appears in password", report)

    def test_repeated_characters(self):
        report = PasswordStrengthChecker(self.user, "Abbb1234!").password_analyzer()
        self.assertIn("Repeated characters detected", report)

    def test_sequential_characters(self):
        report = PasswordStrengthChecker(self.user, "Xabcd9!Z").password_analyzer()
        self.assertIn("Sequential pattern detected", report)

    def test_no_special_character(self):
        report = PasswordStrengthChecker(self.user, "PureUpperLower123").password_analyzer()
        self.assertIn("Has Special Characters: ❌", report)

    def test_no_uppercase(self):
        report = PasswordStrengthChecker(self.user, "lowercase123!").password_analyzer()
        self.assertIn("Has Uppercase: ❌", report)

    def test_no_digit(self):
        report = PasswordStrengthChecker(self.user, "NoDigitsLetters!").password_analyzer()
        self.assertIn("Has Digits: ❌", report)

    def test_empty_username(self):
        with self.assertRaises(ValueError):
            PasswordStrengthChecker("", "SomePass123!")

    def test_empty_password(self):
        with self.assertRaises(ValueError):
            PasswordStrengthChecker("SomeUser", "   ")


if __name__ == "__main__":
    unittest.main()
