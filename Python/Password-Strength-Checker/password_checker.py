import re
from getpass import getpass


class PasswordStrengthChecker:
    def __init__(self, username, password):
        if not isinstance(username, str) or not isinstance(password, str):
            raise TypeError("Username and password must be strings.")
        if not username.strip():
            raise ValueError("Username cannot be empty.")
        if not password.strip():
            raise ValueError("Password cannot be empty.")

        self.__username = username.strip()
        self.__password = password
        self.__common_passwords = {
            "password", "123456", "12345678", "qwerty", "admin", "password123"
        }

    def __is_common_password(self):
        return self.__password.lower() in self.__common_passwords

    def __has_repeated_chars(self):
        return bool(re.search(r"(.)\1\1", self.__password))

    def __has_sequential_patterns(self):
        value = self.__password.lower()
        if len(value) < 4:
            return False

        for i in range(len(value) - 3):
            chars = value[i:i + 4]
            codes = [ord(c) for c in chars]

            ascending = all(codes[j + 1] - codes[j] == 1 for j in range(3))
            descending = all(codes[j] - codes[j + 1] == 1 for j in range(3))

            if ascending or descending:
                return True
        return False

    def password_analyzer(self):
        findings = []

        has_digit = any(c.isdigit() for c in self.__password)
        has_upper = any(c.isupper() for c in self.__password)
        has_lower = any(c.islower() for c in self.__password)
        has_special = any(c in "!@#$%^&*()-_=+[]{};:,.?/\\|" for c in self.__password)
        pass_len = len(self.__password)

        score = 0
        if has_digit:
            score += 20
        if has_upper:
            score += 20
        if has_lower:
            score += 20
        if has_special:
            score += 20

        if pass_len >= 12:
            score += 20
        elif pass_len >= 8:
            score += 10

        if self.__username.lower() in self.__password.lower():
            score -= 20
            findings.append("Username appears in password (-20)")

        if self.__has_repeated_chars():
            score -= 15
            findings.append("Repeated characters detected (e.g. 'aaa') (-15)")

        if self.__has_sequential_patterns():
            score -= 15
            findings.append("Sequential pattern detected (e.g. '1234' or 'dcba') (-15)")

        critical = False

        if self.__is_common_password():
            score = 0
            findings.append("CRITICAL: This is a very common password!")
            critical = True
        elif pass_len < 8:
            score = 0
            findings.append("CRITICAL: Password is too short! Minimum length is 8 characters.")
            critical = True

        score = max(0, min(100, score))

        if score < 50 or critical:
            strength = "Weak"
        elif score < 75:
            strength = "Medium"
        elif score < 90:
            strength = "Strong"
        else:
            strength = "Very Strong"

        if findings:
            issues = "\nIssues/Findings:\n" + "\n".join(f" - {x}" for x in findings)
        else:
            issues = "\nIssues/Findings:\n - None! Clean password. ✅"

        return (
            "--- Password Analysis Report ---\n"
            f"Length: {pass_len}\n"
            f"Has Lowercase: {'✅' if has_lower else '❌'}\n"
            f"Has Uppercase: {'✅' if has_upper else '❌'}\n"
            f"Has Digits: {'✅' if has_digit else '❌'}\n"
            f"Has Special Characters: {'✅' if has_special else '❌'}\n"
            f"Repeated Chars: {'Yes ⚠️' if self.__has_repeated_chars() else 'No ✅'}\n"
            f"Sequential Patterns: {'Yes ⚠️' if self.__has_sequential_patterns() else 'No ✅'}\n"
            f"Contains Username: {'Yes ⚠️' if self.__username.lower() in self.__password.lower() else 'No ✅'}\n"
            "--------------------------------\n"
            f"Final Score: {score}/100\n"
            f"Overall Strength: {strength}"
            f"{issues}"
        )


def main():
    print("=== Welcome to Password Strength Checker ===")
    try:
        user = input("Enter your username: ")
        password = getpass("Enter your password (typing will be hidden): ")
        checker = PasswordStrengthChecker(user, password)
        print("\nEvaluating...\n")
        print(checker.password_analyzer())
    except (ValueError, TypeError) as error:
        print(f"\n❌ Input Error: {error}")
    except KeyboardInterrupt:
        print("\n\n👋 Program closed by user.")


if __name__ == "__main__":
    main()
