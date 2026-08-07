# Password Strength Checker

A Python cybersecurity project that analyzes password strength using a heuristic scoring model.

## Features
- Length analysis
- Upper/lowercase, digit and special-character checks
- Common-password detection
- Username similarity detection
- Repeated-character detection
- Sequential-pattern detection
- 0-100 score and strength classification
- Hidden password input with `getpass`
- Input validation and exception handling
- Unit tests with `unittest`

## Structure
```text
Password-Strength-Checker/
├── password_checker.py
├── README.md
└── tests/
    └── test_password_checker.py
```

## Run
```bash
python password_checker.py
```

## Test
```bash
python -m unittest discover -s tests -v
```

## Scoring
Positive:
- Digit +20
- Uppercase +20
- Lowercase +20
- Special character +20
- Length >=12 +20
- Length 8-11 +10

Deductions:
- Username appears in password -20
- Repeated characters -15
- Sequential pattern -15

Common passwords and passwords shorter than 8 characters are critical weaknesses and receive a final score of 0.

## Disclaimer
This is an educational heuristic analyzer, not a formal security standard. It does not guarantee that a password is secure against every attack and does not store, transmit, hash, or crack passwords.

## Technologies
Python 3, OOP, Regular Expressions, getpass, unittest
