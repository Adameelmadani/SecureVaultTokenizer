import re
from ff3 import FF3Cipher

DIGITS = "0123456789"
EMAIL_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-"
TWEAKS = {"CREDIT_CARD": "D8E7920AFA330A", "PHONE": "9A768A92F60E1B", "EMAIL": "4772D1F7A1E65C"}

def is_luhn_valid(number: str) -> bool:
    digits = re.sub(r"\D", "", number); total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char); value = value * 2 - 9 if index % 2 and value > 4 else value * 2 if index % 2 else value; total += value
    return len(digits) >= 12 and total % 10 == 0

def _check_digit(prefix: str) -> str:
    return next(digit for digit in DIGITS if is_luhn_valid(prefix + digit))

def _cipher(key: str, data_type: str, alphabet: str) -> FF3Cipher:
    if len(key) != 64 or any(char not in "0123456789abcdefABCDEF" for char in key): raise ValueError("FPE key must be a 256-bit hexadecimal key")
    return FF3Cipher.withCustomAlphabet(key, TWEAKS[data_type], alphabet)

def _restore_format(source: str, digits: str) -> str:
    iterator = iter(digits); return "".join(next(iterator) if char.isdigit() else char for char in source)

def tokenize_value(value: str, data_type: str, key: str) -> str:
    cleaned = value.strip()
    if data_type == "CREDIT_CARD":
        if not is_luhn_valid(cleaned): raise ValueError("Invalid credit card number")
        digits = re.sub(r"\D", "", cleaned); encrypted = _cipher(key, data_type, DIGITS).encrypt(digits[:-1])
        return _restore_format(cleaned, encrypted + _check_digit(encrypted))
    if data_type == "PHONE":
        digits = re.sub(r"\D", "", cleaned)
        if len(digits) < 6: raise ValueError("Phone numbers must contain at least 6 digits")
        return _restore_format(cleaned, _cipher(key, data_type, DIGITS).encrypt(digits))
    if data_type == "EMAIL":
        if cleaned.count("@") != 1: raise ValueError("Invalid email address")
        local, domain = cleaned.split("@")
        if len(local) < 4 or any(char not in EMAIL_ALPHABET for char in local): raise ValueError("Unsupported email local part")
        return f"{_cipher(key, data_type, EMAIL_ALPHABET).encrypt(local)}@{domain}"
    raise ValueError("Unsupported format type")
