"""
Password Hashing, Validation & OTP Utilities
Uses Werkzeug's built-in memory-hard scrypt hashing (no extra native dependencies).
"""

import hashlib
import re
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


class InvalidEmailError(Exception):
    """Raised when an email address is missing or malformed."""
    pass


class WeakPasswordError(Exception):
    """Raised when a password fails strength requirements."""
    pass


def normalize_and_validate_email(email: str) -> str:
    if not email or not isinstance(email, str):
        raise InvalidEmailError("Please enter a valid email address.")
    cleaned = email.strip().lower()
    if len(cleaned) > 254 or not EMAIL_REGEX.match(cleaned):
        raise InvalidEmailError("Please enter a valid email address.")
    return cleaned


def validate_password_strength(password: str) -> None:
    if not password or not isinstance(password, str):
        raise WeakPasswordError("Password is required.")
    if len(password) < 8:
        raise WeakPasswordError("Password must be at least 8 characters long.")
    if len(password) > 128:
        raise WeakPasswordError("Password must be 128 characters or fewer.")
    has_letter = any(ch.isalpha() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    if not (has_letter and has_digit):
        raise WeakPasswordError("Password must include at least one letter and one number.")


def hash_password(password: str) -> str:
    """Hashes a plaintext password with salted scrypt."""
    return generate_password_hash(password, method="scrypt")


def verify_password(password_hash: str, password: str) -> bool:
    """Constant-time verification of a plaintext password against a stored hash."""
    if not password_hash or not password:
        return False
    return check_password_hash(password_hash, password)


def generate_otp_code(length: int = 6) -> str:
    """Generates a cryptographically secure numeric OTP (default 6 digits)."""
    upper = 10 ** length
    return f"{secrets.randbelow(upper):0{length}d}"


def hash_otp_code(otp: str) -> str:
    """Hashes an OTP with SHA-256 before storing or comparing in PostgreSQL."""
    return hashlib.sha256(str(otp).strip().encode("utf-8")).hexdigest()
