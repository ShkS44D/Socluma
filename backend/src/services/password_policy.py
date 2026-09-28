from __future__ import annotations

from src.core.config import get_settings


settings = get_settings()

COMMON_PASSWORDS = {
    "password",
    "password123",
    "password123!",
    "qwerty123",
    "admin123",
    "letmein",
    "welcome123",
    "changeme",
    "vigilantai",
}


class PasswordPolicyError(ValueError):
    pass


def validate_new_password(password: str, *, email: str | None = None, full_name: str | None = None) -> None:
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters")
    if len(password) > settings.PASSWORD_MAX_LENGTH:
        raise PasswordPolicyError(f"Password must not exceed {settings.PASSWORD_MAX_LENGTH} characters")
    normalized = password.casefold().strip()
    if normalized in COMMON_PASSWORDS:
        raise PasswordPolicyError("Choose a less common password or a longer passphrase")
    if email:
        local = email.split("@", 1)[0].casefold()
        if len(local) >= 3 and local in normalized:
            raise PasswordPolicyError("Password must not contain your email name")
    if full_name:
        words = [word.casefold() for word in full_name.split() if len(word) >= 3]
        if any(word in normalized for word in words):
            raise PasswordPolicyError("Password must not contain your name")
    # Passphrases are accepted. Shorter passwords must demonstrate basic
    # character diversity without imposing arbitrary composition on long ones.
    if len(password) < 16:
        categories = sum(
            (
                any(char.islower() for char in password),
                any(char.isupper() for char in password),
                any(char.isdigit() for char in password),
                any(not char.isalnum() for char in password),
            )
        )
        if categories < 3:
            raise PasswordPolicyError("Use a longer passphrase or at least three character types")
