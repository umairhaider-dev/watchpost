"""Password hashing with Argon2id.

Hashes carry their own parameters, so raising the cost later only means
that :func:`needs_rehash` starts returning ``True`` for older hashes.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256

_hasher = PasswordHasher()


class WeakPasswordError(ValueError):
    """The password does not meet the length policy."""


def check_password_policy(password: str) -> None:
    """Raise :class:`WeakPasswordError` unless the password is long enough."""
    if len(password) < MIN_PASSWORD_LENGTH:
        msg = f"passwords must be at least {MIN_PASSWORD_LENGTH} characters"
        raise WeakPasswordError(msg)
    if len(password) > MAX_PASSWORD_LENGTH:
        msg = f"passwords must be at most {MAX_PASSWORD_LENGTH} characters"
        raise WeakPasswordError(msg)


def hash_password(password: str) -> str:
    """Argon2id hash of a password that meets the policy."""
    check_password_policy(password)
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Whether ``password`` matches ``password_hash``; malformed hashes never match."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Whether a stored hash uses weaker parameters than the current ones."""
    return _hasher.check_needs_rehash(password_hash)
