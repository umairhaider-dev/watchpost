from __future__ import annotations

import pytest
from argon2 import PasswordHasher

from watchpost.core.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    WeakPasswordError,
    check_password_policy,
    hash_password,
    needs_rehash,
    verify_password,
)

PASSWORD = "correct-horse-battery"


def test_hash_and_verify() -> None:
    hashed = hash_password(PASSWORD)

    assert hashed.startswith("$argon2id$")
    assert PASSWORD not in hashed
    assert verify_password(hashed, PASSWORD)
    assert not verify_password(hashed, PASSWORD + "!")


def test_each_hash_is_salted() -> None:
    assert hash_password(PASSWORD) != hash_password(PASSWORD)


def test_malformed_hashes_never_match() -> None:
    assert not verify_password("not-a-hash", PASSWORD)
    assert not verify_password("", PASSWORD)


@pytest.mark.parametrize(
    "password", ["x" * (MIN_PASSWORD_LENGTH - 1), "x" * (MAX_PASSWORD_LENGTH + 1)]
)
def test_policy_rejects_short_and_huge_passwords(password: str) -> None:
    with pytest.raises(WeakPasswordError):
        check_password_policy(password)
    with pytest.raises(WeakPasswordError):
        hash_password(password)


def test_weaker_hashes_need_rehashing() -> None:
    weak = PasswordHasher(time_cost=1, memory_cost=8 * 1024).hash(PASSWORD)

    assert needs_rehash(weak)
    assert not needs_rehash(hash_password(PASSWORD))
