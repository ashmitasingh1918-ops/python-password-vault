import string

import pytest

from password_manager.constants import (
    DIGITS,
    LOWERCASE_LETTERS,
    MINIMUM_GENERATED_PASSWORD_LENGTH,
    SAFE_SYMBOLS,
    UPPERCASE_LETTERS,
)

from password_manager.generator import (
    PasswordTooShortError,
    generate_password,
)


def test_generate_password_default_length_matches_argument() -> None:
    password = generate_password(20)
    assert len(password) == 20


def test_generate_password_below_minimum_raises() -> None:
    with pytest.raises(PasswordTooShortError):
        generate_password(
            MINIMUM_GENERATED_PASSWORD_LENGTH - 1
        )


def test_generate_password_with_no_pools_enabled_raises() -> None:
    with pytest.raises(ValueError):
        generate_password(
            16,
            use_lowercase=False,
            use_uppercase=False,
            use_digits=False,
            use_symbols=False,
        )


def test_generate_password_contains_at_least_one_from_each_pool() -> None:
    password = generate_password(
        16,
        use_lowercase=True,
        use_uppercase=True,
        use_digits=True,
        use_symbols=True,
    )

    assert any(
        c in LOWERCASE_LETTERS
        for c in password
    )

    assert any(
        c in UPPERCASE_LETTERS
        for c in password
    )

    assert any(
        c in DIGITS
        for c in password
    )

    assert any(
        c in SAFE_SYMBOLS
        for c in password
    )


def test_generate_password_only_lowercase_when_others_disabled() -> None:
    password = generate_password(
        16,
        use_lowercase=True,
        use_uppercase=False,
        use_digits=False,
        use_symbols=False,
    )

    assert all(
        c in LOWERCASE_LETTERS
        for c in password
    )


def test_generate_password_excludes_symbols_when_disabled() -> None:
    password = generate_password(
        16,
        use_symbols=False,
    )

    assert not any(
        c in SAFE_SYMBOLS
        for c in password
    )


def test_generate_password_uniqueness_across_calls() -> None:
    passwords = {
        generate_password(16)
        for _ in range(100)
    }

    assert len(passwords) == 100


def test_generate_password_only_uses_expected_alphabet() -> None:
    password = generate_password(32)

    allowed = set(
        LOWERCASE_LETTERS
        + UPPERCASE_LETTERS
        + DIGITS
        + SAFE_SYMBOLS
    )

    assert all(
        c in allowed
        for c in password
    )

    assert not any(
        c in string.whitespace
        for c in password
    )


def test_generate_password_short_request_with_many_pools_raises() -> None:
    password = generate_password(8)

    assert len(password) == 8
