import secrets

from password_manager.constants import (
    DEFAULT_GENERATED_PASSWORD_LENGTH,
    DIGITS,
    LOWERCASE_LETTERS,
    MINIMUM_GENERATED_PASSWORD_LENGTH,
    SAFE_SYMBOLS,
    UPPERCASE_LETTERS,
)


class PasswordTooShortError(ValueError):
    pass


def generate_password(
    length: int = DEFAULT_GENERATED_PASSWORD_LENGTH,
    *,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    if length < MINIMUM_GENERATED_PASSWORD_LENGTH:
        raise PasswordTooShortError(
            f"Password length must be >= "
            f"{MINIMUM_GENERATED_PASSWORD_LENGTH}, got {length}"
        )

    enabled_pools = {
        "lower": LOWERCASE_LETTERS if use_lowercase else "",
        "upper": UPPERCASE_LETTERS if use_uppercase else "",
        "digit": DIGITS if use_digits else "",
        "symbol": SAFE_SYMBOLS if use_symbols else "",
    }

    enabled_pools = {
        k: v for k, v in enabled_pools.items() if v
    }

    if not enabled_pools:
        raise ValueError("At least one character pool must be enabled")

    if length < len(enabled_pools):
        raise PasswordTooShortError(
            f"length={length} is too small to include one character "
            f"from each of {len(enabled_pools)} enabled pools"
        )

    alphabet = "".join(enabled_pools.values())

    required = [
        secrets.choice(pool)
        for pool in enabled_pools.values()
    ]

    fill_count = length - len(required)

    fill = [
        secrets.choice(alphabet)
        for _ in range(fill_count)
    ]

    chars = required + fill

    _secure_shuffle(chars)

    return "".join(chars)


def _secure_shuffle(items: list[str]) -> None:
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]
