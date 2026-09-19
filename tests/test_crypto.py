import pytest

from password_manager.crypto import (
    KdfParameters,
    WrongPasswordError,
    decrypt,
    derive_key,
    encrypt,
    generate_nonce,
    generate_salt,
)

from password_manager.constants import (
    KEY_LENGTH_BYTES,
    NONCE_LENGTH_BYTES,
    SALT_LENGTH_BYTES,
)

from tests.conftest import TEST_KDF_PARAMETERS


def test_generate_salt_returns_correct_length() -> None:
    salt = generate_salt()
    assert len(salt) == SALT_LENGTH_BYTES


def test_generate_salt_returns_different_values_on_each_call() -> None:
    salts = {generate_salt() for _ in range(50)}
    assert len(salts) == 50


def test_generate_nonce_returns_correct_length() -> None:
    nonce = generate_nonce()
    assert len(nonce) == NONCE_LENGTH_BYTES


def test_generate_nonce_returns_different_values_on_each_call() -> None:
    nonces = {generate_nonce() for _ in range(50)}
    assert len(nonces) == 50


def test_derive_key_returns_correct_length() -> None:
    key = derive_key(
        "password",
        generate_salt(),
        TEST_KDF_PARAMETERS,
    )
    assert len(key) == KEY_LENGTH_BYTES


def test_derive_key_is_deterministic() -> None:
    salt = generate_salt()

    key_a = derive_key(
        "hunter2",
        salt,
        TEST_KDF_PARAMETERS,
    )

    key_b = derive_key(
        "hunter2",
        salt,
        TEST_KDF_PARAMETERS,
    )

    assert key_a == key_b


def test_derive_key_different_passwords_yield_different_keys() -> None:
    salt = generate_salt()

    key_a = derive_key(
        "password-a",
        salt,
        TEST_KDF_PARAMETERS,
    )

    key_b = derive_key(
        "password-b",
        salt,
        TEST_KDF_PARAMETERS,
    )

    assert key_a != key_b


def test_derive_key_different_salts_yield_different_keys() -> None:
    key_a = derive_key(
        "hunter2",
        generate_salt(),
        TEST_KDF_PARAMETERS,
    )

    key_b = derive_key(
        "hunter2",
        generate_salt(),
        TEST_KDF_PARAMETERS,
    )

    assert key_a != key_b


def test_kdf_parameters_defaults_are_immutable() -> None:
    params = KdfParameters.defaults()

    with pytest.raises(AttributeError):
        params.time_cost = 999  # type: ignore[misc]


def test_derive_key_rejects_empty_password() -> None:
    with pytest.raises(ValueError):
        derive_key(
            "",
            generate_salt(),
            TEST_KDF_PARAMETERS,
        )


def test_encrypt_decrypt_round_trip() -> None:
    salt = generate_salt()

    key = derive_key(
        "master",
        salt,
        TEST_KDF_PARAMETERS,
    )

    plaintext = b"the quick brown fox jumps over the lazy dog"

    nonce, ciphertext = encrypt(
        plaintext,
        key,
    )

    recovered = decrypt(
        ciphertext,
        nonce,
        key,
    )

    assert recovered == plaintext


def test_encrypt_produces_fresh_nonce_each_call() -> None:
    salt = generate_salt()

    key = derive_key(
        "master",
        salt,
        TEST_KDF_PARAMETERS,
    )

    plaintext = b"hello"

    nonce1, ct1 = encrypt(
        plaintext,
        key,
    )

    nonce2, ct2 = encrypt(
        plaintext,
        key,
    )

    assert nonce1 != nonce2
    assert ct1 != ct2


def test_encrypt_handles_empty_plaintext() -> None:
    salt = generate_salt()

    key = derive_key(
        "master",
        salt,
        TEST_KDF_PARAMETERS,
    )

    nonce, ciphertext = encrypt(
        b"",
        key,
    )

    assert decrypt(
        ciphertext,
        nonce,
        key,
    ) == b""


def test_decrypt_with_wrong_key_raises_wrong_password_error() -> None:
    salt = generate_salt()

    correct_key = derive_key(
        "correct",
        salt,
        TEST_KDF_PARAMETERS,
    )

    wrong_key = derive_key(
        "wrong",
        salt,
        TEST_KDF_PARAMETERS,
    )

    nonce, ciphertext = encrypt(
        b"secret",
        correct_key,
    )

    with pytest.raises(WrongPasswordError):
        decrypt(
            ciphertext,
            nonce,
            wrong_key,
        )


def test_decrypt_with_modified_ciphertext_raises() -> None:
    salt = generate_salt()

    key = derive_key(
        "master",
        salt,
        TEST_KDF_PARAMETERS,
    )

    nonce, ciphertext = encrypt(
        b"important data",
        key,
    )

    middle = len(ciphertext) // 2

    tampered = bytearray(ciphertext)
    tampered[middle] ^= 0x01

    tampered_bytes = bytes(tampered)

    with pytest.raises(WrongPasswordError):
        decrypt(
            tampered_bytes,
            nonce,
            key,
        )


def test_decrypt_with_modified_nonce_raises() -> None:
    salt = generate_salt()

    key = derive_key(
        "master",
        salt,
        TEST_KDF_PARAMETERS,
    )

    nonce, ciphertext = encrypt(
        b"important data",
        key,
    )

    bad_nonce = bytearray(nonce)
    bad_nonce[0] ^= 0xFF

    with pytest.raises(WrongPasswordError):
        decrypt(
            ciphertext,
            bytes(bad_nonce),
            key,
        )
