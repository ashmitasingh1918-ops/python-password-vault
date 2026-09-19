from dataclasses import dataclass
import secrets

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from password_manager.constants import (
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    KEY_LENGTH_BYTES,
    NONCE_LENGTH_BYTES,
    SALT_LENGTH_BYTES,
)


class CryptoError(Exception):
    pass


class WrongPasswordError(CryptoError):
    pass


@dataclass(frozen=True, slots=True)
class KdfParameters:
    time_cost: int
    memory_cost: int
    parallelism: int

    @classmethod
    def defaults(cls) -> "KdfParameters":
        return cls(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_KIB,
            parallelism=ARGON2_PARALLELISM,
        )


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_LENGTH_BYTES)


def generate_nonce() -> bytes:
    return secrets.token_bytes(NONCE_LENGTH_BYTES)


def derive_key(
    master_password: str,
    salt: bytes,
    parameters: KdfParameters | None = None,
) -> bytes:
    if not master_password:
        raise ValueError("master_password must not be empty")

    if parameters is None:
        parameters = KdfParameters.defaults()

    password_bytes = master_password.encode("utf-8")

    return hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=parameters.time_cost,
        memory_cost=parameters.memory_cost,
        parallelism=parameters.parallelism,
        hash_len=KEY_LENGTH_BYTES,
        type=Type.ID,
    )


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    cipher = AESGCM(key)
    nonce = generate_nonce()

    ciphertext = cipher.encrypt(
        nonce=nonce,
        data=plaintext,
        associated_data=None,
    )

    return nonce, ciphertext


def decrypt(
    ciphertext: bytes,
    nonce: bytes,
    key: bytes,
) -> bytes:
    cipher = AESGCM(key)

    try:
        return cipher.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=None,
        )
    except InvalidTag as exc:
        raise WrongPasswordError(
            "Decryption failed: wrong master password or corrupted vault"
        ) from exc
