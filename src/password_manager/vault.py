from __future__ import annotations

import base64
import contextlib
import json
import os
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, UTC
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from password_manager.constants import (
    ARGON2_MEMORY_KIB_PER_LANE_MIN,
    ARGON2_PARALLELISM_MIN,
    ARGON2_TIME_COST_MIN,
    CIPHER_KEY_CIPHERTEXT,
    CIPHER_KEY_NAME,
    CIPHER_KEY_NONCE,
    CIPHER_NAME_AES_256_GCM,
    KDF_KEY_MEMORY_COST,
    KDF_KEY_NAME,
    KDF_KEY_PARALLELISM,
    KDF_KEY_SALT,
    KDF_KEY_TIME_COST,
    KDF_NAME_ARGON2ID,
    KEY_LENGTH_BYTES,
    VAULT_FILE_MODE,
    VAULT_FORMAT_VERSION,
    VAULT_KEY_CIPHER,
    VAULT_KEY_KDF,
    VAULT_KEY_VERSION,
)

from password_manager.crypto import (
    KdfParameters,
    decrypt,
    derive_key,
    encrypt,
    generate_salt,
)


try:
    import fcntl as _fcntl
except ImportError:
    _fcntl = None


class VaultError(Exception):
    pass


class VaultNotFoundError(VaultError):
    pass


class VaultAlreadyExistsError(VaultError):
    pass


class VaultFormatError(VaultError):
    pass


class EntryNotFoundError(VaultError):
    pass


class EntryAlreadyExistsError(VaultError):
    pass


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise VaultFormatError(f"Invalid base64 in vault: {exc}") from exc


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _validate_entry_name(name: str) -> None:
    if not name or not name.strip():
        raise ValueError("Entry name cannot be empty or whitespace")

    if name != name.strip():
        raise ValueError(
            "Entry name must not have leading or trailing whitespace"
        )


@contextlib.contextmanager
def _file_lock(target_path: Path) -> Iterator[None]:
    if _fcntl is None:
        yield
        return

    lock_path = target_path.with_suffix(target_path.suffix + ".lock")

    target_path.parent.mkdir(parents=True, exist_ok=True)

    fd = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT,
        VAULT_FILE_MODE,
    )

    try:
        _fcntl.flock(fd, _fcntl.LOCK_EX)

        try:
            yield
        finally:
            _fcntl.flock(fd, _fcntl.LOCK_UN)

    finally:
        os.close(fd)


@dataclass(slots=True, frozen=True)
class Entry:
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Entry":
        try:
            username = data["username"]
            password = data["password"]
        except KeyError as exc:
            raise VaultFormatError(
                f"Entry missing required field: {exc}"
            ) from exc

        if not isinstance(username, str) or not isinstance(password, str):
            raise VaultFormatError(
                "Entry username and password must be strings"
            )

        return cls(
            username=username,
            password=password,
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


@dataclass(slots=True)
class UnlockedVault:
    path: Path
    salt: bytes
    kdf_parameters: KdfParameters
    key: bytes
    entries: dict[str, Entry]

    @classmethod
    def create(
        cls,
        path: Path,
        master_password: str,
        *,
        kdf_parameters: KdfParameters | None = None,
    ) -> Self:
        if path.exists():
            raise VaultAlreadyExistsError(
                f"Vault already exists at {path}"
            )

        salt = generate_salt()

        kdf_parameters = (
            kdf_parameters or KdfParameters.defaults()
        )

        key = derive_key(
            master_password,
            salt,
            kdf_parameters,
        )

        vault = cls(
            path=path,
            salt=salt,
            kdf_parameters=kdf_parameters,
            key=key,
            entries={},
        )

        vault.save()

        return vault

    @classmethod
    def unlock(
        cls,
        path: Path,
        master_password: str,
    ) -> Self:
        if not path.exists():
            raise VaultNotFoundError(
                f"No vault at {path}"
            )

        try:
            envelope = json.loads(
                path.read_text(encoding="utf-8")
            )
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise VaultFormatError(
                f"Vault file at {path} is not valid JSON: {exc}"
            ) from exc

        salt, kdf_parameters, nonce, ciphertext = _parse_envelope(
            envelope
        )

        key = derive_key(
            master_password,
            salt,
            kdf_parameters,
        )

        plaintext_bytes = decrypt(
            ciphertext,
            nonce,
            key,
        )

        try:
            entries_data = json.loads(
                plaintext_bytes.decode("utf-8")
            )
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise VaultFormatError(
                f"Decrypted plaintext is not valid JSON: {exc}"
            ) from exc

        entries = {
            name: Entry.from_dict(row)
            for name, row in entries_data.items()
        }

        return cls(
            path=path,
            salt=salt,
            kdf_parameters=kdf_parameters,
            key=key,
            entries=entries,
        )

    def save(self) -> None:
        entries_json = json.dumps(
            {
                name: entry.to_dict()
                for name, entry in self.entries.items()
            },
            sort_keys=True,
            indent=2,
        ).encode("utf-8")

        nonce, ciphertext = encrypt(
            entries_json,
            self.key,
        )

        envelope = _build_envelope(
            salt=self.salt,
            kdf_parameters=self.kdf_parameters,
            nonce=nonce,
            ciphertext=ciphertext,
        )

        envelope_bytes = json.dumps(
            envelope,
            indent=2,
        ).encode("utf-8")

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with _file_lock(self.path):
            self._atomic_write(envelope_bytes)

    def _atomic_write(
        self,
        envelope_bytes: bytes,
    ) -> None:
        tmp_path = self.path.with_suffix(
            self.path.suffix + ".tmp"
        )

        fd = os.open(
            tmp_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            VAULT_FILE_MODE,
        )

        try:
            try:
                os.write(
                    fd,
                    envelope_bytes,
                )

                os.fsync(fd)

            finally:
                os.close(fd)

            os.replace(
                tmp_path,
                self.path,
            )

        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_path)

            raise

        if os.name != "nt":
            dir_fd = os.open(
                self.path.parent,
                os.O_RDONLY,
            )

            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    def names(self) -> list[str]:
        return sorted(self.entries.keys())

    def get_entry(self, name: str) -> Entry:
        try:
            return self.entries[name]
        except KeyError as exc:
            raise EntryNotFoundError(
                f"No entry named: {name}"
            ) from exc

    def add_entry(
        self,
        name: str,
        entry: Entry,
        *,
        force: bool = False,
    ) -> None:
        _validate_entry_name(name)

        if name in self.entries and not force:
            raise EntryAlreadyExistsError(
                f"Entry already exists: {name}"
            )

        if name in self.entries:
            old = self.entries[name]

            entry = replace(
                entry,
                created_at=old.created_at,
                updated_at=_now_iso(),
            )

        self.entries[name] = entry

    def delete_entry(self, name: str) -> Entry:
        try:
            return self.entries.pop(name)
        except KeyError as exc:
            raise EntryNotFoundError(
                f"No entry named: {name}"
            ) from exc

    def change_master_password(
        self,
        new_master_password: str,
        *,
        kdf_parameters: KdfParameters | None = None,
    ) -> None:
        if not new_master_password:
            raise ValueError(
                "new_master_password must not be empty"
            )

        new_salt = generate_salt()

        new_kdf_parameters = (
            kdf_parameters or KdfParameters.defaults()
        )

        new_key = derive_key(
            new_master_password,
            new_salt,
            new_kdf_parameters,
        )

        self.salt = new_salt
        self.kdf_parameters = new_kdf_parameters
        self.key = new_key

    def close(self) -> None:
        self.entries = {}
        self.key = bytes(KEY_LENGTH_BYTES)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


def _build_envelope(
    salt: bytes,
    kdf_parameters: KdfParameters,
    nonce: bytes,
    ciphertext: bytes,
) -> dict[str, Any]:
    return {
        VAULT_KEY_VERSION: VAULT_FORMAT_VERSION,
        VAULT_KEY_KDF: {
            KDF_KEY_NAME: KDF_NAME_ARGON2ID,
            KDF_KEY_SALT: _b64encode(salt),
            KDF_KEY_TIME_COST: kdf_parameters.time_cost,
            KDF_KEY_MEMORY_COST: kdf_parameters.memory_cost,
            KDF_KEY_PARALLELISM: kdf_parameters.parallelism,
        },
        VAULT_KEY_CIPHER: {
            CIPHER_KEY_NAME: CIPHER_NAME_AES_256_GCM,
            CIPHER_KEY_NONCE: _b64encode(nonce),
            CIPHER_KEY_CIPHERTEXT: _b64encode(ciphertext),
        },
    }


def _parse_envelope(
    envelope: dict[str, Any],
) -> tuple[bytes, KdfParameters, bytes, bytes]:
    if not isinstance(envelope, dict):
        raise VaultFormatError(
            "Vault envelope is not a JSON object"
        )

    version = envelope.get(VAULT_KEY_VERSION)

    if version != VAULT_FORMAT_VERSION:
        raise VaultFormatError(
            f"Unsupported vault version: {version} "
            f"(this build supports version {VAULT_FORMAT_VERSION})"
        )

    kdf = envelope.get(VAULT_KEY_KDF)
    cipher = envelope.get(VAULT_KEY_CIPHER)

    if not isinstance(kdf, dict) or not isinstance(cipher, dict):
        raise VaultFormatError(
            "Vault envelope missing kdf or cipher section"
        )

    if kdf.get(KDF_KEY_NAME) != KDF_NAME_ARGON2ID:
        raise VaultFormatError(
            f"Unsupported KDF: {kdf.get(KDF_KEY_NAME)}"
        )

    try:
        salt = _b64decode(
            kdf[KDF_KEY_SALT]
        )

        kdf_parameters = KdfParameters(
            time_cost=int(kdf[KDF_KEY_TIME_COST]),
            memory_cost=int(kdf[KDF_KEY_MEMORY_COST]),
            parallelism=int(kdf[KDF_KEY_PARALLELISM]),
        )

    except (KeyError, TypeError, ValueError) as exc:
        raise VaultFormatError(
            f"Invalid KDF section: {exc}"
        ) from exc

    if kdf_parameters.time_cost < ARGON2_TIME_COST_MIN:
        raise VaultFormatError(
            f"Invalid Argon2 time_cost: "
            f"{kdf_parameters.time_cost} "
            f"(minimum {ARGON2_TIME_COST_MIN})"
        )

    if kdf_parameters.parallelism < ARGON2_PARALLELISM_MIN:
        raise VaultFormatError(
            f"Invalid Argon2 parallelism: "
            f"{kdf_parameters.parallelism} "
            f"(minimum {ARGON2_PARALLELISM_MIN})"
        )

    memory_floor = (
        ARGON2_MEMORY_KIB_PER_LANE_MIN
        * kdf_parameters.parallelism
    )

    if kdf_parameters.memory_cost < memory_floor:
        raise VaultFormatError(
            f"Invalid Argon2 memory_cost: "
            f"{kdf_parameters.memory_cost} KiB "
            f"(minimum {memory_floor} KiB for "
            f"parallelism={kdf_parameters.parallelism})"
        )

    if cipher.get(CIPHER_KEY_NAME) != CIPHER_NAME_AES_256_GCM:
        raise VaultFormatError(
            f"Unsupported cipher: {cipher.get(CIPHER_KEY_NAME)}"
        )

    try:
        nonce = _b64decode(
            cipher[CIPHER_KEY_NONCE]
        )

        ciphertext = _b64decode(
            cipher[CIPHER_KEY_CIPHERTEXT]
        )

    except KeyError as exc:
        raise VaultFormatError(
            f"Cipher section missing field: {exc}"
        ) from exc

    return (
        salt,
        kdf_parameters,
        nonce,
        ciphertext,
    )
