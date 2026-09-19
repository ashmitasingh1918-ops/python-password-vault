import dataclasses
import json
import os
import stat
from pathlib import Path

import pytest

from password_manager.constants import (
    VAULT_FILE_MODE,
    VAULT_FORMAT_VERSION,
)

from password_manager.crypto import WrongPasswordError

from password_manager.vault import (
    Entry,
    EntryAlreadyExistsError,
    EntryNotFoundError,
    UnlockedVault,
    VaultAlreadyExistsError,
    VaultFormatError,
    VaultNotFoundError,
)

from tests.conftest import TEST_KDF_PARAMETERS


def _sample_entry(password: str = "s3cret") -> Entry:
    return Entry(
        username="alice",
        password=password,
        url="https://example.com",
        notes="primary account",
    )


def _create_test_vault(
    path: Path,
    master_password: str,
) -> UnlockedVault:
    return UnlockedVault.create(
        path,
        master_password,
        kdf_parameters=TEST_KDF_PARAMETERS,
    )


def test_create_writes_file_at_path(
    vault_path: Path,
    master_password: str,
) -> None:
    _create_test_vault(vault_path, master_password)
    assert vault_path.exists()


def test_create_refuses_to_overwrite_existing_file(
    vault_path: Path,
    master_password: str,
) -> None:
    _create_test_vault(vault_path, master_password)

    with pytest.raises(VaultAlreadyExistsError):
        _create_test_vault(vault_path, master_password)


def test_create_sets_file_mode_to_0600(
    vault_path: Path,
    master_password: str,
) -> None:
    _create_test_vault(vault_path, master_password)

    mode = stat.S_IMODE(os.stat(vault_path).st_mode)

    if os.name != "nt":
        assert mode == VAULT_FILE_MODE


def test_create_writes_valid_envelope_json(
    vault_path: Path,
    master_password: str,
) -> None:
    _create_test_vault(vault_path, master_password)

    envelope = json.loads(
        vault_path.read_text(encoding="utf-8")
    )

    assert envelope["version"] == VAULT_FORMAT_VERSION
    assert envelope["kdf"]["name"] == "argon2id"
    assert envelope["cipher"]["name"] == "aes-256-gcm"


def test_create_makes_parent_directory_if_missing(
    tmp_path: Path,
    master_password: str,
) -> None:
    nested = (
        tmp_path
        / "deep"
        / "nested"
        / "dir"
        / "vault.json"
    )

    _create_test_vault(nested, master_password)

    assert nested.exists()


def test_create_rejects_empty_master_password(
    vault_path: Path,
) -> None:
    with pytest.raises(ValueError):
        _create_test_vault(vault_path, "")


def test_unlock_reads_back_what_was_saved(
    fresh_vault: UnlockedVault,
    master_password: str,
) -> None:
    fresh_vault.add_entry(
        "github",
        _sample_entry(),
    )

    fresh_vault.save()

    reopened = UnlockedVault.unlock(
        fresh_vault.path,
        master_password,
    )

    assert "github" in reopened.entries
    assert reopened.entries["github"].username == "alice"
    assert reopened.entries["github"].password == "s3cret"


def test_unlock_with_wrong_password_raises(
    fresh_vault: UnlockedVault,
) -> None:
    with pytest.raises(WrongPasswordError):
        UnlockedVault.unlock(
            fresh_vault.path,
            "not the right password",
        )


def test_unlock_missing_file_raises(
    tmp_path: Path,
) -> None:
    with pytest.raises(VaultNotFoundError):
        UnlockedVault.unlock(
            tmp_path / "nope.json",
            "any-password",
        )


def test_unlock_invalid_json_raises(
    vault_path: Path,
) -> None:
    vault_path.write_text("this is not json")

    with pytest.raises(VaultFormatError):
        UnlockedVault.unlock(
            vault_path,
            "any-password",
        )


def test_unlock_unsupported_version_raises(
    vault_path: Path,
) -> None:
    vault_path.write_text(
        json.dumps(
            {
                "version": 99,
                "kdf": {},
                "cipher": {},
            }
        )
    )

    with pytest.raises(VaultFormatError):
        UnlockedVault.unlock(
            vault_path,
            "any-password",
        )


def test_unlock_rejects_zero_time_cost(
    vault_path: Path,
) -> None:
    vault_path.write_text(
        json.dumps(
            {
                "version": 1,
                "kdf": {
                    "name": "argon2id",
                    "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                    "time_cost": 0,
                    "memory_cost": 8,
                    "parallelism": 1,
                },
                "cipher": {
                    "name": "aes-256-gcm",
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AAAAAAAAAAAAAAAA",
                },
            }
        )
    )

    with pytest.raises(VaultFormatError):
        UnlockedVault.unlock(
            vault_path,
            "any-password",
        )


def test_unlock_rejects_memory_cost_below_lane_floor(
    vault_path: Path,
) -> None:
    vault_path.write_text(
        json.dumps(
            {
                "version": 1,
                "kdf": {
                    "name": "argon2id",
                    "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                    "time_cost": 1,
                    "memory_cost": 4,
                    "parallelism": 2,
                },
                "cipher": {
                    "name": "aes-256-gcm",
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AAAAAAAAAAAAAAAA",
                },
            }
        )
    )

    with pytest.raises(VaultFormatError):
        UnlockedVault.unlock(
            vault_path,
            "any-password",
        )


def test_entry_is_immutable() -> None:
    entry = Entry(
        username="alice",
        password="x",
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.password = "y"  # type: ignore[misc]


def test_entry_from_dict_missing_password_raises() -> None:
    with pytest.raises(VaultFormatError):
        Entry.from_dict(
            {
                "username": "alice",
            }
        )


def test_entry_from_dict_missing_username_raises() -> None:
    with pytest.raises(VaultFormatError):
        Entry.from_dict(
            {
                "password": "x",
            }
        )


def test_entry_from_dict_non_string_password_raises() -> None:
    with pytest.raises(VaultFormatError):
        Entry.from_dict(
            {
                "username": "alice",
                "password": 12345,
            }
        )


def test_entry_from_dict_uses_empty_string_for_missing_timestamps() -> None:
    entry = Entry.from_dict(
        {
            "username": "alice",
            "password": "x",
        }
    )

    assert entry.created_at == ""
    assert entry.updated_at == ""


def test_add_entry_appears_in_names(
    fresh_vault: UnlockedVault,
) -> None:
    fresh_vault.add_entry(
        "github",
        _sample_entry(),
    )

    assert "github" in fresh_vault.names()


def test_names_returns_sorted(
    fresh_vault: UnlockedVault,
) -> None:
    fresh_vault.add_entry(
        "zebra",
        _sample_entry(),
    )

    fresh_vault.add_entry(
        "apple",
        _sample_entry(),
    )

    fresh_vault.add_entry(
        "mango",
        _sample_entry(),
    )

    assert fresh_vault.names() == [
        "apple",
        "mango",
        "zebra",
    ]


def test_add_entry_refuses_duplicate(
    fresh_vault: UnlockedVault,
) -> None:
    fresh_vault.add_entry(
        "github",
        _sample_entry(),
    )

    with pytest.raises(EntryAlreadyExistsError):
        fresh_vault.add_entry(
            "github",
            _sample_entry(),
        )


def test_add_entry_with_force_overwrites(
    fresh_vault: UnlockedVault,
) -> None:
    fresh_vault.add_entry(
        "github",
        _sample_entry(password="old"),
    )

    fresh_vault.add_entry(
        "github",
        _sample_entry(password="new"),
        force=True,
    )

    assert fresh_vault.get_entry("github").password == "new"


def test_overwrite_preserves_created_at(
    fresh_vault: UnlockedVault,
) -> None:
    fresh_vault.add_entry(
        "github",
        _sample_entry(),
    )

    original_created = (
        fresh_vault.get_entry("github").created_at
    )

    fresh_vault.add_entry(
        "github",
        _sample_entry(password="rotated"),
        force=True,
    )

    assert (
        fresh_vault.get_entry("github").created_at
        == original_created
    )


def test_get_entry_missing_raises(
    fresh_vault: UnlockedVault,
) -> None:
    with pytest.raises(EntryNotFoundError):
        fresh_vault.get_entry(
            "does-not-exist"
        )


def test_delete_entry_removes_it(
    fresh_vault: UnlockedVault,
) -> None:
    fresh_vault.add_entry(
        "github",
        _sample_entry(),
    )

    fresh_vault.delete_entry("github")

    assert "github" not in fresh_vault.names()


def test_delete_entry_missing_raises(
    fresh_vault: UnlockedVault,
) -> None:
    with pytest.raises(EntryNotFoundError):
        fresh_vault.delete_entry(
            "does-not-exist"
        )


@pytest.mark.parametrize(
    "bad_name",
    [
        "",
        "  ",
        "\t",
        "\n",
        " github",
        "github ",
        " github ",
    ],
)
def test_add_entry_rejects_invalid_names(
    fresh_vault: UnlockedVault,
    bad_name: str,
) -> None:
    with pytest.raises(ValueError):
        fresh_vault.add_entry(
            bad_name,
            _sample_entry(),
        )


def test_change_master_password_rotates_key_and_salt(
    fresh_vault: UnlockedVault,
    master_password: str,
) -> None:
    fresh_vault.add_entry(
        "github",
        _sample_entry(),
    )

    original_salt = fresh_vault.salt
    original_key = fresh_vault.key

    fresh_vault.change_master_password(
        "an entirely new master pass",
        kdf_parameters=TEST_KDF_PARAMETERS,
    )

    fresh_vault.save()

    assert fresh_vault.salt != original_salt
    assert fresh_vault.key != original_key


def test_change_master_password_old_password_no_longer_unlocks(
    fresh_vault: UnlockedVault,
    master_password: str,
) -> None:
    fresh_vault.add_entry(
        "github",
        _sample_entry(),
    )

    fresh_vault.change_master_password(
        "the new one",
        kdf_parameters=TEST_KDF_PARAMETERS,
    )

    fresh_vault.save()

    with pytest.raises(WrongPasswordError):
        UnlockedVault.unlock(
            fresh_vault.path,
            master_password,
        )


def test_change_master_password_new_password_unlocks_with_entries_intact(
    fresh_vault: UnlockedVault,
) -> None:
    fresh_vault.add_entry(
        "github",
        _sample_entry(),
    )

    fresh_vault.change_master_password(
        "the new one",
        kdf_parameters=TEST_KDF_PARAMETERS,
    )

    fresh_vault.save()

    reopened = UnlockedVault.unlock(
        fresh_vault.path,
        "the new one",
    )

    assert reopened.entries["github"].password == "s3cret"


def test_change_master_password_rejects_empty(
    fresh_vault: UnlockedVault,
) -> None:
    with pytest.raises(ValueError):
        fresh_vault.change_master_password("")


def test_close_zeroes_key_and_drops_entries(
    fresh_vault: UnlockedVault,
) -> None:
    fresh_vault.add_entry(
        "github",
        _sample_entry(),
    )

    fresh_vault.close()

    assert fresh_vault.entries == {}
    assert fresh_vault.key == bytes(32)


def test_unlocked_vault_works_as_context_manager(
    vault_path: Path,
    master_password: str,
) -> None:
    with _create_test_vault(
        vault_path,
        master_password,
    ) as vault:
        vault.add_entry(
            "github",
            _sample_entry(),
        )

        assert (
            vault.entries["github"].username
            == "alice"
        )

    assert vault.entries == {}
    assert vault.key == bytes(32)


def test_context_manager_cleans_up_on_exception(
    vault_path: Path,
    master_password: str,
) -> None:
    with (
        pytest.raises(RuntimeError),
        _create_test_vault(
            vault_path,
            master_password,
        ) as vault,
    ):
        vault.add_entry(
            "github",
            _sample_entry(),
        )

        raise RuntimeError("boom")

    assert vault.entries == {}
    assert vault.key == bytes(32)


def test_save_uses_fresh_nonce_each_time(
    fresh_vault: UnlockedVault,
) -> None:
    fresh_vault.save()

    cipher_a = json.loads(
        fresh_vault.path.read_text()
    )["cipher"]

    fresh_vault.save()

    cipher_b = json.loads(
        fresh_vault.path.read_text()
    )["cipher"]

    assert cipher_a["nonce"] != cipher_b["nonce"]
    assert cipher_a["ciphertext"] != cipher_b["ciphertext"]


def test_save_does_not_leave_temp_file(
    fresh_vault: UnlockedVault,
) -> None:
    fresh_vault.save()

    tmp = fresh_vault.path.with_suffix(
        fresh_vault.path.suffix + ".tmp"
    )

    assert not tmp.exists()


def test_save_creates_temp_file_with_secure_mode_only(
    fresh_vault: UnlockedVault,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt":
        pytest.skip(
            "POSIX-only check — Windows ignores Unix file modes"
        )

    captured_modes: list[int] = []
    real_open = os.open

    def spy_open(
        path,
        flags,
        mode=0o777,
        *,
        dir_fd=None,
    ):
        if str(path).endswith(".tmp"):
            captured_modes.append(mode)

        return real_open(
            path,
            flags,
            mode,
            dir_fd=dir_fd,
        )

    monkeypatch.setattr(
        os,
        "open",
        spy_open,
    )

    fresh_vault.save()

    assert captured_modes
    assert all(
        mode == VAULT_FILE_MODE
        for mode in captured_modes
    )


def test_save_cleans_up_temp_file_on_replace_failure(
    fresh_vault: UnlockedVault,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(
        *_args: object,
        **_kwargs: object,
    ) -> None:
        raise OSError(
            "simulated replace failure"
        )

    fresh_vault.save()

    monkeypatch.setattr(
        os,
        "replace",
        explode,
    )

    with pytest.raises(
        OSError,
        match="simulated replace failure",
    ):
        fresh_vault.save()

    tmp = fresh_vault.path.with_suffix(
        fresh_vault.path.suffix + ".tmp"
    )

    assert not tmp.exists()
