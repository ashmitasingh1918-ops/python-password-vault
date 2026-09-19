from pathlib import Path

import pytest

from password_manager.crypto import KdfParameters
from password_manager.vault import UnlockedVault


TEST_KDF_PARAMETERS = KdfParameters(
    time_cost=1,
    memory_cost=8,
    parallelism=1,
)


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    return tmp_path / "test-vault.json"


@pytest.fixture
def master_password() -> str:
    return "correct horse battery staple"


@pytest.fixture
def fresh_vault(
    vault_path: Path,
    master_password: str,
) -> UnlockedVault:
    return UnlockedVault.create(
        vault_path,
        master_password,
        kdf_parameters=TEST_KDF_PARAMETERS,
    )
