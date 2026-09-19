from pathlib import Path
from typing import Final
# Argon2id parameters
ARGON2_TIME_COST: Final[int] = 3
ARGON2_MEMORY_KIB: Final[int] = 65536
ARGON2_PARALLELISM: Final[int] = 4

SALT_LENGTH_BYTES: Final[int] = 16

ARGON2_TIME_COST_MIN: Final[int] = 1
ARGON2_PARALLELISM_MIN: Final[int] = 1
ARGON2_MEMORY_KIB_PER_LANE_MIN: Final[int] = 8
# AES-256-GCM parameters
KEY_LENGTH_BYTES: Final[int] = 32
NONCE_LENGTH_BYTES: Final[int] = 12
# Vault format
VAULT_FORMAT_VERSION: Final[int] = 1

VAULT_KEY_VERSION: Final[str] = "version"
VAULT_KEY_KDF: Final[str] = "kdf"
VAULT_KEY_CIPHER: Final[str] = "cipher"

KDF_KEY_NAME: Final[str] = "name"
KDF_KEY_SALT: Final[str] = "salt"
KDF_KEY_TIME_COST: Final[str] = "time_cost"
KDF_KEY_MEMORY_COST: Final[str] = "memory_cost"
KDF_KEY_PARALLELISM: Final[str] = "parallelism"

CIPHER_KEY_NAME: Final[str] = "name"
CIPHER_KEY_NONCE: Final[str] = "nonce"
CIPHER_KEY_CIPHERTEXT: Final[str] = "ciphertext"

KDF_NAME_ARGON2ID: Final[str] = "argon2id"
CIPHER_NAME_AES_256_GCM: Final[str] = "aes-256-gcm"
VAULT_FILE_MODE: Final[int] = 0o600

DEFAULT_VAULT_DIRECTORY: Final[Path] = Path.home() / ".password-vault"
DEFAULT_VAULT_FILENAME: Final[str] = "vault.json"
DEFAULT_VAULT_PATH: Final[Path] = (
    DEFAULT_VAULT_DIRECTORY / DEFAULT_VAULT_FILENAME
)

# Password generator
DEFAULT_GENERATED_PASSWORD_LENGTH: Final[int] = 24
MINIMUM_GENERATED_PASSWORD_LENGTH: Final[int] = 8
MINIMUM_MASTER_PASSWORD_LENGTH: Final[int] = 8

LOWERCASE_LETTERS: Final[str] = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE_LETTERS: Final[str] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS: Final[str] = "0123456789"
SAFE_SYMBOLS: Final[str] = "!@#$%^&*()-_=+[]{};:,.<>/?"
# CLI prompts and messages
PROMPT_MASTER_PASSWORD: Final[str] = "Master password: "
PROMPT_MASTER_PASSWORD_CONFIRM: Final[str] = "Confirm master password: "
PROMPT_MASTER_PASSWORD_NEW: Final[str] = "New master password: "

PROMPT_VAULT_PATH: Final[str] = "Vault path: "

PROMPT_ENTRY_USERNAME: Final[str] = "Username: "
PROMPT_ENTRY_URL: Final[str] = "URL (optional): "
PROMPT_ENTRY_NOTES: Final[str] = "Notes (optional): "

MSG_VAULT_CREATED: Final[str] = "Vault created successfully at {path}."
MSG_VAULT_UNLOCKED: Final[str] = "Vault unlocked successfully."
MSG_VAULT_LOCKED: Final[str] = "Vault locked."
MSG_VAULT_NOT_FOUND: Final[str] = "Vault not found at {path}."
MSG_VAULT_ALREADY_EXISTS: Final[str] = "Vault already exists at {path}."
MSG_VAULT_EMPTY: Final[str] = "Vault is empty."

MSG_WRONG_MASTER_PASSWORD: Final[str] = "Wrong master password."
MSG_MASTER_PASSWORD_EMPTY: Final[str] = "Master password cannot be empty."
MSG_MASTER_PASSWORD_TOO_SHORT: Final[str] = (
    "Master password must be at least {minimum} characters."
)
MSG_PASSWORDS_DO_NOT_MATCH: Final[str] = "Passwords do not match."
MSG_MASTER_PASSWORD_CHANGED: Final[str] = (
    "Master password changed successfully for {path}."
)

MSG_ENTRY_ADDED: Final[str] = "Entry '{name}' added."
MSG_ENTRY_ALREADY_EXISTS: Final[str] = "Entry '{name}' already exists."
MSG_ENTRY_DELETED: Final[str] = "Entry '{name}' deleted."
MSG_ENTRY_NOT_FOUND: Final[str] = "Entry '{name}' not found."
