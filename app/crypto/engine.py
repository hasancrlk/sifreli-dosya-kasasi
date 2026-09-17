"""
VaultCore Cryptographic Engine.

AES-256-GCM authenticated encryption with Argon2id key derivation.

Security properties:
    - Confidentiality + integrity: AES-256-GCM (128-bit tag).
    - Key derivation: Argon2id (RFC 9106), memory-hard.
    - Unique 16-byte salt and 12-byte nonce per file from os.urandom.
    - KDF parameters are returned with every ciphertext and must be stored
      alongside it, so tuning them later never breaks old files.
    - Optional associated data (the file ID) binds a ciphertext to its record.

Limitations (honest notes):
    - Python cannot reliably wipe keys/passwords from memory; we only avoid
      storing or logging them.
    - Encryption happens server-side: the server briefly sees plaintext and
      password. This is NOT end-to-end / zero-knowledge encryption.
"""

import logging
import os
from dataclasses import dataclass

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

logger = logging.getLogger(__name__)

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16


@dataclass(frozen=True)
class CryptoParams:
    """Argon2id parameters."""
    time_cost: int
    memory_cost: int
    parallelism: int


@dataclass(frozen=True)
class EncryptionResult:
    """Encryption output. Everything except the password is needed to decrypt."""
    ciphertext: bytes
    salt: bytes
    nonce: bytes
    params: CryptoParams


def _get_crypto_params() -> CryptoParams:
    """KDF parameters for new encryptions."""
    return CryptoParams(
        time_cost=settings.ARGON2_TIME_COST,
        memory_cost=settings.ARGON2_MEMORY_COST,
        parallelism=settings.ARGON2_PARALLELISM,
    )


def derive_key(password: str, salt: bytes, params: CryptoParams | None = None) -> bytes:
    """Derive a 256-bit key from *password* and *salt* with Argon2id."""
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be exactly {SALT_SIZE} bytes, got {len(salt)}")
    params = params or _get_crypto_params()
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_SIZE,
        type=Argon2Type.ID,
    )


def encrypt(plaintext: bytes, password: str, aad: bytes | None = None) -> EncryptionResult:
    """Encrypt *plaintext*; *aad* is authenticated but not encrypted."""
    params = _get_crypto_params()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt, params)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return EncryptionResult(ciphertext=ciphertext, salt=salt, nonce=nonce, params=params)


def decrypt(
    ciphertext: bytes,
    password: str,
    salt: bytes,
    nonce: bytes,
    params: CryptoParams | None = None,
    aad: bytes | None = None,
) -> bytes:
    """Decrypt and authenticate.

    Raises:
        InvalidTag: wrong password, wrong params/AAD, or tampered data
                    (deliberately indistinguishable).
        ValueError: malformed salt/nonce.
    """
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be exactly {NONCE_SIZE} bytes, got {len(nonce)}")
    key = derive_key(password, salt, params)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        logger.warning("Decryption failed: authentication tag mismatch")
        raise
