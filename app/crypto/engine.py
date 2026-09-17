"""
VaultCore Cryptographic Engine.

Implements AES-256-GCM authenticated encryption with Argon2id key derivation.

Security Properties:
    - Confidentiality: AES-256-GCM provides 256-bit symmetric encryption.
    - Integrity: GCM mode provides built-in authentication (GMAC tag).
    - Key Derivation: Argon2id is resistant to both side-channel and GPU attacks.
    - Unique nonce per encryption: Prevents nonce reuse attacks.
    - Unique salt per file: Prevents rainbow table / precomputation attacks.

Threat Model:
    - Passwords never stored or logged; only used transiently for key derivation.
    - Each file gets a unique (salt, nonce) pair from os.urandom (CSPRNG).
    - AES-GCM tag verification prevents ciphertext tampering (InvalidTag).
    - Argon2id memory-hardness mitigates brute-force/dictionary attacks.
"""

import os
import hmac
import logging
from dataclasses import dataclass

from argon2.low_level import hash_secret_raw, Type as Argon2Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from app.config import settings

logger = logging.getLogger(__name__)

# Constants
SALT_SIZE = 16       # 128-bit salt for KDF
NONCE_SIZE = 12      # 96-bit nonce for AES-GCM (NIST recommended)
KEY_SIZE = 32        # 256-bit key for AES-256
TAG_SIZE = 16        # 128-bit authentication tag (appended by AESGCM)


@dataclass(frozen=True)
class EncryptionResult:
    """Immutable container for encryption output."""
    ciphertext: bytes
    salt: bytes
    nonce: bytes


@dataclass(frozen=True)
class CryptoParams:
    """Immutable container for KDF parameters."""
    time_cost: int
    memory_cost: int
    parallelism: int


def _get_crypto_params() -> CryptoParams:
    """Get KDF parameters from settings."""
    return CryptoParams(
        time_cost=settings.ARGON2_TIME_COST,
        memory_cost=settings.ARGON2_MEMORY_COST,
        parallelism=settings.ARGON2_PARALLELISM,
    )


def derive_key(password: str, salt: bytes, params: CryptoParams | None = None) -> bytes:
    """
    Derive a 256-bit encryption key from a password using Argon2id.

    Argon2id is the recommended variant (RFC 9106) that combines:
      - Argon2i: Data-independent memory access (side-channel resistant)
      - Argon2d: Data-dependent memory access (GPU/ASIC resistant)

    Args:
        password: User-supplied passphrase (UTF-8 encoded internally).
        salt: 16-byte cryptographically random salt (unique per file).
        params: Optional KDF parameters override (for testing).

    Returns:
        32-byte derived key suitable for AES-256-GCM.

    Raises:
        ValueError: If salt size is incorrect.
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be exactly {SALT_SIZE} bytes, got {len(salt)}")

    if params is None:
        params = _get_crypto_params()

    try:
        key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=KEY_SIZE,
            type=Argon2Type.ID,
        )
    finally:
        # Note: Python doesn't allow true secure memory wiping of strings,
        # but we minimize the password's lifetime by not storing it.
        pass

    return key


def encrypt(plaintext: bytes, password: str) -> EncryptionResult:
    """
    Encrypt data using AES-256-GCM with Argon2id-derived key.

    Process:
        1. Generate cryptographically random salt (16 bytes) and nonce (12 bytes).
        2. Derive 256-bit key from password + salt using Argon2id.
        3. Encrypt plaintext with AES-256-GCM (produces ciphertext + 16-byte auth tag).

    The authentication tag is automatically appended to the ciphertext by AESGCM.

    Args:
        plaintext: Raw file data to encrypt.
        password: User-supplied passphrase.

    Returns:
        EncryptionResult containing ciphertext (with appended tag), salt, and nonce.
    """
    # Generate unique cryptographic material per file
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # Derive encryption key
    key = derive_key(password, salt)

    try:
        # AES-256-GCM encryption
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        # ciphertext includes the 16-byte GCM authentication tag

        logger.info(
            "Encryption successful: plaintext=%d bytes, ciphertext=%d bytes",
            len(plaintext),
            len(ciphertext),
        )

        return EncryptionResult(
            ciphertext=ciphertext,
            salt=salt,
            nonce=nonce,
        )
    finally:
        # Overwrite key material in memory (best-effort in Python)
        key = b"\x00" * KEY_SIZE  # noqa: F841


def decrypt(ciphertext: bytes, password: str, salt: bytes, nonce: bytes) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data with Argon2id-derived key.

    Process:
        1. Re-derive the encryption key from password + stored salt using Argon2id.
        2. Decrypt and verify authentication tag with AES-256-GCM.
        3. If tag verification fails, InvalidTag is raised (wrong password or tampered data).

    Args:
        ciphertext: Encrypted data with appended GCM authentication tag.
        password: User-supplied passphrase.
        salt: Original 16-byte salt used during encryption.
        nonce: Original 12-byte nonce used during encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        InvalidTag: Password is wrong OR ciphertext has been tampered with.
                    We intentionally do not distinguish between these cases
                    to prevent information leakage to attackers.
        ValueError: If salt or nonce sizes are incorrect.
    """
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be exactly {NONCE_SIZE} bytes, got {len(nonce)}")

    # Derive encryption key using same parameters
    key = derive_key(password, salt)

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

        logger.info(
            "Decryption successful: ciphertext=%d bytes, plaintext=%d bytes",
            len(ciphertext),
            len(plaintext),
        )

        return plaintext
    except InvalidTag:
        # Do NOT log any details about the failure to prevent information leakage.
        # The caller should handle this as a generic authentication failure.
        logger.warning("Decryption failed: authentication tag mismatch (wrong password or tampered data)")
        raise
    finally:
        key = b"\x00" * KEY_SIZE  # noqa: F841


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Timing-safe comparison of two byte strings.

    Uses hmac.compare_digest to prevent timing side-channel attacks
    that could reveal information about the expected value.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        True if both byte strings are equal, False otherwise.
    """
    return hmac.compare_digest(a, b)
