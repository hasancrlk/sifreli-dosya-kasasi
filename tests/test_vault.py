"""
VaultCore Test Suite.

Tests cover the full security lifecycle of the encrypted file vault:

1. CORRECTNESS TESTS:
   - Upload → download with correct password produces identical content.
   - Multiple files can be uploaded and listed independently.
   - File metadata is returned correctly (no sensitive fields leaked).

2. SECURITY TESTS:
   - Wrong password → DecryptionError (HTTP 401).
   - Tampered ciphertext → DecryptionError (AES-GCM InvalidTag).
   - Error messages do NOT leak whether password was wrong or data was tampered.

3. ACCESS CONTROL TESTS:
   - One-time download: file becomes unavailable after max_downloads reached.
   - Non-existent file_id → HTTP 404.

4. CRYPTOGRAPHIC UNIT TESTS:
   - Unique salt and nonce per encryption (no reuse).
   - Key derivation produces consistent output for same inputs.
   - Different passwords produce different keys (avalanche effect).
"""

import os
from unittest.mock import patch

import pytest
import pytest_asyncio

from app.crypto.engine import (
    NONCE_SIZE,
    SALT_SIZE,
    CryptoParams,
    decrypt,
    derive_key,
    encrypt,
)
from cryptography.exceptions import InvalidTag


# ═══════════════════════════════════════════════════════════════════════════════
# CRYPTOGRAPHIC UNIT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

# Use fast params for all crypto tests
FAST_PARAMS = CryptoParams(time_cost=1, memory_cost=1024, parallelism=1)


class TestKeyDerivation:
    """Tests for Argon2id key derivation."""

    def test_derive_key_produces_32_bytes(self):
        """Derived key must be exactly 256 bits (32 bytes) for AES-256."""
        salt = os.urandom(SALT_SIZE)
        key = derive_key("test_password", salt, FAST_PARAMS)
        assert len(key) == 32

    def test_derive_key_deterministic(self):
        """Same password + same salt must produce the same key."""
        salt = os.urandom(SALT_SIZE)
        key1 = derive_key("test_password", salt, FAST_PARAMS)
        key2 = derive_key("test_password", salt, FAST_PARAMS)
        assert key1 == key2

    def test_derive_key_different_passwords(self):
        """Different passwords with the same salt must produce different keys."""
        salt = os.urandom(SALT_SIZE)
        key1 = derive_key("password_one", salt, FAST_PARAMS)
        key2 = derive_key("password_two", salt, FAST_PARAMS)
        assert key1 != key2

    def test_derive_key_different_salts(self):
        """Same password with different salts must produce different keys."""
        salt1 = os.urandom(SALT_SIZE)
        salt2 = os.urandom(SALT_SIZE)
        key1 = derive_key("same_password", salt1, FAST_PARAMS)
        key2 = derive_key("same_password", salt2, FAST_PARAMS)
        assert key1 != key2

    def test_derive_key_invalid_salt_size(self):
        """Salt must be exactly 16 bytes."""
        with pytest.raises(ValueError, match="Salt must be exactly"):
            derive_key("password", b"short", FAST_PARAMS)


class TestEncryptDecrypt:
    """Tests for AES-256-GCM encryption and decryption."""

    @patch("app.crypto.engine._get_crypto_params", return_value=FAST_PARAMS)
    def test_encrypt_decrypt_roundtrip(self, _mock):
        """Encrypting then decrypting with correct password yields original data."""
        plaintext = b"Hello, VaultCore! This is sensitive data."
        password = "strong_passphrase_123!"

        result = encrypt(plaintext, password)
        decrypted = decrypt(result.ciphertext, password, result.salt, result.nonce)

        assert decrypted == plaintext

    @patch("app.crypto.engine._get_crypto_params", return_value=FAST_PARAMS)
    def test_encrypt_produces_unique_salt(self, _mock):
        """Each encryption must generate a unique salt."""
        plaintext = b"test data"
        password = "password"

        result1 = encrypt(plaintext, password)
        result2 = encrypt(plaintext, password)

        assert result1.salt != result2.salt

    @patch("app.crypto.engine._get_crypto_params", return_value=FAST_PARAMS)
    def test_encrypt_produces_unique_nonce(self, _mock):
        """Each encryption must generate a unique nonce."""
        plaintext = b"test data"
        password = "password"

        result1 = encrypt(plaintext, password)
        result2 = encrypt(plaintext, password)

        assert result1.nonce != result2.nonce

    @patch("app.crypto.engine._get_crypto_params", return_value=FAST_PARAMS)
    def test_encrypt_salt_size(self, _mock):
        """Salt must be exactly 16 bytes (128 bits)."""
        result = encrypt(b"data", "password")
        assert len(result.salt) == SALT_SIZE

    @patch("app.crypto.engine._get_crypto_params", return_value=FAST_PARAMS)
    def test_encrypt_nonce_size(self, _mock):
        """Nonce must be exactly 12 bytes (96 bits)."""
        result = encrypt(b"data", "password")
        assert len(result.nonce) == NONCE_SIZE

    @patch("app.crypto.engine._get_crypto_params", return_value=FAST_PARAMS)
    def test_ciphertext_larger_than_plaintext(self, _mock):
        """Ciphertext must be larger than plaintext (GCM tag adds 16 bytes)."""
        plaintext = b"test data"
        result = encrypt(plaintext, "password")
        # AES-GCM appends a 16-byte authentication tag
        assert len(result.ciphertext) == len(plaintext) + 16

    @patch("app.crypto.engine._get_crypto_params", return_value=FAST_PARAMS)
    def test_wrong_password_raises_invalid_tag(self, _mock):
        """Decryption with wrong password must raise InvalidTag."""
        plaintext = b"secret data"
        result = encrypt(plaintext, "correct_password")

        with pytest.raises(InvalidTag):
            decrypt(result.ciphertext, "wrong_password", result.salt, result.nonce)

    @patch("app.crypto.engine._get_crypto_params", return_value=FAST_PARAMS)
    def test_tampered_ciphertext_raises_invalid_tag(self, _mock):
        """
        Tampered ciphertext must raise InvalidTag.

        This is the CRITICAL security property of AES-GCM:
        any modification to the ciphertext invalidates the authentication tag.
        """
        plaintext = b"important data that must not be tampered with"
        result = encrypt(plaintext, "password")

        # Tamper with the ciphertext (flip a single bit)
        tampered = bytearray(result.ciphertext)
        tampered[0] ^= 0xFF  # Flip all bits in the first byte
        tampered = bytes(tampered)

        with pytest.raises(InvalidTag):
            decrypt(tampered, "password", result.salt, result.nonce)

    @patch("app.crypto.engine._get_crypto_params", return_value=FAST_PARAMS)
    def test_tampered_nonce_raises_invalid_tag(self, _mock):
        """Using a wrong nonce must raise InvalidTag."""
        plaintext = b"data"
        result = encrypt(plaintext, "password")

        wrong_nonce = os.urandom(NONCE_SIZE)
        with pytest.raises(InvalidTag):
            decrypt(result.ciphertext, "password", result.salt, wrong_nonce)

    @patch("app.crypto.engine._get_crypto_params", return_value=FAST_PARAMS)
    def test_empty_plaintext(self, _mock):
        """Encrypting empty data should work (edge case)."""
        result = encrypt(b"", "password")
        decrypted = decrypt(result.ciphertext, "password", result.salt, result.nonce)
        assert decrypted == b""

    @patch("app.crypto.engine._get_crypto_params", return_value=FAST_PARAMS)
    def test_large_plaintext(self, _mock):
        """Encrypting larger data should work correctly."""
        plaintext = os.urandom(1024 * 1024)  # 1 MB
        password = "password"

        result = encrypt(plaintext, password)
        decrypted = decrypt(result.ciphertext, password, result.salt, result.nonce)

        assert decrypted == plaintext


# ═══════════════════════════════════════════════════════════════════════════════
# API INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
class TestUploadEndpoint:
    """Tests for POST /api/v1/vault/upload."""

    async def test_upload_success(self, client):
        """Successful upload returns 201 with file metadata."""
        response = await client.post(
            "/api/v1/vault/upload",
            files={"file": ("test.txt", b"Hello World", "text/plain")},
            data={"password": "my_secure_password"},
        )

        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert data["filename"] == "test.txt"
        assert data["encrypted_size"] > 0
        assert data["message"] == "File encrypted and stored successfully"

    async def test_upload_with_max_downloads(self, client):
        """Upload with max_downloads parameter."""
        response = await client.post(
            "/api/v1/vault/upload",
            files={"file": ("test.txt", b"content", "text/plain")},
            data={"password": "password", "max_downloads": "1"},
        )

        assert response.status_code == 201
        assert response.json()["max_downloads"] == 1

    async def test_upload_with_expiration(self, client):
        """Upload with expires_in_hours parameter."""
        response = await client.post(
            "/api/v1/vault/upload",
            files={"file": ("test.txt", b"content", "text/plain")},
            data={"password": "password", "expires_in_hours": "24"},
        )

        assert response.status_code == 201
        assert response.json()["expires_at"] is not None

    async def test_upload_empty_file_rejected(self, client):
        """Empty file upload should be rejected."""
        response = await client.post(
            "/api/v1/vault/upload",
            files={"file": ("empty.txt", b"", "text/plain")},
            data={"password": "password"},
        )

        assert response.status_code == 400

    async def test_upload_no_password_rejected(self, client):
        """Upload without password should be rejected."""
        response = await client.post(
            "/api/v1/vault/upload",
            files={"file": ("test.txt", b"content", "text/plain")},
        )

        assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
class TestDownloadEndpoint:
    """Tests for POST /api/v1/vault/download/{file_id}."""

    async def test_download_with_correct_password(self, client):
        """Download with correct password returns original content."""
        original_content = b"This is my secret file content!"
        password = "correct_password_123"

        # Upload
        upload_resp = await client.post(
            "/api/v1/vault/upload",
            files={"file": ("secret.txt", original_content, "text/plain")},
            data={"password": password},
        )
        file_id = upload_resp.json()["id"]

        # Download
        download_resp = await client.post(
            f"/api/v1/vault/download/{file_id}",
            json={"password": password},
        )

        assert download_resp.status_code == 200
        assert download_resp.content == original_content
        assert "secret.txt" in download_resp.headers.get("content-disposition", "")

    async def test_download_with_wrong_password(self, client):
        """Download with wrong password returns 401 (no info leakage)."""
        # Upload
        upload_resp = await client.post(
            "/api/v1/vault/upload",
            files={"file": ("test.txt", b"secret", "text/plain")},
            data={"password": "correct_password"},
        )
        file_id = upload_resp.json()["id"]

        # Download with wrong password
        download_resp = await client.post(
            f"/api/v1/vault/download/{file_id}",
            json={"password": "wrong_password"},
        )

        assert download_resp.status_code == 401
        # Verify error message is generic (no info leakage)
        detail = download_resp.json()["detail"]
        assert "invalid credentials or corrupted data" in detail.lower()

    async def test_download_nonexistent_file(self, client):
        """Download of non-existent file returns 404."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        download_resp = await client.post(
            f"/api/v1/vault/download/{fake_id}",
            json={"password": "password"},
        )

        assert download_resp.status_code == 404

    async def test_one_time_download(self, client):
        """File with max_downloads=1 becomes unavailable after first download."""
        password = "otp_password"

        # Upload with max_downloads=1
        upload_resp = await client.post(
            "/api/v1/vault/upload",
            files={"file": ("onetime.txt", b"one-time secret", "text/plain")},
            data={"password": password, "max_downloads": "1"},
        )
        file_id = upload_resp.json()["id"]

        # First download — should succeed
        first_download = await client.post(
            f"/api/v1/vault/download/{file_id}",
            json={"password": password},
        )
        assert first_download.status_code == 200

        # Second download — should fail (410 Gone)
        second_download = await client.post(
            f"/api/v1/vault/download/{file_id}",
            json={"password": password},
        )
        assert second_download.status_code == 410

    async def test_download_binary_file(self, client):
        """Binary file (e.g., image) roundtrip should preserve content exactly."""
        binary_content = os.urandom(4096)  # Random binary data
        password = "binary_pass"

        upload_resp = await client.post(
            "/api/v1/vault/upload",
            files={"file": ("image.png", binary_content, "image/png")},
            data={"password": password},
        )
        file_id = upload_resp.json()["id"]

        download_resp = await client.post(
            f"/api/v1/vault/download/{file_id}",
            json={"password": password},
        )

        assert download_resp.status_code == 200
        assert download_resp.content == binary_content


@pytest.mark.asyncio
class TestListFilesEndpoint:
    """Tests for GET /api/v1/vault/files."""

    async def test_list_empty_vault(self, client):
        """Empty vault returns empty list."""
        response = await client.get("/api/v1/vault/files")

        assert response.status_code == 200
        data = response.json()
        assert data["files"] == []
        assert data["total"] == 0

    async def test_list_after_upload(self, client):
        """Uploaded files appear in the list."""
        # Upload a file
        await client.post(
            "/api/v1/vault/upload",
            files={"file": ("listed.txt", b"content", "text/plain")},
            data={"password": "password"},
        )

        response = await client.get("/api/v1/vault/files")
        data = response.json()

        assert data["total"] == 1
        assert data["files"][0]["filename"] == "listed.txt"

    async def test_list_does_not_expose_sensitive_data(self, client):
        """File listing must NOT contain passwords, salts, nonces, or file content."""
        await client.post(
            "/api/v1/vault/upload",
            files={"file": ("safe.txt", b"content", "text/plain")},
            data={"password": "super_secret_password"},
        )

        response = await client.get("/api/v1/vault/files")
        file_data = response.json()["files"][0]

        # Verify NO sensitive fields are present
        assert "password" not in file_data
        assert "salt" not in file_data
        assert "salt_hex" not in file_data
        assert "nonce" not in file_data
        assert "nonce_hex" not in file_data
        assert "key" not in file_data
        assert "content" not in file_data

        # Verify only expected fields are present
        expected_fields = {
            "id", "filename", "encrypted_size", "original_size",
            "content_type", "upload_date", "download_count",
            "max_downloads", "expires_at", "is_available",
        }
        assert set(file_data.keys()) == expected_fields

    async def test_list_multiple_files(self, client):
        """Multiple uploaded files should all appear in the list."""
        for i in range(3):
            await client.post(
                "/api/v1/vault/upload",
                files={"file": (f"file_{i}.txt", f"content_{i}".encode(), "text/plain")},
                data={"password": f"password_{i}"},
            )

        response = await client.get("/api/v1/vault/files")
        data = response.json()

        assert data["total"] == 3


@pytest.mark.asyncio
class TestSecurityHeaders:
    """Tests for security-related HTTP headers."""

    async def test_security_headers_present(self, client):
        """All security headers should be present in responses."""
        response = await client.get("/health")

        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("x-frame-options") == "DENY"
        assert "strict-transport-security" in response.headers


@pytest.mark.asyncio
class TestHealthEndpoint:
    """Tests for the health check endpoint."""

    async def test_health_check(self, client):
        """Health endpoint returns service status."""
        response = await client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "VaultCore"
