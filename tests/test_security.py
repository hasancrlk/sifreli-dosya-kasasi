"""Regression tests for the security fixes."""

import asyncio
import os
import time
import uuid

import pytest
from cryptography.exceptions import InvalidTag

from app.config import settings
from app.crypto.engine import decrypt, encrypt
from app.services.vault_service import VaultService
from tests.conftest import STRONG_PASSWORD

UPLOAD = "/api/v1/vault/upload"


async def _upload(client, content=b"secret", name="f.txt", **data):
    resp = await client.post(
        UPLOAD, files={"file": (name, content, "text/plain")},
        data={"password": STRONG_PASSWORD, **data},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def test_kdf_param_change_does_not_break_old_files(client, monkeypatch):
    file_id = await _upload(client, b"old file")
    monkeypatch.setattr(settings, "ARGON2_TIME_COST", 2)
    monkeypatch.setattr(settings, "ARGON2_MEMORY_COST", 2048)

    resp = await client.post(f"/api/v1/vault/download/{file_id}", json={"password": STRONG_PASSWORD})
    assert resp.status_code == 200
    assert resp.content == b"old file"


def test_aad_binds_ciphertext_to_file_id():
    a, b = uuid.uuid4().bytes, uuid.uuid4().bytes
    r = encrypt(b"data", STRONG_PASSWORD, aad=a)
    with pytest.raises(InvalidTag):
        decrypt(r.ciphertext, STRONG_PASSWORD, r.salt, r.nonce, r.params, aad=b)


async def test_one_time_link_race(client):
    file_id = await _upload(client, max_downloads="1")
    url = f"/api/v1/vault/download/{file_id}"
    results = await asyncio.gather(
        *(client.post(url, json={"password": STRONG_PASSWORD}) for _ in range(5))
    )
    codes = sorted(r.status_code for r in results)
    assert codes.count(200) == 1
    assert all(c == 410 for c in codes if c != 200)


async def test_exhausted_file_is_shredded(client, fast_settings):
    file_id = await _upload(client, max_downloads="1")
    await client.post(f"/api/v1/vault/download/{file_id}", json={"password": STRONG_PASSWORD})
    assert not (fast_settings / f"{file_id}.enc").exists()


async def test_lockout_after_failed_attempts(client, monkeypatch):
    monkeypatch.setattr(settings, "MAX_FAILED_ATTEMPTS", 3)
    file_id = await _upload(client)
    url = f"/api/v1/vault/download/{file_id}"

    for _ in range(3):
        assert (await client.post(url, json={"password": "wrong-password"})).status_code == 401

    resp = await client.post(url, json={"password": STRONG_PASSWORD})
    assert resp.status_code == 429


async def test_management_endpoints_require_api_key(client):
    for method, url in (("get", "/api/v1/vault/files"), ("delete", f"/api/v1/vault/files/{uuid.uuid4()}")):
        resp = await getattr(client, method)(url, headers={"X-API-Key": "nope"})
        assert resp.status_code == 401
    resp = await client.post(
        UPLOAD, files={"file": ("a", b"x")}, data={"password": STRONG_PASSWORD},
        headers={"X-API-Key": "nope"},
    )
    assert resp.status_code == 401


async def test_download_does_not_need_api_key(client):
    file_id = await _upload(client)
    resp = await client.post(
        f"/api/v1/vault/download/{file_id}",
        json={"password": STRONG_PASSWORD}, headers={"X-API-Key": ""},
    )
    assert resp.status_code == 200


async def test_weak_password_rejected(client):
    resp = await client.post(UPLOAD, files={"file": ("a", b"x")}, data={"password": "short"})
    assert resp.status_code == 400


async def test_oversized_upload_rejected(client, monkeypatch):
    monkeypatch.setattr(settings, "MAX_FILE_SIZE_MB", 1)
    resp = await client.post(
        UPLOAD, files={"file": ("big", os.urandom(1024 * 1024 + 1))}, data={"password": STRONG_PASSWORD}
    )
    assert resp.status_code == 413


async def test_header_injection_and_mime_neutralised(client):
    file_id = await _upload(client, name='evil"; x=\r\n.html')
    resp = await client.post(f"/api/v1/vault/download/{file_id}", json={"password": STRONG_PASSWORD})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/octet-stream"
    assert "\r" not in resp.headers["content-disposition"]
    assert resp.headers["content-disposition"].count('"') == 2


async def test_delete_removes_ciphertext(client, fast_settings):
    file_id = await _upload(client)
    assert (await client.delete(f"/api/v1/vault/files/{file_id}")).status_code == 204
    assert not (fast_settings / f"{file_id}.enc").exists()
    resp = await client.post(f"/api/v1/vault/download/{file_id}", json={"password": STRONG_PASSWORD})
    assert resp.status_code == 410


async def test_purge_removes_orphans(db_session, fast_settings):
    orphan = fast_settings / f"{uuid.uuid4()}.enc"
    orphan.write_bytes(b"x")
    old = time.time() - 7200
    os.utime(orphan, (old, old))

    assert await VaultService(db_session).purge_unavailable() == 1
    assert not orphan.exists()
