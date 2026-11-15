from __future__ import annotations

import base64
import hashlib
import json

import httpx
import jcs
import pytest

from awiki_open_server.app.main import create_app
from awiki_open_server.app.settings import Settings
from awiki_open_server.protocol.anp_adapter import generate_service_http_signature_headers
from tests.helpers import _b58, sign_did_document, single_device_document


AUTH_PATH = "/user-service/v1/did-auth/rpc"
DID = "did:wba:testserver:users:device-rebind:e1_fixture"
PURPOSE = "awiki.identity.device-rebind.v1"
OLD_DEVICE = "device-primary"


def setup_app(tmp_path):
    settings = Settings(
        data_dir=tmp_path, public_base_url="http://testserver",
        service_did="did:wba:testserver", did_domain="testserver",
    )
    return create_app(settings), settings


def document_keys(*, device_id: str = OLD_DEVICE, root_key=None):
    root, signing, document = single_device_document(DID, device_id=device_id, root_key=root_key)
    document["service"][0].update(serviceEndpoint="http://testserver/anp-im/rpc", serviceDid="did:wba:testserver")
    return root, signing, document


async def call(client, method, params=None, *, token=None):
    return await client.post(
        AUTH_PATH, json={"jsonrpc": "2.0", "id": "rebind-test", "method": method, "params": params or {}},
        headers={"Authorization": f"Bearer {token}"} if token else {},
    )


async def register_device(client, root, document):
    signed = sign_did_document(document, root)
    response = await call(client, "register", {"handle": "device-rebind", "did_document": signed})
    body = response.json()
    assert "error" not in body, body
    return body["result"], signed


def claims(token: str) -> dict:
    value = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


def document_hash(document: dict) -> str:
    digest = hashlib.sha256(jcs.canonicalize(document)).digest()
    return "sha256:" + base64.urlsafe_b64encode(digest).decode().rstrip("=")


def possession_proof(*, device_id, signing_key, signing_key_id, operation_id, document):
    intent = {
        "purpose": PURPOSE,
        "did": document["id"],
        "operationId": operation_id,
        "documentHash": document_hash(document),
        "deviceId": device_id,
        "signingKeyId": signing_key_id,
    }
    proof = {
        "type": "DataIntegrityProof",
        "created": "2026-07-10T00:00:00Z",
        "verificationMethod": signing_key_id,
        "proofPurpose": "assertionMethod",
        "cryptosuite": "eddsa-jcs-2022",
    }
    signing_input = (
        hashlib.sha256(jcs.canonicalize(proof)).digest()
        + hashlib.sha256(jcs.canonicalize(intent)).digest()
    )
    return {**proof, "proofValue": _b58(signing_key.sign(signing_input))}


def replacement_document(root, *, device_id: str):
    _, signing, document = document_keys(device_id=device_id, root_key=root)
    return signing, sign_did_document(document, root)


def rebind_params(
    *, operation_id, current_document, expected_version, expected_registry_version,
    new_document, signing_key, replaced_device_ids, **overrides,
):
    entry = new_document["deviceManifest"]["devices"][0]
    params = {
        "did": new_document["id"],
        "operation_id": operation_id,
        "expected_document_hash": document_hash(current_document),
        "expected_document_version": expected_version,
        "expected_registry_version": expected_registry_version,
        "new_document": new_document,
        "new_device": {
            "device_id": entry["device_id"],
            "signing_key_id": entry["signing_key_id"],
            "e2ee_key_id": entry["e2ee_key_id"],
        },
        "replaced_device_ids": replaced_device_ids,
        "new_device_object_proof": possession_proof(
            device_id=entry["device_id"], signing_key=signing_key,
            signing_key_id=entry["signing_key_id"], operation_id=operation_id,
            document=new_document,
        ),
    }
    params.update(overrides)
    return params


def signed_request(document, key, keyid, params):
    raw = json.dumps(
        {"jsonrpc": "2.0", "id": "rebind", "method": "device_rebind", "params": params},
        separators=(",", ":"),
    ).encode()
    headers = generate_service_http_signature_headers(
        did_document=document, request_url=f"http://testserver{AUTH_PATH}", request_method="POST",
        headers={"Content-Type": "application/json"}, body=raw, keyid=keyid,
        sign_callback=lambda value, _keyid: key.sign(value),
    )
    return raw, {"Content-Type": "application/json", **headers}


async def signed_me(client, document, key, keyid):
    raw = json.dumps({"jsonrpc": "2.0", "id": "renewal", "method": "get_me", "params": {}}, separators=(",", ":")).encode()
    headers = generate_service_http_signature_headers(
        did_document=document, request_url=f"http://testserver{AUTH_PATH}", request_method="POST",
        headers={"Content-Type": "application/json"}, body=raw, keyid=keyid,
        sign_callback=lambda value, _keyid: key.sign(value),
    )
    return await client.post(AUTH_PATH, content=raw, headers={"Content-Type": "application/json", **headers})


@pytest.mark.asyncio
async def test_device_rebind_replaces_device_and_rotates_credentials(tmp_path):
    app, _ = setup_app(tmp_path)
    root, _device_key, document = document_keys()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        registration, document = await register_device(client, root, document)
        did = document["id"]
        old_token = registration["access_token"]
        assert (await call(client, "get_me", token=old_token)).status_code == 200
        with app.state.store.connect() as conn:
            old_refresh = conn.execute("SELECT refresh_token FROM users WHERE did = ?", (did,)).fetchone()["refresh_token"]

        new_signing, new_document = replacement_document(root, device_id="device-rebound")
        operation_id = "rebind-op-1"
        params = rebind_params(
            operation_id=operation_id, current_document=document,
            expected_version=1, expected_registry_version=1,
            new_document=new_document, signing_key=new_signing,
            replaced_device_ids=[OLD_DEVICE],
        )
        raw, headers = signed_request(document, root, f"{did}#key-1", params)
        response = await client.post(AUTH_PATH, content=raw, headers=headers)
        body = response.json()
        assert "error" not in body, body
        result = body["result"]
        assert result["replayed"] is False
        assert result["document_version"] == 2
        assert result["registry_version"] == 2
        assert result["auth_generation"] == 2
        assert result["device_id"] == "device-rebound"
        assert result["replaced_device_ids"] == [OLD_DEVICE]
        assert result["document"] == new_document
        token = result["access_token"]
        assert response.headers["authorization"] == f"Bearer {token}"
        assert claims(token)["device_id"] == "device-rebound"
        assert claims(token)["auth_generation"] == 2

        # The replaced generation loses both bearer artifacts.
        assert (await call(client, "get_me", token=old_token)).status_code == 401
        stale_refresh = await client.post(
            "/user-service/v1/auth/token-refresh", json={"refresh_token": old_refresh},
        )
        assert stale_refresh.status_code == 401

        # The new device authenticates by signing with its own key.
        renewed = await signed_me(client, result["document"], new_signing, f"{did}#device-rebound-sign")
        assert renewed.status_code == 200, renewed.text
        assert renewed.json()["result"]["did"] == did
        renewed_token = renewed.json()["result"]["access_token"]
        assert claims(renewed_token)["auth_generation"] == 2
        assert (await call(client, "get_me", token=renewed_token)).status_code == 200

        # An identical retry with a fresh HTTP signature is idempotent.
        raw, headers = signed_request(result["document"], root, f"{did}#key-1", params)
        replay = (await client.post(AUTH_PATH, content=raw, headers=headers)).json()["result"]
        assert replay["replayed"] is True
        assert replay["document_version"] == 2
        assert replay["registry_version"] == 2
        assert (await call(client, "get_me", token=replay["access_token"])).status_code == 200
        # Single-token rotation: each issuance invalidates the previous bearer.
        assert (await call(client, "get_me", token=token)).status_code == 401
        assert (await call(client, "get_me", token=renewed_token)).status_code == 401


@pytest.mark.asyncio
async def test_device_rebind_requires_root_authority(tmp_path):
    app, _ = setup_app(tmp_path)
    root, device_key, document = document_keys()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        _registration, document = await register_device(client, root, document)
        did = document["id"]
        new_signing, new_document = replacement_document(root, device_id="device-rebound")
        params = rebind_params(
            operation_id="rebind-unauthenticated", current_document=document,
            expected_version=1, expected_registry_version=1,
            new_document=new_document, signing_key=new_signing,
            replaced_device_ids=[OLD_DEVICE],
        )

        unsigned = await call(client, "device_rebind", params)
        assert unsigned.status_code == 401
        assert unsigned.json()["error"]["message"] == "root_signature_required"

        raw, headers = signed_request(document, device_key, f"{did}#device-primary-sign", params)
        device_signed = await client.post(AUTH_PATH, content=raw, headers=headers)
        assert device_signed.status_code == 401
        assert device_signed.json()["error"]["message"] == "root_signature_required"


@pytest.mark.asyncio
async def test_device_rebind_rejects_stale_cas_and_invalid_possession(tmp_path):
    app, _ = setup_app(tmp_path)
    root, device_key, document = document_keys()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        registration, document = await register_device(client, root, document)
        did = document["id"]
        new_signing, new_document = replacement_document(root, device_id="device-rebound")

        def params_for(operation_id: str, **overrides):
            params = rebind_params(
                operation_id=operation_id, current_document=document,
                expected_version=1, expected_registry_version=1,
                new_document=new_document, signing_key=new_signing,
                replaced_device_ids=[OLD_DEVICE],
            )
            params.update(overrides)
            return params

        async def error_of(params):
            raw, headers = signed_request(document, root, f"{did}#key-1", params)
            response = await client.post(AUTH_PATH, content=raw, headers=headers)
            body = response.json()
            assert "error" in body, body
            return body["error"]

        stale_hash = document_hash({**document, "deactivated": False})
        assert (await error_of(params_for("rebind-stale-hash", expected_document_hash=stale_hash)))["message"] == "document_digest_mismatch"
        assert (await error_of(params_for("rebind-stale-version", expected_document_version=2)))["message"] == "document_digest_mismatch"
        assert (await error_of(params_for("rebind-stale-registry", expected_registry_version=5)))["message"] == "registry_version_mismatch"
        conflict = await error_of(params_for("rebind-replaced", replaced_device_ids=[]))
        assert conflict["message"] == "replaced_device_ids_mismatch"
        assert conflict["data"]["expected"] == [OLD_DEVICE]

        old_signing_key_id = document["deviceManifest"]["devices"][0]["signing_key_id"]
        old_device_proof = possession_proof(
            device_id="device-rebound", signing_key=device_key,
            signing_key_id=old_signing_key_id, operation_id="rebind-old-proof", document=new_document,
        )
        assert (await error_of(params_for("rebind-old-proof", new_device_object_proof=old_device_proof)))["message"] == "new_device_proof_invalid"

        root_proof = possession_proof(
            device_id="device-rebound", signing_key=root,
            signing_key_id=f"{did}#key-1", operation_id="rebind-root-proof", document=new_document,
        )
        assert (await error_of(params_for("rebind-root-proof", new_device_object_proof=root_proof)))["message"] == "new_device_proof_invalid"

        # Nothing was mutated by the rejected attempts.
        assert (await call(client, "get_me", token=registration["access_token"])).status_code == 200

        raw, headers = signed_request(document, root, f"{did}#key-1", params_for("rebind-success"))
        committed = (await client.post(AUTH_PATH, content=raw, headers=headers)).json()["result"]
        assert committed["document_version"] == 2


@pytest.mark.asyncio
async def test_server_info_advertises_root_device_rebind(tmp_path):
    app, _ = setup_app(tmp_path)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        info = (await client.get("/user-service/v1/server-info?client_platform=app")).json()
        rebind = info["identity"]["device_rebind"]
        assert rebind["enabled"] is True
        assert rebind["purpose"] == PURPOSE
        assert rebind["methods"] == [{
            "id": "root_signature", "enabled": True,
            "verification": {"required": True, "type": "did_document_root_http_signature"},
        }]
        other = (await client.get("/user-service/v1/server-info?registration_domain=other.example")).json()
        assert other["identity"]["device_rebind"]["enabled"] is False
