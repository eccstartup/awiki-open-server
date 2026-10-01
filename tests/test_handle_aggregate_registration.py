from __future__ import annotations

import base64
import copy

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from awiki_open_server.app.main import create_app
from awiki_open_server.app.settings import Settings
import pytest_asyncio

from awiki_open_server.service_identity import generate_ed25519_private_key_pem
from tests.conftest import rpc
from tests.helpers import _multikey, sign_did_document


def _aggregate_ad(
    local: str,
    domain: str,
    submitting_did: str,
    keys: list[tuple[str, ed25519.Ed25519PrivateKey]],
    *,
    signed_with: ed25519.Ed25519PrivateKey | None = None,
) -> dict:
    """Build a handle aggregate ad.json mirroring the extension's shape."""
    keyids = [f"{did}#key-1" for did, _ in keys]
    verification_method = [
        {"id": f"{did}#key-1", "type": "Multikey", "controller": did, "publicKeyMultibase": _multikey(priv.public_key())}
        for did, priv in keys
    ]
    ad = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/data-integrity/v2",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": submitting_did,
        "handle": f"{local}.{domain}",
        "type": "ANPHandleAggregate",
        "protocolType": "ANP-03",
        "version": 1,
        "did": submitting_did,
        "dids": [did for did, _ in keys],
        "verificationMethod": verification_method,
        "authentication": keyids,
        "assertionMethod": keyids,
        "owner": submitting_did,
        "service": [
            {
                "id": f"{submitting_did}#handle",
                "type": "ANPHandleService",
                "serviceEndpoint": f"https://{domain}/.well-known/handle/{local}",
            },
        ],
    }
    if signed_with is not None:
        ad = sign_did_document(ad, signed_with)
    return ad


@pytest_asyncio.fixture
async def strict_client(tmp_path):
    app = create_app(
        Settings(
            data_dir=tmp_path,
            public_base_url="http://testserver",
            service_did="did:wba:testserver",
            did_domain="testserver",
            service_private_key_pem=generate_ed25519_private_key_pem(),
            allow_unsigned_peer_dev=False,
        )
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as async_client:
        yield async_client


@pytest.mark.asyncio
async def test_aggregate_register_binds_all_dids_and_survives_second_key(client):
    domain = "testserver"
    local = "agg-dev"
    did0 = f"did:wba:{domain}:users:{local}:e1_aaa"
    did1 = f"did:wba:{domain}:users:{local}:e1_bbb"
    key0 = ed25519.Ed25519PrivateKey.generate()
    key1 = ed25519.Ed25519PrivateKey.generate()

    ad = _aggregate_ad(local, domain, did0, [(did0, key0), (did1, key1)])
    reg = await rpc(client, "/did-auth/rpc", "register", {"handle": local, "ad": ad})
    result = reg["result"]
    assert result["did"] == did0
    assert result["dids"] == [did0, did1]
    assert result["full_handle"] == f"{local}.{domain}"

    # A second register for the SAME handle adding a third key must NOT fail with
    # handle_already_registered — it re-upserts the whole aggregate.
    did2 = f"did:wba:{domain}:users:{local}:e1_ccc"
    key2 = ed25519.Ed25519PrivateKey.generate()
    ad2 = _aggregate_ad(local, domain, did0, [(did0, key0), (did1, key1), (did2, key2)])
    reg2 = await rpc(client, "/did-auth/rpc", "register", {"handle": local, "ad": ad2})
    assert "error" not in reg2, reg2
    assert set(reg2["result"]["dids"]) == {did0, did1, did2}

    hd = await client.get(f"/.well-known/handle/{local}")
    assert hd.status_code == 200
    body = hd.json()
    assert body["handle"] == f"{local}.{domain}"
    assert body["did"] == did0
    assert set(body["dids"]) == {did0, did1, did2}

    # Each derived DID is individually resolvable as its own did.json.
    for d, priv in [(did1, key1), (did2, key2)]:
        key_part = d.split(":")[-1]
        resolved = await client.get(f"/dids/resolve/users/{local}/{key_part}/did.json")
        assert resolved.status_code == 200
        assert resolved.json()["id"] == d
        assert any(vm["id"] == f"{d}#key-1" for vm in resolved.json()["verificationMethod"])


@pytest.mark.asyncio
async def test_aggregate_register_dev_mode_unsigned_is_rejected_by_strict_server(strict_client):
    # In non-dev (strict) mode, an UNSIGNED aggregate ad is rejected.
    domain = "testserver"
    local = "agg-strict-unsigned"
    did0 = f"did:wba:{domain}:users:{local}:e1_aaa"
    key0 = ed25519.Ed25519PrivateKey.generate()
    ad = _aggregate_ad(local, domain, did0, [(did0, key0)])
    reg = await rpc(strict_client, "/did-auth/rpc", "register", {"handle": local, "ad": ad})
    assert reg.get("error"), reg
    assert reg["error"]["message"] == "handle_ad_proof_required"


@pytest.mark.asyncio
async def test_aggregate_register_strict_signed_ad_with_challenge(strict_client):
    domain = "testserver"
    local = "agg-strict"
    did0 = f"did:wba:{domain}:users:{local}:e1_aaa"
    did1 = f"did:wba:{domain}:users:{local}:e1_bbb"
    key0 = ed25519.Ed25519PrivateKey.generate()
    key1 = ed25519.Ed25519PrivateKey.generate()

    chal = await rpc(strict_client, "/did-auth/rpc", "challenge", {"handle": local})
    challenge = chal["result"]["challenge"]
    ad = _aggregate_ad(local, domain, did0, [(did0, key0), (did1, key1)], signed_with=key0)
    sig = base64.urlsafe_b64encode(key0.sign(challenge.encode())).rstrip(b"=").decode()
    reg = await rpc(strict_client, "/did-auth/rpc", "register", {
        "handle": local,
        "ad": ad,
        "challenge": challenge,
        "challenge_signature": sig,
    })
    assert "error" not in reg, reg
    assert reg["result"]["dids"] == [did0, did1]

    # A legitimately re-signed aggregate adding a third DID also succeeds.
    did2 = f"did:wba:{domain}:users:{local}:e1_ccc"
    key2 = ed25519.Ed25519PrivateKey.generate()
    chal2 = await rpc(strict_client, "/did-auth/rpc", "challenge", {"handle": local})
    ad2 = _aggregate_ad(local, domain, did0, [(did0, key0), (did1, key1), (did2, key2)], signed_with=key0)
    sig2 = base64.urlsafe_b64encode(key0.sign(chal2["result"]["challenge"].encode())).rstrip(b"=").decode()
    reg2 = await rpc(strict_client, "/did-auth/rpc", "register", {
        "handle": local,
        "ad": ad2,
        "challenge": chal2["result"]["challenge"],
        "challenge_signature": sig2,
    })
    assert "error" not in reg2, reg2

    # A post-sign mutation (extra DID injected into a previously-valid ad) is
    # rejected: the signature no longer covers the changed dids.
    did_t = f"did:wba:{domain}:users:{local}:e1_tamper"
    chal3 = await rpc(strict_client, "/did-auth/rpc", "challenge", {"handle": local})
    tampered = copy.deepcopy(ad2)
    tampered["dids"] = list(tampered["dids"]) + [did_t]
    sig3 = base64.urlsafe_b64encode(key0.sign(chal3["result"]["challenge"].encode())).rstrip(b"=").decode()
    reg3 = await rpc(strict_client, "/did-auth/rpc", "register", {
        "handle": local,
        "ad": tampered,
        "challenge": chal3["result"]["challenge"],
        "challenge_signature": sig3,
    })
    assert reg3.get("error"), reg3


@pytest.mark.asyncio
async def test_aggregate_register_primary_transfer_by_member(strict_client):
    """The wallet "change primary" flow re-registers a handle signed by a MEMBER.

    A DID already under the handle may take over ownership (owner_did moves to the
    new primary), bumping binding_generation. A foreign DID is still rejected.
    """
    domain = "testserver"
    local = "agg-transfer"
    did0 = f"did:wba:{domain}:users:{local}:e1_aaa"
    did1 = f"did:wba:{domain}:users:{local}:e1_bbb"
    key0 = ed25519.Ed25519PrivateKey.generate()
    key1 = ed25519.Ed25519PrivateKey.generate()

    chal0 = await rpc(strict_client, "/did-auth/rpc", "challenge", {"handle": local})
    ad0 = _aggregate_ad(local, domain, did0, [(did0, key0), (did1, key1)], signed_with=key0)
    sig0 = base64.urlsafe_b64encode(key0.sign(chal0["result"]["challenge"].encode())).rstrip(b"=").decode()
    reg0 = await rpc(strict_client, "/did-auth/rpc", "register", {
        "handle": local,
        "ad": ad0,
        "challenge": chal0["result"]["challenge"],
        "challenge_signature": sig0,
    })
    assert "error" not in reg0, reg0
    assert reg0["result"]["did"] == did0

    # Member takeover: key1 (a member DID already in dids) becomes owner.
    chal1 = await rpc(strict_client, "/did-auth/rpc", "challenge", {"handle": local})
    ad1 = _aggregate_ad(local, domain, did1, [(did0, key0), (did1, key1)], signed_with=key1)
    sig1 = base64.urlsafe_b64encode(key1.sign(chal1["result"]["challenge"].encode())).rstrip(b"=").decode()
    reg1 = await rpc(strict_client, "/did-auth/rpc", "register", {
        "handle": local,
        "ad": ad1,
        "challenge": chal1["result"]["challenge"],
        "challenge_signature": sig1,
    })
    assert "error" not in reg1, reg1
    assert reg1["result"]["did"] == did1

    hd = await strict_client.get(f"/.well-known/handle/{local}")
    assert hd.status_code == 200
    body = hd.json()
    assert body["did"] == did1
    assert body["binding_generation"] == "2"

    # A foreign DID instantiating itself under the same handle is rejected.
    didX = f"did:wba:{domain}:users:{local}:e1_zzz"
    keyX = ed25519.Ed25519PrivateKey.generate()
    chalX = await rpc(strict_client, "/did-auth/rpc", "challenge", {"handle": local})
    adX = _aggregate_ad(local, domain, didX, [(did0, key0), (did1, key1), (didX, keyX)], signed_with=keyX)
    sigX = base64.urlsafe_b64encode(keyX.sign(chalX["result"]["challenge"].encode())).rstrip(b"=").decode()
    regX = await rpc(strict_client, "/did-auth/rpc", "register", {
        "handle": local,
        "ad": adX,
        "challenge": chalX["result"]["challenge"],
        "challenge_signature": sigX,
    })
    assert regX.get("error"), regX
    assert regX["error"]["message"] == "handle_already_registered"

