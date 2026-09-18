from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import time
import urllib.parse

import jcs
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from awiki_open_server.service_identity import content_digest
from tests.conftest import rpc


async def register(client, handle: str):
    data = await rpc(client, "/did-auth/rpc", "register", {"handle": handle})
    return data["result"]["did"], data["result"]["token"]


async def register_with_key(client, handle: str):
    did = f"did:wba:testserver:users:{handle}:e1_default"
    private_key, document = bound_did_keypair_document(did)
    did = document["id"]
    document["service"][0]["serviceEndpoint"] = "http://testserver/anp-im/rpc"
    document["service"][0]["serviceDid"] = "did:wba:testserver"
    document = sign_did_document(document, private_key)
    data = await rpc(client, "/did-auth/rpc", "register", {"handle": handle, "did_document": document})
    return data["result"]["did"], data["result"]["token"], private_key, document


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _multikey(public_key: ed25519.Ed25519PublicKey) -> str:
    import base58

    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "z" + base58.b58encode(b"\xed\x01" + raw).decode("ascii")


def sign_did_document(
    document: dict,
    private_key: ed25519.Ed25519PrivateKey,
    *,
    key_id: str | None = None,
    created: str = "2026-07-10T00:00:00Z",
) -> dict:
    did = document["id"]
    proof = {
        "type": "DataIntegrityProof",
        "created": created,
        "verificationMethod": key_id or f"{did}#key-1",
        "proofPurpose": "assertionMethod",
        "cryptosuite": "eddsa-jcs-2022",
    }
    unsigned = copy.deepcopy({k: v for k, v in document.items() if k != "proof"})
    signing_input = hashlib.sha256(jcs.canonicalize(proof)).digest() + hashlib.sha256(jcs.canonicalize(unsigned)).digest()
    signed = copy.deepcopy(document)
    signed["proof"] = {**proof, "proofValue": _b64u(private_key.sign(signing_input))}
    return signed


def did_keypair_document(did: str) -> tuple[ed25519.Ed25519PrivateKey, dict]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    key_id = f"{did}#key-1"
    return private_key, {
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": _multikey(private_key.public_key()),
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "service": [
            {
                "id": f"{did}#anp-message",
                "type": "ANPMessageService",
                "serviceEndpoint": "https://awiki.info/anp-im/rpc",
                "serviceDid": "did:wba:awiki.info",
                "profiles": ["anp.direct.base.v1", "anp.group.base.v1", "anp.group.base.v2"],
                "securityProfiles": ["transport-protected"],
            }
        ],
    }


def bound_did_keypair_document(did: str) -> tuple[ed25519.Ed25519PrivateKey, dict]:
    from awiki_open_server.protocol.anp_adapter import ed25519_root_fingerprint

    private_key, document = did_keypair_document(did)
    bound_did = f"{did.rsplit(':', 1)[0]}:e1_{ed25519_root_fingerprint(private_key.public_key())}"
    return private_key, json.loads(json.dumps(document).replace(did, bound_did))


def single_device_document(did: str, *, device_id: str = "device-primary", root_key=None) -> tuple:
    """Build distinct root/device keys for registration, without encrypted traffic."""
    from anp.authentication.device_manifest import DeviceManifestEntry, build_vnext_did_document
    from anp.authentication.did_wba import compute_multikey_fingerprint
    from cryptography.hazmat.primitives.asymmetric import x25519

    root, document = did_keypair_document(did)
    root = root_key or root
    did = f"{did.rsplit(':', 1)[0]}:e1_{compute_multikey_fingerprint(root.public_key())}"
    document["service"][0]["id"] = f"{did}#anp-message"
    document["verificationMethod"][0].update(
        id=f"{did}#key-1", controller=did, publicKeyMultibase=_multikey(root.public_key()),
    )
    signing = ed25519.Ed25519PrivateKey.generate()
    agreement = x25519.X25519PrivateKey.generate()
    signing_id = f"{did}#{device_id}-sign"
    agreement_id = f"{did}#{device_id}-agreement"
    entry = DeviceManifestEntry(
        device_id=device_id,
        signing_key_id=signing_id,
        e2ee_key_id=agreement_id,
        profiles=("anp.core.binding.v1", "anp.identity.discovery.v1", "anp.direct.base.v1", "anp.group.base.v1"),
    )
    document = build_vnext_did_document(
        {"id": did, "service": document["service"]},
        f"{did}#key-1",
        document["verificationMethod"][0],
        entry,
        {"id": signing_id, "type": "Multikey", "controller": did, "publicKeyMultibase": _multikey(signing.public_key())},
        {
            "id": agreement_id,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": _b64u(agreement.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))},
        },
    )
    return root, signing, document


def origin_proof(meta: dict, body: dict, private_key: ed25519.Ed25519PrivateKey | None = None, method: str = "direct.send", *, created: int | None = None, ttl_seconds: int = 300) -> dict:
    private_key = private_key or ed25519.Ed25519PrivateKey.generate()
    key_id = f"{meta['sender_did']}#key-1"
    digest = content_digest(jcs.canonicalize({"method": method, "meta": meta, "body": body}))
    created = int(time.time()) if created is None else created
    signature_input = (
        'sig1=("@method" "@target-uri" "content-digest");'
        f'created={created};expires={created + ttl_seconds};keyid="{key_id}"'
    )
    target = meta["target"]
    proof_base = "\n".join(
        [
            f'"@method": {method}',
            f'"@target-uri": anp://{target["kind"]}/{urllib.parse.quote(target["did"], safe="-._~")}',
            f'"content-digest": {digest}',
            f'"@signature-params": {signature_input.split("=", 1)[1].strip()}',
        ]
    ).encode()
    return {
        "contentDigest": digest,
        "signatureInput": signature_input,
        "signature": f"sig1=:{_b64(private_key.sign(proof_base))}:",
    }


def remote_direct_result(payload: dict, *, target_did: str | None = None, overrides: dict | None = None) -> dict:
    meta = payload["params"]["meta"]
    result = {
        "accepted": True,
        "delivery_state": "accepted",
        "final_acceptance": True,
        "message_id": meta["message_id"],
        "operation_id": meta["operation_id"],
        "target_did": target_did or meta["target"]["did"],
        "accepted_at": datetime.now(timezone.utc).isoformat(),
    }
    if overrides:
        result.update(overrides)
    return {"jsonrpc": "2.0", "result": result, "id": payload["id"]}


def runtime_capabilities(service_did: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "result": {
            "service_did": service_did,
            "profiles": [
                "anp.core.binding.v1",
                "anp.identity.discovery.v1",
                "anp.direct.base.v1",
                "anp.group.base.v1",
                "anp.group.base.v2",
                "anp.attachment.v1",
                "anp.federation.relay.v1",
            ],
            "security_profiles": ["transport-protected"],
            "transports": ["http"],
        },
        "id": "discovery-test",
    }
