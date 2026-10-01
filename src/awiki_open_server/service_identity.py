from __future__ import annotations

import base64
import base58
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from typing import Any

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from awiki_open_server.protocol.anp_adapter import (
    AnpProtocolError,
    build_content_digest as anp_build_content_digest,
    ed25519_root_fingerprint,
    find_verification_method,
    generate_service_http_signature_headers,
    has_verification_method,
    is_verification_method_authorized,
    signature_keyid,
    verify_origin_proof,
    verify_service_http_signature,
)
from awiki_open_server.protocol.registry import STANDARD_PROFILES
from awiki_open_server.shared.errors import InvalidParams, Unauthorized


def _b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode((value + padding).encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise InvalidParams("did_document_proof_value_invalid") from exc


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _canonical_json(value: Any) -> bytes:
    return jcs.canonicalize(value)


def _multikey_ed25519(public_key: ed25519.Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    # multicodec ed25519-pub varint prefix: 0xed 0x01
    return "z" + base58.b58encode(b"\xed\x01" + raw).decode("ascii")


def _ed25519_public_key_from_multikey(value: Any) -> ed25519.Ed25519PublicKey:
    if not isinstance(value, str) or not value.startswith("z"):
        raise InvalidParams("did_document_proof_public_key_not_supported")
    try:
        decoded = base58.b58decode(value[1:])
    except Exception as exc:
        raise InvalidParams("did_document_proof_public_key_invalid") from exc
    if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        raise InvalidParams("did_document_proof_public_key_not_supported")
    return ed25519.Ed25519PublicKey.from_public_bytes(decoded[2:])


def _encode_proof_value(signature: bytes) -> str:
    """`proofValue` as base58-btc multibase, per ANP-03 §2.5.5.

    §2.5.5 fixes the `e1_` DID Document proof profile to DataIntegrityProof +
    eddsa-jcs-2022 and requires `proofValue` in base58-btc multibase (`z...`).
    The pinned ANP SDK verifies `e1_` proofs through
    `anp.proof.proof.verify_w3c_proof`, which base64url-decodes instead, so the
    SDK's binding check is replaced by `validate_e1_document_binding` rather
    than treated as authoritative.
    """
    return "z" + base58.b58encode(signature).decode("ascii")


def _decode_proof_value(value: Any, *, code: str = "did_document_proof_value_invalid") -> bytes:
    """Base58-btc-decode a `proofValue` written as multibase (`z...`)."""
    if not isinstance(value, str) or not value.startswith("z"):
        raise InvalidParams(code)
    try:
        return base58.b58decode(value[1:])
    except (ValueError, TypeError) as exc:
        raise InvalidParams(code) from exc


def _load_ed25519_private_key(pem: str) -> ed25519.Ed25519PrivateKey:
    key = load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise InvalidParams("service_private_key_must_be_ed25519")
    return key


def generate_ed25519_private_key_pem() -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


def _service_did_domain(service_did: str) -> str:
    parts = service_did.split(":")
    if len(parts) != 3 or parts[0] != "did" or parts[1] != "wba" or not parts[2]:
        raise InvalidParams("service_did_must_be_bare_wba_domain")
    return parts[2]


def _service_entry(did: str, endpoint: str) -> dict[str, Any]:
    return {
        "id": f"{did}#anp-message",
        "type": "ANPMessageService",
        "serviceEndpoint": endpoint,
        "serviceDid": did,
        "profiles": list(STANDARD_PROFILES),
        "securityProfiles": ["transport-protected"],
        "authSchemes": ["bearer", "didwba"],
    }


def _anp_message_services(document: dict[str, Any]) -> list[dict[str, Any]]:
    services = document.get("service")
    if not isinstance(services, list):
        return []
    return [
        service
        for service in services
        if isinstance(service, dict) and service.get("type") == "ANPMessageService"
    ]


def _validate_service_did_document(document: dict[str, Any], service_did: str, endpoint: str, key_id: str) -> None:
    if document.get("id") != service_did:
        raise InvalidParams("service_did_document_id_mismatch")
    services = _anp_message_services(document)
    if len(services) != 1:
        raise InvalidParams("service_did_document_requires_single_anp_message_service")
    service = services[0]
    if service.get("serviceEndpoint") != endpoint:
        raise InvalidParams(
            "service_did_document_endpoint_mismatch",
            data={"actual": service.get("serviceEndpoint"), "expected": endpoint},
        )
    if service.get("serviceDid") != service_did:
        raise InvalidParams(
            "service_did_document_service_did_mismatch",
            data={"actual": service.get("serviceDid"), "expected": service_did},
        )
    if service.get("authSchemes") != ["bearer", "didwba"]:
        raise InvalidParams(
            "service_did_document_auth_schemes_mismatch",
            data={"actual": service.get("authSchemes"), "expected": ["bearer", "didwba"]},
        )
    if not has_verification_method(document, key_id):
        raise InvalidParams("service_did_document_verification_method_missing")
    if not is_verification_method_authorized(document, key_id, "authentication"):
        raise InvalidParams("service_did_document_authentication_missing")


def _sign_did_document(document: dict[str, Any], key: ed25519.Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    proof = {
        "type": "DataIntegrityProof",
        "created": created,
        "verificationMethod": key_id,
        "proofPurpose": "assertionMethod",
        "cryptosuite": "eddsa-jcs-2022",
    }
    unsigned = {k: v for k, v in document.items() if k != "proof"}
    signing_input = _sha256(_canonical_json(proof)) + _sha256(_canonical_json(unsigned))
    signed = dict(document)
    signed["proof"] = {**proof, "proofValue": _encode_proof_value(key.sign(signing_input))}
    return signed


def verify_did_document_data_integrity_proof(
    document: dict[str, Any],
    *,
    expected_did: str | None = None,
) -> None:
    did = document.get("id")
    if not isinstance(did, str) or not did:
        raise InvalidParams("did_document_id_required")
    if expected_did is not None and did != expected_did:
        raise InvalidParams("did_document_id_mismatch", data={"did": expected_did, "document_id": did})

    proof = document.get("proof")
    if not isinstance(proof, dict):
        raise InvalidParams("did_document_proof_required")
    if proof.get("type") != "DataIntegrityProof":
        raise InvalidParams("did_document_proof_type_not_supported")
    if proof.get("cryptosuite") != "eddsa-jcs-2022":
        raise InvalidParams("did_document_proof_cryptosuite_not_supported")
    if proof.get("proofPurpose") != "assertionMethod":
        raise InvalidParams("did_document_proof_purpose_not_supported")
    if not isinstance(proof.get("created"), str) or not proof.get("created"):
        raise InvalidParams("did_document_proof_created_required")

    verification_method = proof.get("verificationMethod")
    if not isinstance(verification_method, str) or not verification_method.startswith(f"{did}#"):
        raise InvalidParams("did_document_proof_verification_method_mismatch")
    method = find_verification_method(document, verification_method)
    if method is None:
        raise InvalidParams("did_document_proof_verification_method_missing")
    if method.get("controller") not in (None, did):
        raise InvalidParams("did_document_proof_verification_method_controller_mismatch")
    if not is_verification_method_authorized(document, verification_method, "assertionMethod"):
        raise InvalidParams("did_document_proof_verification_method_unauthorized")
    if method.get("type") != "Multikey":
        raise InvalidParams("did_document_proof_public_key_not_supported")

    public_key = _ed25519_public_key_from_multikey(method.get("publicKeyMultibase"))
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str) or not proof_value:
        raise InvalidParams("did_document_proof_value_required")
    signature = _decode_proof_value(proof_value)
    if len(signature) != 64:
        raise InvalidParams("did_document_proof_value_invalid")
    proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
    unsigned = {k: v for k, v in document.items() if k != "proof"}
    signing_input = _sha256(_canonical_json(proof_options)) + _sha256(_canonical_json(unsigned))
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise InvalidParams("did_document_proof_invalid") from exc


def validate_e1_document_binding(document: dict[str, Any]) -> None:
    """ANP-03 §2.5.5 binding check for an active `e1_` DID Document.

    The document's own `proof` must verify, and the key that signed it must hash
    to the DID's trailing `e1_<fingerprint>` path segment, so path binding,
    public-key binding and document integrity are checked as one thing.
    """
    did = document.get("id")
    if not isinstance(did, str) or not did:
        raise InvalidParams("did_document_id_required")
    segment = did.rsplit(":", 1)[-1]
    if not segment.startswith("e1_"):
        raise InvalidParams("did_document_binding_invalid")
    verify_did_document_data_integrity_proof(document)
    method = find_verification_method(document, document["proof"]["verificationMethod"])
    public_key = _ed25519_public_key_from_multikey(method.get("publicKeyMultibase"))
    if ed25519_root_fingerprint(public_key) != segment[3:]:
        raise InvalidParams("did_document_e1_binding_mismatch")


def did_document_proof_issue(document: Any) -> str | None:
    """The error code when a stored DID Document's proof no longer verifies.

    `proofValue` must be base58-btc multibase (ANP-03 §2.5.5). Documents stored
    under the base64url encoding that preceded that rule still resolve, but
    neither this server nor a peer can verify them, so startup reports them
    rather than letting resolution hand out an unverifiable identity. Documents
    without a proof are local-compatibility identities, a separate case.
    """
    if not isinstance(document, Mapping) or not isinstance(document.get("proof"), Mapping):
        return None
    payload = dict(document)
    try:
        if str(payload.get("id", "")).rsplit(":", 1)[-1].startswith("e1_"):
            validate_e1_document_binding(payload)
        else:
            verify_did_document_data_integrity_proof(payload)
    except InvalidParams as exc:
        return str(exc)
    return None


def verify_object_proof(
    document: dict[str, Any],
    *,
    issuer_did: str,
    issuer_did_document: dict[str, Any],
) -> None:
    """Verify an Appendix-B object proof, e.g. a Group receipt.

    The signing input is identical to the DID Document DataIntegrityProof — the
    difference is only who signs: the key is authorized by `issuer_did_document`
    through `assertionMethod` rather than being the document's own binding key.
    `proofValue` is base58-btc multibase here too (ANP-03 §2.5.5); the pinned
    SDK's own object-proof verifier re-checks the issuer document's `e1_` binding
    with base64url, so it cannot be used for base58 issuers.
    """
    if issuer_did_document.get("id") != issuer_did:
        raise InvalidParams("object_proof_issuer_mismatch")

    proof = document.get("proof")
    if not isinstance(proof, dict):
        raise InvalidParams("object_proof_required")
    if proof.get("type") != "DataIntegrityProof":
        raise InvalidParams("object_proof_type_not_supported")
    if proof.get("cryptosuite") != "eddsa-jcs-2022":
        raise InvalidParams("object_proof_cryptosuite_not_supported")
    if proof.get("proofPurpose") != "assertionMethod":
        raise InvalidParams("object_proof_purpose_not_supported")
    if not isinstance(proof.get("created"), str) or not proof.get("created"):
        raise InvalidParams("object_proof_created_required")

    verification_method = proof.get("verificationMethod")
    if not isinstance(verification_method, str) or not verification_method.startswith(f"{issuer_did}#"):
        raise InvalidParams("object_proof_verification_method_mismatch")
    if not is_verification_method_authorized(issuer_did_document, verification_method, "assertionMethod"):
        raise InvalidParams("object_proof_verification_method_unauthorized")
    method = find_verification_method(issuer_did_document, verification_method)
    if method is None:
        raise InvalidParams("object_proof_verification_method_missing")
    if method.get("type") != "Multikey":
        raise InvalidParams("object_proof_public_key_not_supported")

    public_key = _ed25519_public_key_from_multikey(method.get("publicKeyMultibase"))
    signature = _decode_proof_value(proof.get("proofValue"), code="object_proof_value_invalid")
    if len(signature) != 64:
        raise InvalidParams("object_proof_value_invalid")
    proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
    unsigned = {k: v for k, v in document.items() if k != "proof"}
    signing_input = _sha256(_canonical_json(proof_options)) + _sha256(_canonical_json(unsigned))
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise InvalidParams("object_proof_invalid") from exc


def verify_handle_ad_proof(ad: dict[str, Any], submitting_did: str) -> None:
    """Verify a handle-level aggregate `ad.json` self-sign.

    Unlike `verify_did_document_data_integrity_proof`, this document is NOT a
    single DID document — it aggregates many distinct `e1_<fp>` DIDs under one
    handle, so its verification methods carry different controllers. The proof is
    signed by the *submitting* key (`<submitting_did>#key-1`), which must be one
    of the DIDs listed in `ad.dids`. That key's possession is additionally proven
    by the one-time challenge signature at the register layer.
    """
    did = ad.get("id")
    if not isinstance(did, str) or not did:
        raise InvalidParams("handle_ad_id_required")

    proof = ad.get("proof")
    if not isinstance(proof, dict):
        raise InvalidParams("handle_ad_proof_required")
    if proof.get("type") != "DataIntegrityProof":
        raise InvalidParams("handle_ad_proof_type_not_supported")
    if proof.get("cryptosuite") != "eddsa-jcs-2022":
        raise InvalidParams("handle_ad_proof_cryptosuite_not_supported")
    if proof.get("proofPurpose") != "assertionMethod":
        raise InvalidParams("handle_ad_proof_purpose_not_supported")
    if not isinstance(proof.get("created"), str) or not proof.get("created"):
        raise InvalidParams("handle_ad_proof_created_required")

    verification_method = proof.get("verificationMethod")
    expected_vm = f"{submitting_did}#key-1"
    if verification_method != expected_vm:
        raise InvalidParams("handle_ad_proof_verification_method_mismatch")

    dids = ad.get("dids", [])
    if not isinstance(dids, list) or submitting_did not in dids:
        raise InvalidParams("handle_ad_submitting_did_missing")

    method = find_verification_method(ad, verification_method)
    if method is None:
        raise InvalidParams("handle_ad_proof_verification_method_missing")
    if method.get("controller") not in (None, submitting_did):
        raise InvalidParams("handle_ad_proof_verification_method_controller_mismatch")
    if not is_verification_method_authorized(ad, verification_method, "assertionMethod"):
        raise InvalidParams("handle_ad_proof_verification_method_unauthorized")
    if method.get("type") != "Multikey":
        raise InvalidParams("handle_ad_proof_public_key_not_supported")

    public_key = _ed25519_public_key_from_multikey(method.get("publicKeyMultibase"))
    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str) or not proof_value:
        raise InvalidParams("handle_ad_proof_value_required")
    signature = _decode_proof_value(proof_value, code="handle_ad_proof_value_invalid")
    if len(signature) != 64:
        raise InvalidParams("handle_ad_proof_value_invalid")
    proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
    unsigned = {k: v for k, v in ad.items() if k != "proof"}
    signing_input = _sha256(_canonical_json(proof_options)) + _sha256(_canonical_json(unsigned))
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise InvalidParams("handle_ad_proof_invalid") from exc


def build_service_did_document(service_did: str, endpoint: str, private_key_pem: str) -> dict[str, Any]:
    _service_did_domain(service_did)
    key = _load_ed25519_private_key(private_key_pem)
    key_id = f"{service_did}#key-1"
    public_key = key.public_key()
    document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/data-integrity/v2",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": service_did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Multikey",
                "controller": service_did,
                "publicKeyMultibase": _multikey_ed25519(public_key),
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "service": [_service_entry(service_did, endpoint)],
    }
    return _sign_did_document(document, key, key_id)


def content_digest(body: bytes) -> str:
    return anp_build_content_digest(body)


def _header_value(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def verify_peer_http_signature(
    *,
    service_did_document: dict[str, Any],
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
) -> str:
    try:
        verified = verify_service_http_signature(
            did_document=service_did_document,
            request_method=method,
            request_url=url,
            headers=headers,
            body=body,
        )
    except AnpProtocolError as exc:
        raise Unauthorized(exc.code, data={"detail": exc.detail}) from exc
    return verified.keyid


@dataclass(frozen=True)
class ServiceIdentity:
    did: str
    did_document: dict[str, Any]
    private_key_pem: str
    verification_method_id: str

    def sign_headers(self, url: str, method: str, base_headers: dict[str, str], body: bytes) -> dict[str, str]:
        key = _load_ed25519_private_key(self.private_key_pem)

        def sign_callback(signature_base_bytes: bytes, _: str) -> bytes:
            return key.sign(signature_base_bytes)

        try:
            return generate_service_http_signature_headers(
                did_document=self.did_document,
                request_url=url,
                request_method=method,
                sign_callback=sign_callback,
                headers=base_headers,
                body=body,
                keyid=self.verification_method_id,
            )
        except AnpProtocolError as exc:
            raise Unauthorized(exc.code, data={"detail": exc.detail}) from exc


def service_identity_from_settings(
    *,
    service_did: str,
    endpoint: str,
    private_key_pem: str | None,
    document_json: str | None = None,
) -> ServiceIdentity | None:
    if not private_key_pem:
        return None
    document = json.loads(document_json) if document_json else build_service_did_document(service_did, endpoint, private_key_pem)
    key_id = f"{service_did}#key-1"
    _validate_service_did_document(document, service_did, endpoint, key_id)
    return ServiceIdentity(
        did=service_did,
        did_document=document,
        private_key_pem=private_key_pem,
        verification_method_id=key_id,
    )


def require_origin_proof(auth: dict[str, Any] | None) -> None:
    if not isinstance(auth, dict) or not isinstance(auth.get("origin_proof"), dict):
        raise Unauthorized("missing_origin_proof")


def validate_origin_proof_structure(
    auth: dict[str, Any] | None,
    *,
    method: str,
    meta: dict[str, Any],
    body: dict[str, Any],
    sender_did_document: dict[str, Any] | None = None,
    verified_at: datetime | None = None,
) -> None:
    require_origin_proof(auth)
    proof = auth["origin_proof"]
    sender_did = meta.get("sender_did")
    if not isinstance(sender_did, str) or not sender_did:
        raise Unauthorized("origin_proof_sender_did_required")
    try:
        verify_origin_proof(
            origin_proof=proof,
            method=method,
            meta=meta,
            body=body,
            did_document=sender_did_document,
            expected_signer_did=sender_did,
            verified_at=verified_at,
        )
    except AnpProtocolError as exc:
        raise Unauthorized(exc.code, data={"detail": exc.detail}) from exc


def require_signed_peer_request(headers: dict[str, str], *, allow_unsigned_dev: bool) -> None:
    if allow_unsigned_dev:
        return
    if not _header_value(headers, "Signature-Input") or not _header_value(headers, "Signature"):
        raise Unauthorized("missing_peer_http_signature")
    try:
        signature_keyid(headers)
    except AnpProtocolError as exc:
        raise Unauthorized(exc.code, data={"detail": exc.detail}) from exc


def load_private_key_setting(value: str | None, path: str | None) -> str | None:
    if value:
        return value.replace("\\n", "\n")
    if path:
        with open(os.path.expanduser(path), encoding="utf-8") as handle:
            return handle.read()
    return None
