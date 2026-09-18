from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from awiki_open_server.app.settings import Settings
from awiki_open_server.protocol.anp_adapter import AnpProtocolError, did_resolution_authority, did_resolution_url
from awiki_open_server.shared import outbound_http, runtime
from awiki_open_server.shared.errors import InvalidParams


@pytest.mark.parametrize("method", ["wba", "web"])
def test_did_resolution_preserves_full_authority_and_path(method):
    did = f"did:{method}:example.test%3A8443:users:alice"
    assert did_resolution_authority(did) == "example.test:8443"
    assert did_resolution_url(did) == "https://example.test:8443/users/alice/did.json"
    assert did_resolution_url(f"did:{method}:example.test") == "https://example.test/.well-known/did.json"
    assert not runtime._did_belongs_to_domain(did, "example.test")
    assert not runtime._did_belongs_to_domain("did:web:example.test:users:alice", "example.test")


@pytest.mark.parametrize("did", [
    "did:web:example.test%2Fmalicious:alice", "did:web:user%40example.test:alice",
    "did:web:example.test:..:alice", "did:web:example.test:%2e%2e:alice",
    "did:web:example.test:%252e%252e:alice", "did:web:example.test:alice%2F..",
    "did:web:example.test:alice%3Fquery", "did:web:example.test:alice%23fragment",
    "did:web:example.test%3A0:alice", "did:web:example.test%3A65536:alice",
    "did:web:example.test::alice", "did:web:example.test:bad%escape", "did:key:abc",
    "did:web:example.test:%00", "did:web:example.test:%ff", "did:web:example.test%00:alice",
])
def test_did_resolution_rejects_authority_and_path_injection(did):
    with pytest.raises(AnpProtocolError):
        did_resolution_url(did)


def test_endpoint_authority_is_service_bound_and_local_override_is_explicit(tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url="https://local.test", service_did="did:wba:local.test", did_domain="local.test",
                        did_resolver_base_urls={"peer.test:8443": "http://127.0.0.1:18443"})
    service = {"serviceDid": "did:web:peer.test%3A8443", "serviceEndpoint": "https://peer.test:8443/anp-im/rpc"}
    assert runtime.outbound_options(service, settings) == {}
    same_origin_override = Settings(data_dir=tmp_path, public_base_url="https://local.test", service_did="did:wba:local.test", did_domain="local.test",
                                   did_resolver_base_urls={"peer.test:8443": "https://peer.test:8443"})
    assert runtime.outbound_options(service, same_origin_override) == {"allow_private": True}
    with pytest.raises(InvalidParams):
        runtime.outbound_options({**service, "serviceEndpoint": "https://peer.test/anp-im/rpc"}, settings)
    with pytest.raises(InvalidParams):
        runtime.outbound_options({**service, "serviceEndpoint": "https://attacker.test/anp-im/rpc"}, settings)
    assert runtime.outbound_options({**service, "serviceEndpoint": "http://127.0.0.1:18443/anp-im/rpc"}, settings) == {"allow_private": True}


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fc00::1"])
def test_outbound_private_dns_is_rejected_before_connect(monkeypatch, ip):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_kw: [(family, socket.SOCK_STREAM, 6, "", (ip, 443))])
    with pytest.raises(InvalidParams, match="private_address"):
        outbound_http.resolve_target("https://peer.test/did.json")


def test_pinned_connection_does_not_resolve_dns_again_and_retains_tls_hostname(monkeypatch):
    lookups = []
    connections = []
    tls_names = []

    def lookup(*_args, **_kwargs):
        lookups.append(True)
        ip = "93.184.216.34" if len(lookups) == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]

    class Socket:
        def settimeout(self, _value): pass
        def connect(self, address): connections.append(address)
        def close(self): pass

    def wrap(sock, *, server_hostname):
        tls_names.append(server_hostname)
        return sock

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    monkeypatch.setattr(socket, "socket", lambda *_args: Socket())
    monkeypatch.setattr(outbound_http.ssl, "create_default_context", lambda: SimpleNamespace(wrap_socket=wrap))
    target, addresses = outbound_http.resolve_target("https://peer.test/did.json")
    connection = outbound_http.PinnedConnection(target, addresses)
    connection.connect()
    assert len(lookups) == 1
    assert connections == [("93.184.216.34", 443)]
    assert tls_names == ["peer.test"]


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_http_redirect_is_not_followed(monkeypatch, status):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    calls = []
    class Connection:
        def __init__(self, *_args): pass
        def request(self, *args, **kwargs): calls.append((args, kwargs))
        def getresponse(self): return SimpleNamespace(status=status, close=lambda: None)
        def close(self): pass
    monkeypatch.setattr(outbound_http, "PinnedConnection", Connection)
    with pytest.raises(InvalidParams, match="remote_http_status"):
        outbound_http.request_bytes("https://peer.test/rpc", method="POST", body=b"{}")
    assert len(calls) == 1


def test_remote_json_duplicate_members_do_not_choose_a_mode():
    with pytest.raises(InvalidParams, match="remote_json_invalid"):
        runtime._decode_remote_object(b'{"result":{"supported_profiles":[],"supported_profiles":["fake"]}}')


def test_remote_web_document_requires_exact_id(monkeypatch, tmp_path):
    settings = Settings(data_dir=tmp_path, public_base_url="https://local.test", service_did="did:wba:local.test", did_domain="local.test")
    monkeypatch.setattr(runtime, "_http_get_json", lambda _url: {"id": "did:web:other.test:alice"})
    with pytest.raises(InvalidParams, match="did_document_id_mismatch"):
        runtime._fetch_did_document("did:web:peer.test:alice", settings)


def test_web_relative_verification_references_are_normalized_only_for_lookup():
    import copy
    from awiki_open_server.protocol.anp_adapter import generate_service_http_signature_headers, verify_service_http_signature
    from tests.helpers import did_keypair_document

    did = "did:web:peer.test:service"
    key, document = did_keypair_document(did)
    document["verificationMethod"][0]["id"] = "#key-1"
    document["authentication"] = ["#key-1"]
    document["assertionMethod"] = ["#key-1"]
    original = copy.deepcopy(document)
    headers = generate_service_http_signature_headers(
        did_document=document, request_url="https://receiver.test/anp-im/rpc", request_method="POST",
        headers={"Content-Type": "application/json"}, body=b"{}", keyid=f"{did}#key-1",
        sign_callback=lambda body, _keyid: key.sign(body),
    )
    verified = verify_service_http_signature(did_document=document, request_method="POST", request_url="https://receiver.test/anp-im/rpc", headers=headers, body=b"{}")
    assert verified.keyid == f"{did}#key-1"
    assert document == original
    from awiki_open_server.service_identity import validate_origin_proof_structure
    from tests.helpers import origin_proof
    meta = {"profile": "anp.direct.base.v1", "security_profile": "transport-protected", "sender_did": did,
            "target": {"kind": "agent", "did": "did:wba:receiver.test:user"}, "operation_id": "web-origin", "message_id": "web-message", "content_type": "text/plain"}
    body = {"text": "web signer"}
    validate_origin_proof_structure({"scheme": "anp-rfc9421-origin-proof-v1", "origin_proof": origin_proof(meta, body, key)},
                                   method="direct.send", meta=meta, body=body, sender_did_document=document)
    assert document == original
    duplicate = copy.deepcopy(document["verificationMethod"][0])
    duplicate["id"] = f"{did}#key-1"
    document["verificationMethod"].append(duplicate)
    with pytest.raises(AnpProtocolError, match="ambiguous"):
        verify_service_http_signature(did_document=document, request_method="POST", request_url="https://receiver.test/anp-im/rpc", headers=headers, body=b"{}")


def test_outbound_deadline_does_not_reset_when_peer_trickles_bytes(monkeypatch):
    clock = [0.0]
    timeouts = []
    closed = []
    class Socket:
        def settimeout(self, value): timeouts.append(value)
        def recv_into(self, buffer):
            buffer[0] = ord("x")
            return 1
        def close(self): closed.append(True)
    monkeypatch.setattr(outbound_http.time, "monotonic", lambda: clock[0])
    transport = outbound_http._DeadlineSocket(Socket(), 10)
    reader = transport.makefile("rb")
    assert reader.read1(1) == b"x"
    clock[0] = 11
    with pytest.raises(TimeoutError):
        reader.read1(1)
    transport.close()
    reader.close()
    assert timeouts == [10]
    assert closed
