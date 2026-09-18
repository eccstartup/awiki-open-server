from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tests.conftest import rpc
from tests.helpers import sign_did_document, single_device_document


FIXTURES = json.loads((Path(__file__).parent / "fixtures/community-sync-v1.json").read_text())["cases"]


async def registered_device(client):
    did = "did:wba:testserver:users:community-contract:e1_fixture"
    root, _, document = single_device_document(did, device_id="device-alice-1")
    did = document["id"]
    document["service"][0].update(serviceEndpoint="http://testserver/anp-im/rpc", serviceDid="did:wba:testserver")
    result = await rpc(client, "/user-service/v1/did-auth/rpc", "register", {
        "handle": "community-contract", "did_document": sign_did_document(document, root),
    })
    assert "error" not in result
    return did, result["result"]["user_id"], result["result"]["access_token"]


async def call_fixture(client, case, did, token):
    request = copy.deepcopy(FIXTURES[case]["request"])
    request["params"]["meta"]["sender_did"] = did
    response = await client.post("/im/rpc", json=request, headers={
        "Authorization": f"Bearer {token}", "X-AWiki-Client-Version": "awiki-cli/0815/1.0.52",
    })
    assert response.status_code == 200
    return response.json()


def bindings(client):
    with client._transport.app.state.store.connect() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM sync_v2_bindings ORDER BY owner_did")]


@pytest.mark.asyncio
async def test_community_discovery_is_explicit_local_only_and_read_only(client):
    response = await client.post("/im/rpc", json=FIXTURES["C01"]["request"])
    result = response.json()["result"]
    assert "awiki.message-sync.explicit-negotiation.v1" in result["supported_profiles"]
    assert "sync.snapshot_paging.v1" in result["supported_profiles"]
    assert "awiki.open.single-device-sync.v1" not in result["supported_profiles"]
    assert result["features"]["ordinary_sync"]["snapshot"] == "sync.snapshot_paging.v1"
    assert result["features"]["ordinary_sync"]["lanes"] == []
    public = await client.post("/anp-im/rpc", json=FIXTURES["C01"]["request"])
    assert "ordinary_sync" not in public.json()["result"]["features"]
    assert "sync.snapshot_paging.v1" not in public.json()["result"]["supported_profiles"]
    assert bindings(client) == []


@pytest.mark.asyncio
async def test_community_bootstrap_fixture_and_repeat_preserve_one_binding(client):
    did, user_id, token = await registered_device(client)
    actual = await call_fixture(client, "C02", did, token)
    expected = copy.deepcopy(FIXTURES["C02"]["response"])
    expected["result"]["account_id"] = user_id
    expected["result"]["server_time"] = actual["result"]["server_time"]
    assert actual == expected
    before = bindings(client)
    repeated = await call_fixture(client, "C02", did, token)
    assert repeated["result"]["cursor"] == actual["result"]["cursor"]
    assert bindings(client) == before
    assert len(before) == 1


@pytest.mark.asyncio
async def test_community_second_installation_fixture_has_no_binding_side_effect(client):
    did, _, token = await registered_device(client)
    await call_fixture(client, "C02", did, token)
    before = bindings(client)
    rejected = await call_fixture(client, "C03", did, token)
    assert rejected == FIXTURES["C03"]["response"]
    assert bindings(client) == before


@pytest.mark.asyncio
async def test_community_snapshot_request_fixture_does_not_create_binding(client):
    did, _, token = await registered_device(client)
    assert await call_fixture(client, "C04", did, token) == FIXTURES["C04"]["response"]
    assert bindings(client) == []


@pytest.mark.asyncio
async def test_community_duplicate_request_members_cannot_hide_snapshot_request(client):
    did, _, token = await registered_device(client)
    request = copy.deepcopy(FIXTURES["C02"]["request"])
    request["params"]["meta"]["sender_did"] = did
    raw = json.dumps(request).replace('"event_schema_max": 1', '"event_schema_max": 3, "event_schema_max": 1')
    response = await client.post("/im/rpc", content=raw, headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {token}",
    })
    assert response.json()["error"]["code"] == -32700
    assert bindings(client) == []


@pytest.mark.asyncio
async def test_community_malformed_meta_cannot_fall_back_to_legacy(client):
    did, _, token = await registered_device(client)
    request = copy.deepcopy(FIXTURES["C02"]["request"])
    request["params"]["meta"] = None
    response = await client.post("/im/rpc", json=request, headers={"Authorization": f"Bearer {token}"})
    assert response.json()["error"]["data"]["anp_code"] == "anp.invalid_params_shape"
    assert bindings(client) == []


@pytest.mark.asyncio
async def test_community_invalid_device_token_matches_auth_failure_fixture(client):
    request = copy.deepcopy(FIXTURES["C02"]["request"])
    response = await client.post("/im/rpc", json=request, headers={"Authorization": "Bearer invalid-fixture-token"})
    assert response.status_code == 401
    assert response.json() == FIXTURES["C05"]
    assert bindings(client) == []
