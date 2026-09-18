from __future__ import annotations

import copy

import pytest

from tests.conftest import rpc
from tests.helpers import register
from tests.test_sync_v2_single_device import _register_single_device, _v2_params


async def bootstrap(client, owner, token, instance="only-installation"):
    return await rpc(client, "/im/rpc", "sync.bootstrap", _v2_params(owner, "bootstrap-state", {
        "client_instance_id": instance, "capabilities": {"sync_profile": "anp.sync.local.v2", "event_schema_max": 1},
    }), token=token)


async def delta(client, owner, token, cursor):
    return await rpc(client, "/im/rpc", "sync.delta", _v2_params(owner, "delta-state", {"cursor": cursor, "limit": 100, "reason": "manual_refresh"}), token=token)


@pytest.mark.asyncio
async def test_opaque_conversation_read_state_is_owner_bound_and_monotonic(client):
    owner, token, _, _ = await _register_single_device(client, "state-owner")
    outsider, outsider_token, _, _ = await _register_single_device(client, "state-outsider")
    peer, peer_token = await register(client, "state-peer")
    initial = await bootstrap(client, owner, token)
    await bootstrap(client, outsider, outsider_token)
    messages = []
    for text in ("first", "second"):
        sent = await rpc(client, "/im/rpc", "direct.send", {"recipient_did": owner, "text": text}, token=peer_token)
        messages.append(sent["result"])
    page = await delta(client, owner, token, initial["result"]["cursor"])
    events = page["result"]["events"]
    reference = events[0]["thread_key"]
    assert reference.startswith("conv_") and peer not in reference
    assert events[1]["thread_key"] == reference
    hydrated = await rpc(client, "/im/rpc", "message.get_batch", _v2_params(owner, "batch-owner", {"event_ids": [events[0]["event_id"]]}), token=token)
    assert hydrated["result"]["items"][0]["message"]["conversation_ref"] == reference
    assert "body_json" not in hydrated["result"]["items"][0]["message"]
    stolen = await rpc(client, "/im/rpc", "message.get_batch", _v2_params(outsider, "batch-outsider", {"event_ids": [events[0]["event_id"]]}), token=outsider_token)
    assert stolen["result"]["items"] == []
    forbidden = await rpc(client, "/im/rpc", "sync.thread_after", _v2_params(outsider, "other-history", {"thread_key": reference, "after_server_seq": "0", "limit": 100}), token=outsider_token)
    assert forbidden["error"]["message"] == "sync.conversation_ref_unknown"
    request = {"meta": {"profile": "anp.read_state.local.v1", "security_profile": "transport-protected", "sender_did": owner},
               "body": {"user_did": owner, "thread": {"kind": "direct", "thread_key": reference}, "read_up_to_server_seq": str(messages[1]["server_seq"]), "read_up_to_message_id": messages[1]["message_id"]}}
    marked = await rpc(client, "/im/rpc", "read_state.mark_read", request, token=token)
    assert marked["result"]["thread"] == request["body"]["thread"]
    assert not {"owner_did", "thread_id", "read_up_to_seq"} & marked["result"].keys()
    stale = copy.deepcopy(request)
    stale["body"]["read_up_to_server_seq"] = str(messages[0]["server_seq"])
    stale["body"]["read_up_to_message_id"] = messages[0]["message_id"]
    repeated = await rpc(client, "/im/rpc", "read_state.mark_read", stale, token=token)
    assert repeated["result"]["advanced"] is False
    assert repeated["result"]["read_watermark_message_id"] == messages[1]["message_id"]
    changes = await delta(client, owner, token, page["result"]["next_cursor"])
    assert len(changes["result"]["events"]) == 1
    state = changes["result"]["events"][0]
    assert state["event_type"] == "message.read_state_updated"
    assert not state["ignore_safe"]
    assert state["state_version"] == state["payload"]["state_version"] == "1"
    assert state["payload"]["thread_key"] == reference
    reboot = await bootstrap(client, owner, token)
    assert reboot["result"]["read_state_baseline"][0]["read_up_to_thread_seq"] == str(messages[1]["server_seq"])


@pytest.mark.parametrize("cursor", [{"stream_epoch": "2", "scan_seq": "0"}, {"stream_epoch": "1", "scan_seq": "999"}, {"stream_epoch": "1", "scan_seq": "01"}, {"stream_epoch": "1", "scan_seq": True}])
@pytest.mark.asyncio
async def test_sync_rejects_wrong_epoch_ahead_and_noncanonical_cursor(client, cursor):
    owner, token, _, _ = await _register_single_device(client, "cursor-owner")
    await bootstrap(client, owner, token)
    result = await delta(client, owner, token, cursor)
    assert "error" in result


@pytest.mark.asyncio
async def test_sync_detects_retained_log_gap_without_resetting_binding(client):
    owner, token, _, _ = await _register_single_device(client, "gap-owner")
    peer, peer_token = await register(client, "gap-peer")
    initial = await bootstrap(client, owner, token)
    for text in ("one", "two"):
        await rpc(client, "/im/rpc", "direct.send", {"recipient_did": owner, "text": text}, token=peer_token)
    with client._transport.app.state.store.connect() as conn:
        before = dict(conn.execute("SELECT * FROM sync_v2_bindings WHERE owner_did=?", (owner,)).fetchone())
        conn.execute("DELETE FROM sync_events WHERE owner_did=? AND event_seq=1", (owner,))
    rejected = await delta(client, owner, token, initial["result"]["cursor"])
    assert rejected["error"]["message"] == "sync.retained_log_incomplete"
    assert "error" in await bootstrap(client, owner, token)
    with client._transport.app.state.store.connect() as conn:
        assert dict(conn.execute("SELECT * FROM sync_v2_bindings WHERE owner_did=?", (owner,)).fetchone()) == before
