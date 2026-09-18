from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from awiki_open_server.messaging.groups.migration import apply_group, cancel_group, inspect_group, prepare_group
from awiki_open_server.shared.errors import Conflict, InvalidParams
from tests.helpers import register_with_key
from tests.test_group_v2 import group_call


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def historical_state(app, group):
    with app.state.store.connect() as conn:
        return {
            "messages": digest([dict(row) for row in conn.execute("SELECT * FROM hosted_group_messages WHERE group_did=? ORDER BY group_event_seq", (group,))]),
            "events": digest([dict(row) for row in conn.execute("SELECT * FROM hosted_group_events WHERE group_did=? ORDER BY group_event_seq", (group,))]),
            "members": digest([dict(row) for row in conn.execute("SELECT * FROM hosted_group_members WHERE group_did=? ORDER BY agent_did", (group,))]),
            "key": hashlib.sha256(Path(conn.execute("SELECT key_reference FROM group_did_documents WHERE group_did=?", (group,)).fetchone()[0]).read_bytes()).hexdigest(),
        }


@pytest.mark.asyncio
async def test_group_migration_keeps_identity_history_and_roles_and_is_idempotent(client, tmp_path):
    app = client._transport.app
    owner = await register_with_key(client, "migration-owner")
    created = await group_call(client, owner, "group.create", "did:wba:testserver", "migration-create", {"creator_handle": "migration-owner.testserver"}, profile="anp.group.base.v1")
    group = created["result"]["group_did"]
    await group_call(client, owner, "group.send", group, "before-migration", {"payload": {"text": "retained"}}, profile="anp.group.base.v1")
    history = historical_state(app, group)
    original = inspect_group(app.state.settings, group)
    assert original["unresolved_deliveries"] == []
    prepared = prepare_group(app.state.settings, group, original["plan_digest"], tmp_path.parent / f"{tmp_path.name}-backup")
    assert prepared["protocol_state"] == "quiescing"
    rejected = await group_call(client, owner, "group.send", group, "during-migration", {"payload": {"text": "denied"}}, profile="anp.group.base.v1")
    assert rejected["error"]["message"] == "group.protocol_upgrade_in_progress"
    first = apply_group(app.state.settings, group, original["plan_digest"])
    assert first == apply_group(app.state.settings, group, original["plan_digest"])
    assert historical_state(app, group) == history
    current = inspect_group(app.state.settings, group)
    assert current["wire_profile"] == "anp.group.base.v2"
    assert current["document_version"] == original["document_version"] + 1
    assert current["group_event_seq"] == original["group_event_seq"]
    assert current["group_state_version"] == original["group_state_version"]
    with app.state.store.connect() as conn:
        document = json.loads(conn.execute("SELECT document_json FROM group_did_documents WHERE group_did=?", (group,)).fetchone()[0])
        assert document["id"] == group
        assert document["service"][0]["profiles"] == ["anp.group.base.v2"]
    sent = await group_call(client, owner, "group.send", group, "after-migration", {"payload": {"text": "continued"}})
    assert sent["result"]["accepted"] is True
    old = await group_call(client, owner, "group.send", group, "old-after-migration", {"payload": {"text": "denied"}}, profile="anp.group.base.v1")
    assert old["error"]["message"] == "group.protocol_mismatch"
    with pytest.raises(Conflict):
        cancel_group(app.state.settings, group, original["plan_digest"])


@pytest.mark.asyncio
async def test_group_migration_rejects_stale_plan_and_tampered_backup(client, tmp_path):
    app = client._transport.app
    owner = await register_with_key(client, "migration-backup")
    created = await group_call(client, owner, "group.create", "did:wba:testserver", "backup-create", {}, profile="anp.group.base.v1")
    group = created["result"]["group_did"]
    old = inspect_group(app.state.settings, group)
    await group_call(client, owner, "group.send", group, "changes-plan", {"payload": {"text": "change"}}, profile="anp.group.base.v1")
    backup = tmp_path.parent / f"{tmp_path.name}-backup"
    with pytest.raises(Conflict, match="plan_changed"):
        prepare_group(app.state.settings, group, old["plan_digest"], backup)
    assert not backup.exists()
    current = inspect_group(app.state.settings, group)
    prepare_group(app.state.settings, group, current["plan_digest"], backup)
    (backup / "manifest.json").write_text("{}")
    with pytest.raises(InvalidParams, match="backup_changed"):
        apply_group(app.state.settings, group, current["plan_digest"])
    assert inspect_group(app.state.settings, group)["wire_profile"] == "anp.group.base.v1"
    cancel_group(app.state.settings, group, current["plan_digest"])
    assert inspect_group(app.state.settings, group)["protocol_state"] == "active"


@pytest.mark.asyncio
async def test_group_migration_does_not_skip_unresolved_delivery(client, tmp_path, monkeypatch):
    app = client._transport.app
    owner = await register_with_key(client, "migration-backlog")
    created = await group_call(client, owner, "group.create", "did:wba:testserver", "backlog-create", {}, profile="anp.group.base.v1")
    group = created["result"]["group_did"]
    # Model a delivery failure at the persistence boundary. Real old-version
    # producer/drain and public peer interoperability remain separate gates.
    with app.state.store.connect() as conn:
        conn.execute("""INSERT INTO group_delivery_outbox(delivery_id, group_did, group_event_seq, target_did,
            target_service_did, method, envelope_json, status, next_attempt_at, created_at, updated_at)
            VALUES ('blocked-fixture', ?, 1, 'did:wba:peer.test:member', 'did:wba:peer.test',
            'group.incoming', '{"params":{"meta":{"profile":"anp.group.base.v1"}}}', 'dead', '', '', '')""", (group,))
    current = inspect_group(app.state.settings, group)
    before = historical_state(app, group)
    prepare_group(app.state.settings, group, current["plan_digest"], tmp_path.parent / f"{tmp_path.name}-backup")
    with pytest.raises(Conflict, match="outbox_not_drained"):
        apply_group(app.state.settings, group, current["plan_digest"])
    assert historical_state(app, group) == before
    assert inspect_group(app.state.settings, group)["unresolved_deliveries"][0]["status"] == "dead"


@pytest.mark.asyncio
async def test_cutover_failure_rolls_back_both_document_and_protocol_state(client, tmp_path):
    import sqlite3
    app = client._transport.app
    owner = await register_with_key(client, "migration-atomic")
    created = await group_call(client, owner, "group.create", "did:wba:testserver", "atomic-create", {}, profile="anp.group.base.v1")
    group = created["result"]["group_did"]
    before = inspect_group(app.state.settings, group)
    prepare_group(app.state.settings, group, before["plan_digest"], tmp_path.parent / f"{tmp_path.name}-backup")
    with app.state.store.connect() as conn:
        conn.execute("CREATE TRIGGER cutover_failure BEFORE UPDATE OF wire_profile ON hosted_groups BEGIN SELECT RAISE(ABORT, 'test cutover interrupted'); END")
    with pytest.raises(sqlite3.IntegrityError):
        apply_group(app.state.settings, group, before["plan_digest"])
    failed = inspect_group(app.state.settings, group)
    assert failed["plan_digest"] == before["plan_digest"]
    assert failed["wire_profile"] == "anp.group.base.v1"
    assert failed["protocol_state"] == "quiescing"
    with app.state.store.connect() as conn:
        conn.execute("DROP TRIGGER cutover_failure")
    assert apply_group(app.state.settings, group, before["plan_digest"])["migration_state"] == "applied"


@pytest.mark.asyncio
async def test_rebound_v1_member_is_frozen_at_cutover_and_cannot_rebind_again(client, tmp_path, monkeypatch):
    from awiki_open_server.messaging.groups import service
    from awiki_open_server.messaging.groups.identity import VerifiedHandleBinding

    app = client._transport.app
    owner = await register_with_key(client, "migration-rebind-owner")
    successor = await register_with_key(client, "migration-successor")
    outsider = await register_with_key(client, "migration-outsider")
    handle = "migration-rebind-owner.testserver"
    created = await group_call(client, owner, "group.create", "did:wba:testserver", "rebind-create", {"creator_handle": handle}, profile="anp.group.base.v1")
    group = created["result"]["group_did"]
    monkeypatch.setattr(service, "_resolve_handle_binding", lambda *_args: VerifiedHandleBinding(handle, successor[0], "2"))
    rebound = await group_call(client, successor, "group.rebind_member", group, "before-cutover-rebind", {
        "member_handle": handle, "previous_member_did": owner[0], "new_member_did": successor[0], "handle_binding_generation": "2",
    }, profile="anp.group.base.v1")
    assert rebound["result"]["member_did"] == successor[0]
    premature = await group_call(client, successor, "group.send", group, "premature-v2", {"payload": {"text": "denied"}})
    assert premature["error"]["message"] == "group.protocol_mismatch"
    plan = inspect_group(app.state.settings, group)
    prepare_group(app.state.settings, group, plan["plan_digest"], tmp_path.parent / f"{tmp_path.name}-backup")
    apply_group(app.state.settings, group, plan["plan_digest"])
    sent = await group_call(client, successor, "group.send", group, "successor-v2", {"payload": {"text": "same member"}})
    assert sent["result"]["accepted"] is True
    from tests.conftest import rpc
    roster = await rpc(client, "/im/rpc", "group.list_members", {"group_did": group}, token=successor[1])
    assert all("member_handle" not in member and "handle_binding_generation" not in member for member in roster["result"]["members"])
    before = historical_state(app, group)
    monkeypatch.setattr(service, "_resolve_handle_binding", lambda *_args: VerifiedHandleBinding(handle, outsider[0], "3"))
    denied = await group_call(client, outsider, "group.rebind_member", group, "after-cutover-rebind", {
        "member_handle": handle, "previous_member_did": successor[0], "new_member_did": outsider[0], "handle_binding_generation": "3",
    }, profile="anp.group.base.v1")
    assert denied["error"]["message"] == "group.protocol_mismatch"
    assert historical_state(app, group) == before
    with app.state.store.connect() as conn:
        members = conn.execute("SELECT agent_did, role FROM hosted_group_members WHERE group_did=? AND status='active'", (group,)).fetchall()
        assert [(row["agent_did"], row["role"]) for row in members] == [(successor[0], "owner")]


def test_migration_cli_checks_loaded_stopped_unit(monkeypatch):
    import runpy
    from types import SimpleNamespace
    namespace = runpy.run_path(str(Path(__file__).parents[1] / "scripts/migrate_group_protocol.py"))
    check = namespace["require_stopped_unit"]
    for status in ["LoadState=not-found\nActiveState=inactive\nMainPID=0", "LoadState=loaded\nActiveState=active\nMainPID=123", "LoadState=loaded\nActiveState=inactive\nMainPID=123"]:
        monkeypatch.setattr(namespace["subprocess"], "run", lambda *_args, **_kwargs: SimpleNamespace(stdout=status))
        with pytest.raises(ValueError):
            check("awiki-open-server.service")
    monkeypatch.setattr(namespace["subprocess"], "run", lambda *_args, **_kwargs: SimpleNamespace(stdout="LoadState=loaded\nActiveState=inactive\nMainPID=0"))
    check("awiki-open-server.service")
    with pytest.raises(ValueError):
        check(None)


def test_migration_checks_bound_member_home_capability_without_rewriting_old_member(monkeypatch):
    from awiki_open_server.messaging.groups.migration import _require_peer_v2
    from awiki_open_server.shared import runtime
    from awiki_open_server.shared.errors import NotSupported
    member = 'did:wba:peer.test:users:member'
    home_did = 'did:wba:peer.test'
    member_service = {'serviceDid':home_did, 'serviceEndpoint':'https://peer.test/anp-im/rpc', 'profiles':['anp.group.base.v1']}
    home_service = {**member_service, 'profiles':['anp.group.base.v2']}
    monkeypatch.setattr(runtime, '_discover_anp_service', lambda did, _settings: member_service if did == member else home_service)
    _require_peer_v2(member, None)
    assert member_service['profiles'] == ['anp.group.base.v1']
    home_service['profiles'] = ['anp.group.base.v1']
    with pytest.raises(NotSupported, match='migration_peer_v2_required'):
        _require_peer_v2(member, None)
    home_service['profiles'] = ['anp.group.base.v2']
    for field, wrong in [('serviceDid','did:wba:other.test'),('serviceEndpoint','https://other.test/anp-im/rpc')]:
        previous = home_service[field]
        home_service[field] = wrong
        with pytest.raises(InvalidParams, match='migration_peer_binding_invalid'):
            _require_peer_v2(member, None)
        home_service[field] = previous
