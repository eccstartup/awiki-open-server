"""Replication ordering after cryptographic checks (covered by test_group_host)."""
from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from awiki_open_server.app.settings import Settings
from awiki_open_server.messaging.groups import inbound, routing
from awiki_open_server.shared.errors import Conflict, InvalidParams, Unauthorized
from awiki_open_server.storage.db import Store

OWNER = "did:wba:home.test:user:member"
GROUP = "did:wba:host.test:groups:group"
TIME = "2026-09-17T10:00:00Z"


@pytest.fixture
def terminal_state(tmp_path, monkeypatch):
    store = Store(tmp_path / "state.sqlite3", "home.test")
    settings = Settings(data_dir=tmp_path, public_base_url="https://home.test", service_did="did:wba:home.test", did_domain="home.test")
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(store=store, settings=settings)), state=SimpleNamespace(peer_service_did="did:wba:host.test"))
    with store.connect() as conn:
        conn.execute("INSERT INTO group_views(owner_did,group_did,host_service_did,profile_json,policy_json,group_state_version,group_event_seq,member_role,membership_status,updated_at,wire_profile) VALUES (?,?,?, '{}','{}',2,4,'member','active',?,?)",
                     (OWNER, GROUP, "did:wba:host.test", TIME, "anp.group.base.v2"))
    monkeypatch.setattr(inbound, "_notification_context", lambda params, *_args: (params["meta"], params["body"], OWNER, GROUP))
    monkeypatch.setattr(inbound, "_verified_receipt", lambda _request, body, **_kwargs: (body["group_receipt"], int(body["group_state_version"]), int(body["group_event_seq"])))
    monkeypatch.setattr(inbound.runtime, "_publish_realtime", lambda *_args, **_kwargs: None)
    return request


def operation(method="group.leave"):
    actor = OWNER if method == "group.leave" else "did:wba:home.test:user:admin"
    status = "left" if method == "group.leave" else "removed"
    target_key = "leaver_did" if method == "group.leave" else "member_did"
    receipt = {"group_did": GROUP, "subject_method": method, "actor_did": actor, "operation_id": "terminal-op",
               "payload_digest": "accepted-request-digest", "group_event_seq": "5", "group_state_version": "3", "accepted_at": TIME}
    params = {"_anp_meta": {"profile": "anp.group.base.v2", "sender_did": actor, "operation_id": "terminal-op", "target": {"did": GROUP}}, "_anp_body": {"member_did": OWNER}}
    result = {"accepted": True, "final_acceptance": True, "operation_id": "terminal-op", "group_did": GROUP, "group_event_seq": "5", "group_state_version": "3", "group_receipt": receipt, target_key: OWNER}
    event = {"meta": {"profile": "anp.group.base.v2"}, "body": {"group_did": GROUP, "group_receipt": receipt,
             "group_event_seq": "5", "group_state_version": "3", "subject_method": method,
             "subject_did": OWNER, "membership_status": status, "event_type": "member-" + status,
             "changed_at": TIME, "group_profile": {"display_name": "terminal snapshot"}}}
    return params, result, event, status


@pytest.mark.parametrize("method", ["group.leave", "group.remove"])
def test_terminal_notification_matches_forwarded_receipt_and_emits_once(terminal_state, method):
    request = terminal_state
    params, result, event, status = operation(method)
    routing._apply_terminal_projection(request, method=method, params=params, result=result)
    assert inbound.group_state_changed(event, request)["accepted"] is True
    assert inbound.group_state_changed(event, request)["duplicate"] is True
    with request.app.state.store.connect() as conn:
        assert conn.execute("SELECT membership_status FROM group_views").fetchone()[0] == status
        assert conn.execute("SELECT count(*) FROM sync_events").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM inbound_peer_events").fetchone()[0] == 1
    altered = copy.deepcopy(event)
    altered["body"]["group_profile"]["display_name"] = "conflicting replay"
    with pytest.raises(Conflict, match="inbound_event_conflict"):
        inbound.group_state_changed(altered, request)


def test_unmatched_stale_receipt_cannot_poison_replay_marker(terminal_state):
    request = terminal_state
    params, result, event, _ = operation()
    routing._apply_terminal_projection(request, method="group.leave", params=params, result=result)
    altered = copy.deepcopy(event)
    altered["body"]["group_receipt"]["operation_id"] = "another-operation"
    with pytest.raises(Conflict, match="projection_stale_event"):
        inbound.group_state_changed(altered, request)
    with request.app.state.store.connect() as conn:
        assert conn.execute("SELECT count(*) FROM inbound_peer_events").fetchone()[0] == 0
    assert inbound.group_state_changed(event, request)["accepted"] is True


def test_delayed_terminal_reply_and_notification_do_not_revoke_newer_membership(terminal_state):
    request = terminal_state
    params, result, event, _ = operation()
    routing._apply_terminal_projection(request, method="group.leave", params=params, result=result)
    with request.app.state.store.connect() as conn:
        conn.execute("UPDATE group_views SET group_event_seq=8,group_state_version=4,membership_status='active'")
    routing._apply_terminal_projection(request, method="group.leave", params=params, result=result)
    assert inbound.group_state_changed(event, request)["duplicate"] is True
    with request.app.state.store.connect() as conn:
        row = conn.execute("SELECT group_event_seq,membership_status FROM group_views").fetchone()
        assert tuple(row) == (8, "active")
        assert conn.execute("SELECT count(*) FROM sync_events").fetchone()[0] == 0


def test_remote_v2_response_cannot_retarget_a_valid_receipt(terminal_state, monkeypatch):
    params, result, _, _ = operation()
    params["_anp_auth"] = {"origin_proof": {"contentDigest": result["group_receipt"]["payload_digest"]}}
    monkeypatch.setattr(routing.runtime, "_resolve_did_document_for_proof", lambda *_args: {})
    monkeypatch.setattr(routing, "verify_group_receipt", lambda *_args, **_kwargs: True)
    routing._validate_remote_receipt(terminal_state, method="group.leave", params=params, result=result)
    for key, value in [("group_did", "did:wba:other.test:groups:other"), ("operation_id", "another-operation"),
                       ("accepted", False), ("final_acceptance", False), ("group_event_seq", "6"), ("leaver_did", "did:wba:home.test:user:other")]:
        with pytest.raises(InvalidParams, match="invalid_group_receipt"):
            routing._validate_remote_receipt(terminal_state, method="group.leave", params=params, result={**result, key: value})


def test_pre_leave_echo_is_retained_without_restoring_read_access(terminal_state, monkeypatch):
    from awiki_open_server.messaging.sync_contract import group_source
    request = terminal_state
    activation = {"group_did": GROUP, "subject_did": OWNER, "event_type": "member-activated", "membership_status": "active", "group_event_seq": "2"}
    with request.app.state.store.connect() as conn:
        inbound.runtime.add_sync_event(conn, OWNER, "group.state_changed", activation)
        conn.execute('UPDATE group_views SET observed_event_seq=4,observed_state_version=2')
    params, result, terminal, _ = operation()
    routing._apply_terminal_projection(request, method="group.leave", params=params, result=result)
    inbound.group_state_changed(terminal, request)
    monkeypatch.setattr(inbound, "validate_origin_proof_structure", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(inbound.runtime, "_resolve_did_document_for_proof", lambda *_args: {})
    def message(seq):
        return {"meta": {"profile": "anp.group.base.v2", "sender_did": OWNER, "message_id": f"msg-{seq}", "operation_id": f"send-{seq}", "content_type": "text/plain"},
                "_anp_auth": {"origin_proof": {"contentDigest": "accepted-digest"}},
                "body": {"group_did": GROUP, "group_event_seq": str(seq), "group_state_version": "2", "accepted_at": TIME, "text": "accepted before leave",
                         "group_receipt": {"group_did": GROUP, "group_event_seq": str(seq), "group_state_version": "2", "payload_digest": "accepted-digest", "actor_did": OWNER, "operation_id": f"send-{seq}", "accepted_at": TIME}}}
    assert inbound.group_incoming(message(4), request)["accepted"] is True
    assert inbound.group_incoming(message(4), request)["duplicate"] is True
    for seq in [1, 6]:
        with pytest.raises(Unauthorized, match="projection_membership_required"):
            inbound.group_incoming(message(seq), request)
    with request.app.state.store.connect() as conn:
        assert tuple(conn.execute("SELECT group_event_seq,group_state_version,membership_status FROM group_views").fetchone()) == (5, 3, "left")
        assert conn.execute("SELECT count(*) FROM group_message_views").fetchone()[0] == 1
        with pytest.raises(Unauthorized, match="not_member"):
            group_source(conn, OWNER, GROUP)


def test_authenticated_rejoin_starts_a_new_membership_interval(terminal_state):
    request = terminal_state
    params, result, event, _ = operation()
    routing._apply_terminal_projection(request, method="group.leave", params=params, result=result)
    rejoin = copy.deepcopy(event)
    rejoin["body"].update({"group_event_seq":"8", "group_state_version":"4", "event_type":"member-activated", "subject_method":"group.add", "membership_status":"active", "role":"admin"})
    rejoin["body"]["group_receipt"].update({"group_event_seq":"8", "group_state_version":"4", "subject_method":"group.add", "operation_id":"rejoin"})
    assert inbound.group_state_changed(rejoin, request)["accepted"] is True
    routing._apply_terminal_projection(request, method="group.leave", params=params, result=result)
    with request.app.state.store.connect() as conn:
        assert tuple(conn.execute("SELECT group_event_seq,membership_status,member_role FROM group_views").fetchone()) == (8, "active", "admin")


def test_authenticated_roster_refresh_does_not_discard_delayed_message(terminal_state, monkeypatch):
    import json
    from awiki_open_server.messaging.groups.projection import refresh_remote_member_projection
    request = terminal_state
    observed = {'group_did':GROUP, 'host_service_did':'did:wba:host.test',
        'group_state_version':'3', 'group_event_seq':'6', 'group_profile':{'display_name':'new profile'},
        'member_list':[{'member_did':OWNER,'role':'admin','status':'active'}], 'wire_profile':'anp.group.base.v2'}
    with request.app.state.store.connect() as conn:
        assert refresh_remote_member_projection(conn, owner_did=OWNER, snapshot=observed, updated_at=TIME)
    monkeypatch.setattr(inbound, 'validate_origin_proof_structure', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(inbound.runtime, '_resolve_did_document_for_proof', lambda *_args: {})
    message = {'meta':{'profile':'anp.group.base.v2','sender_did':OWNER,'message_id':'late-message',
        'operation_id':'late-send','content_type':'text/plain'}, '_anp_auth':{'origin_proof':{'contentDigest':'accepted-digest'}},
        'body':{'group_did':GROUP,'group_event_seq':'5','group_state_version':'2','accepted_at':TIME,'text':'late original body',
                'group_receipt':{'group_did':GROUP,'group_event_seq':'5','group_state_version':'2','payload_digest':'accepted-digest','actor_did':OWNER,'operation_id':'late-send','accepted_at':TIME}}}
    assert inbound.group_incoming(message, request)['accepted'] is True
    assert inbound.group_incoming(message, request)['duplicate'] is True
    with request.app.state.store.connect() as conn:
        view = conn.execute('SELECT * FROM group_views').fetchone()
        assert view['group_event_seq'] == 6 and view['group_state_version'] == 3 and view['member_role'] == 'admin'
        assert json.loads(view['profile_json']) == {'display_name':'new profile'}
        assert conn.execute('SELECT count(*) FROM group_message_views').fetchone()[0] == 1


def test_delayed_state_covered_by_roster_observation_never_regresses_or_hides_conflicts(terminal_state):
    import json
    from awiki_open_server.messaging.groups.projection import refresh_remote_member_projection
    request = terminal_state
    observed = {'group_did':GROUP,'host_service_did':'did:wba:host.test','group_state_version':'3',
        'group_event_seq':'6','group_profile':{'display_name':'latest'},
        'member_list':[{'member_did':OWNER,'role':'admin','status':'active'}]}
    with request.app.state.store.connect() as conn:
        refresh_remote_member_projection(conn,owner_did=OWNER,snapshot=observed,updated_at=TIME)
        refresh_remote_member_projection(conn,owner_did=OWNER,snapshot=observed,updated_at=TIME)
    _, _, event, _ = operation()
    event['body'].update(group_event_seq='4',group_state_version='2',event_type='profile-updated',
        subject_method='group.update_profile',group_profile={'display_name':'old'})
    event['body'].pop('subject_did'); event['body'].pop('membership_status')
    event['body']['group_receipt'].update(group_event_seq='4',group_state_version='2',subject_method='group.update_profile')
    assert inbound.group_state_changed(event,request)['superseded'] is True
    assert inbound.group_state_changed(event,request)['duplicate'] is True
    changed = copy.deepcopy(event)
    changed['body']['group_profile']['display_name']='conflicting replay'
    with pytest.raises(Conflict,match='inbound_event_conflict'):
        inbound.group_state_changed(changed,request)
    with request.app.state.store.connect() as conn:
        view=conn.execute('SELECT * FROM group_views').fetchone()
        assert json.loads(view['profile_json'])=={'display_name':'latest'}
        assert view['member_role']=='admin' and view['group_event_seq']==6
        events=conn.execute('SELECT payload_json FROM sync_events').fetchall()
        assert len(events)==1
        assert json.loads(events[0][0])['_sync_group']['group_state_version']=='3'
        assert conn.execute('SELECT count(*) FROM inbound_peer_events').fetchone()[0]==1


def test_roster_observation_is_bounded_by_host_sequence_and_state_version(terminal_state):
    request=terminal_state
    with request.app.state.store.connect() as conn:
        row=conn.execute('SELECT * FROM group_views').fetchone()
        assert not inbound._covered_by_observation(row,request,3,2)
        conn.execute('UPDATE group_views SET observed_event_seq=6,observed_state_version=3')
        row=conn.execute('SELECT * FROM group_views').fetchone()
    assert inbound._covered_by_observation(row,request,5,2)
    assert not inbound._covered_by_observation(row,request,7,2)
    assert not inbound._covered_by_observation(row,request,5,4)
    request.state.peer_service_did='did:wba:other.test'
    assert not inbound._covered_by_observation(row,request,5,2)
