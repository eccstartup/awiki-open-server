from __future__ import annotations

import json
import re
from datetime import datetime, timezone, timedelta
from typing import Any

from awiki_open_server.messaging.groups.protocol import BASE_PROFILES, BASE_V2, discovered_group_profile, validate_v2_shape

import jcs
from fastapi import Request

from awiki_open_server.protocol.anp_adapter import build_content_digest, verify_group_receipt
from awiki_open_server.service_identity import validate_origin_proof_structure
from awiki_open_server.shared import runtime
from awiki_open_server.shared.errors import Conflict, InvalidParams, Unauthorized
from awiki_open_server.shared.ids import now_iso
from awiki_open_server.user_compat.core import get_settings, get_store


_INCOMING_CONTROL_FIELDS = {
    "group_did",
    "group_state_version",
    "group_event_seq",
    "accepted_at",
    "group_receipt",
}


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _require_string(value: Any, error: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidParams(error)
    return value


def _notification_context(params: dict[str, Any], request: Request, method: str) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    meta = params.get("_anp_meta")
    body = params.get("_anp_body")
    if not isinstance(meta, dict) or not isinstance(body, dict):
        raise InvalidParams("group.notification_envelope_required")
    if meta.get("profile") not in BASE_PROFILES or meta.get("security_profile") != "transport-protected":
        raise InvalidParams("group.notification_profile_invalid")
    validate_v2_shape(method, meta, body)
    target = meta.get("target")
    if not isinstance(target, dict) or target.get("kind") != "agent":
        raise InvalidParams("group.notification_target_invalid")
    target_did = _require_string(target.get("did"), "group.notification_target_did_required")
    group_did = _require_string(body.get("group_did"), "group_did_required")
    with get_store(request).connect() as conn:
        if not runtime._user_exists(conn, target_did):
            raise Unauthorized("group.notification_target_not_local")
    runtime._verify_peer_request_signature(
        request,
        get_settings(request),
        caller_anchor=group_did,
    )
    service = runtime._discover_anp_service(group_did, get_settings(request))
    if discovered_group_profile(service) != meta["profile"]:
        raise InvalidParams("group.notification_profile_mismatch")
    if method == "group.state_changed" and meta.get("sender_did") != group_did:
        raise Unauthorized("group.state_changed_sender_mismatch")
    return meta, body, target_did, group_did


def _verified_receipt(request: Request, body: dict[str, Any], *, method: str) -> tuple[dict[str, Any], int, int]:
    receipt = body.get("group_receipt")
    if not isinstance(receipt, dict):
        raise InvalidParams("group.invalid_group_receipt")
    group_did = _require_string(body.get("group_did"), "group_did_required")
    if receipt.get("group_did") != group_did:
        raise InvalidParams("group.invalid_group_receipt")
    try:
        state_version = int(_require_string(body.get("group_state_version"), "group_state_version_required"))
        event_seq = int(_require_string(body.get("group_event_seq"), "group_event_seq_required"))
    except ValueError as exc:
        raise InvalidParams("group.version_invalid") from exc
    if receipt.get("group_state_version") != str(state_version) or receipt.get("group_event_seq") != str(event_seq):
        raise InvalidParams("group.invalid_group_receipt")
    if method == "group.incoming":
        if receipt.get("subject_method") != "group.send" or receipt.get("message_id") != body.get("message_id"):
            raise InvalidParams("group.invalid_group_receipt")
    else:
        if receipt.get("subject_method") != body.get("subject_method"):
            raise InvalidParams("group.invalid_group_receipt")
    document = runtime._resolve_did_document_for_proof(request, group_did)
    if not verify_group_receipt(receipt, issuer_did_document=document):
        raise InvalidParams("group.invalid_group_receipt")
    return receipt, state_version, event_seq


def _record_inbound(
    conn: Any,
    request: Request,
    *,
    method: str,
    target_did: str,
    group_did: str,
    event_seq: int,
    body: dict[str, Any],
) -> bool:
    source_service_did = runtime._verified_peer_service_did(request)
    if not source_service_did:
        raise Unauthorized("missing_source_service_did")
    digest = build_content_digest(jcs.canonicalize(body))
    existing = conn.execute(
        """
        SELECT payload_digest FROM inbound_peer_events
        WHERE source_service_did = ? AND group_did = ? AND group_event_seq = ?
          AND target_did = ? AND method = ?
        """,
        (source_service_did, group_did, event_seq, target_did, method),
    ).fetchone()
    if existing:
        if existing["payload_digest"] != digest:
            raise Conflict("group.inbound_event_conflict")
        return False
    conn.execute(
        """
        INSERT INTO inbound_peer_events(
          source_service_did, group_did, group_event_seq, target_did, method,
          payload_digest, received_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (source_service_did, group_did, event_seq, target_did, method, digest, now_iso()),
    )
    return True


def _covered_by_observation(view, request, event_seq: int, state_version: int) -> bool:
    return bool(view and view["host_service_did"] == runtime._verified_peer_service_did(request)
                and 0 < event_seq <= int(view["observed_event_seq"])
                and 0 < state_version <= int(view["observed_state_version"]))


def group_state_changed(params: dict[str, Any], request: Request) -> dict[str, Any]:
    meta, event, target_did, group_did = _notification_context(params, request, "group.state_changed")
    receipt, state_version, event_seq = _verified_receipt(request, event, method="group.state_changed")
    event_type = _require_string(event.get("event_type"), "group.event_type_required")
    changed_at = _require_string(event.get("changed_at"), "group.changed_at_required")
    with get_store(request).connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT * FROM group_views WHERE owner_did = ? AND group_did = ?",
            (target_did, group_did),
        ).fetchone()
        reactivated = bool(meta["profile"] == BASE_V2 and existing and existing["membership_status"] != "active"
                           and event_type == "member-activated" and event.get("subject_did") == target_did
                           and event.get("membership_status") == "active" and state_version > int(existing["group_state_version"]))
        if existing and event_seq > int(existing["group_event_seq"]) + 1 and not reactivated:
            raise Conflict("group.projection_gap")
        if not existing and not (
            event_type == "member-activated"
            and event.get("subject_did") == target_did
            and event.get("membership_status") == "active"
        ):
            raise Unauthorized("group.projection_membership_required")
        if not _record_inbound(
            conn,
            request,
            method="group.state_changed",
            target_did=target_did,
            group_did=group_did,
            event_seq=event_seq,
            body=event,
        ):
            return {"accepted": True, "duplicate": True}
        if existing and event_seq <= int(existing["group_event_seq"]):
            if _covered_by_observation(existing, request, event_seq, state_version):
                # The roster read already installed a newer authenticated view.
                # Consume this notification without restoring older state.
                return {"accepted": True, "superseded": True}
            if not _matches_forwarded_terminal(conn, meta, event, receipt, target_did, group_did):
                raise Conflict("group.projection_stale_event")
            if event_seq < int(existing["group_event_seq"]):
                return {"accepted": True, "duplicate": True}
        profile = event.get("group_profile") if isinstance(event.get("group_profile"), dict) else (json.loads(existing["profile_json"]) if existing else {})
        policy = event.get("group_policy") if isinstance(event.get("group_policy"), dict) else (json.loads(existing["policy_json"]) if existing else {})
        member_role = str(existing["member_role"]) if existing else str(event.get("role") or "member")
        membership_status = str(existing["membership_status"]) if existing else "active"
        if reactivated:
            membership_status = "active"
            member_role = str(event.get("role") or "member")
        if event.get("subject_did") == target_did and event_type in {"member-removed", "member-left"}:
            membership_status = "removed" if event_type == "member-removed" else "left"
        conn.execute(
            """
            INSERT INTO group_views(
              owner_did, group_did, host_service_did, profile_json, policy_json,
              group_state_version, group_event_seq, member_role, membership_status, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_did, group_did) DO UPDATE SET
              profile_json = excluded.profile_json, policy_json = excluded.policy_json,
              group_state_version = excluded.group_state_version,
              group_event_seq = excluded.group_event_seq, updated_at = excluded.updated_at,
              membership_status = excluded.membership_status, member_role = excluded.member_role
            """,
            (
                target_did,
                group_did,
                runtime._verified_peer_service_did(request),
                _json(profile),
                _json(policy),
                state_version,
                event_seq,
                member_role,
                membership_status,
                changed_at,
            ),
        )
        conn.execute("UPDATE group_views SET wire_profile = ? WHERE owner_did = ? AND group_did = ?", (meta["profile"], target_did, group_did))
        subject_did = event.get("subject_did")
        if isinstance(subject_did, str):
            conn.execute(
                """
                INSERT INTO group_member_views(
                  owner_did, group_did, agent_did, member_handle, handle_binding_generation,
                  role, status, joined_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(owner_did, group_did, agent_did) DO UPDATE SET
                  member_handle = excluded.member_handle,
                  handle_binding_generation = excluded.handle_binding_generation,
                  role = excluded.role, status = excluded.status, updated_at = excluded.updated_at
                """,
                (
                    target_did,
                    group_did,
                    subject_did,
                    event.get("subject_handle"),
                    event.get("handle_binding_generation"),
                    event.get("role") or "member",
                    event.get("membership_status") or ("removed" if event_type == "member-removed" else "left" if event_type == "member-left" else "active"),
                    changed_at,
                    changed_at,
                ),
            )
        sync_seq = runtime.add_sync_event(conn, target_did, "group.state_changed", event)
    runtime._publish_realtime(
        request,
        target_did,
        "group.state_changed",
        event,
        {"owner_did": target_did, "event_type": "group.state_changed", "event_seq": str(sync_seq)},
    )
    return {"accepted": True, "group_did": group_did, "group_event_seq": str(event_seq), "group_receipt": receipt}


def _matches_forwarded_terminal(conn, meta, event, receipt, target_did, group_did) -> bool:
    """Match an already authenticated Host response, never just its sequence."""
    if meta.get("profile") != BASE_V2 or event.get("subject_did") != target_did:
        return False
    method = receipt.get("subject_method")
    terminal = {"group.leave": ("member-left", "left", "leaver_did"),
                "group.remove": ("member-removed", "removed", "member_did")}.get(method)
    if terminal is None or event.get("event_type") != terminal[0] or event.get("membership_status") != terminal[1]:
        return False
    row = conn.execute(
        "SELECT result_json FROM group_operations WHERE sender_did=? AND group_scope=? AND method=? AND operation_id=? AND wire_profile=? AND payload_digest=?",
        (receipt.get("actor_did"), group_did, method, receipt.get("operation_id"), BASE_V2, receipt.get("payload_digest")),
    ).fetchone()
    if row is None:
        return False
    result = json.loads(row["result_json"])
    return result.get(terminal[2]) == target_did and result.get("group_receipt") == receipt


def _accepted_before_terminal(conn, view, meta, receipt, target_did, group_did, event_seq, state_version) -> bool:
    """Retain an in-flight message accepted during this membership interval.

    The current ACL stays terminal; only a known signed terminal response and
    an earlier authenticated activation establish the allowed interval.
    """
    if meta["profile"] != BASE_V2 or view["membership_status"] not in {"left", "removed"}:
        return False
    if event_seq >= int(view["group_event_seq"]) or state_version >= int(view["group_state_version"]):
        return False
    activation = conn.execute(
        """SELECT payload_json FROM sync_events WHERE owner_did=? AND event_type='group.state_changed'
           AND json_extract(payload_json,'$.group_did')=? AND json_extract(payload_json,'$.subject_did')=?
           AND json_extract(payload_json,'$.event_type') IN ('member-activated','member-rebound')
           AND json_extract(payload_json,'$.membership_status')='active' ORDER BY event_seq DESC LIMIT 1""",
        (target_did, group_did, target_did),
    ).fetchone()
    if activation is None or event_seq <= int(json.loads(activation["payload_json"])["group_event_seq"]):
        return False
    method, target_key = ("group.leave", "leaver_did") if view["membership_status"] == "left" else ("group.remove", "member_did")
    rows = conn.execute("SELECT result_json FROM group_operations WHERE group_scope=? AND method=? AND wire_profile=?", (group_did, method, BASE_V2)).fetchall()
    for row in rows:
        result = json.loads(row["result_json"])
        terminal = result.get("group_receipt", {})
        if (result.get(target_key) == target_did and terminal.get("group_event_seq") == str(view["group_event_seq"])
                and terminal.get("group_state_version") == str(view["group_state_version"])):
            return True
    return False


def verified_acceptance_time(receipt: dict[str, Any], body: dict[str, Any]) -> datetime:
    """Use only after the Group Receipt signature/context has been verified."""
    value = receipt.get("accepted_at")
    if not isinstance(value, str) or value != body.get("accepted_at") or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", value):
        raise InvalidParams("group.invalid_group_receipt")
    try:
        accepted = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidParams("group.invalid_group_receipt") from exc
    if accepted > datetime.now(timezone.utc) + timedelta(seconds=60):
        raise InvalidParams("group.invalid_group_receipt")
    return accepted


def group_incoming(params: dict[str, Any], request: Request) -> dict[str, Any]:
    meta, body, target_did, group_did = _notification_context(params, request, "group.incoming")
    message_id = _require_string(meta.get("message_id"), "anp_meta_message_id_required")
    operation_id = _require_string(meta.get("operation_id"), "anp_meta_operation_id_required")
    content_type = _require_string(meta.get("content_type"), "anp_meta_content_type_required")
    sender_did = _require_string(meta.get("sender_did"), "anp_meta_sender_did_required")
    body_with_message = {**body, "message_id": message_id}
    receipt, state_version, event_seq = _verified_receipt(request, body_with_message, method="group.incoming")
    if receipt.get("actor_did") != sender_did or receipt.get("operation_id") != operation_id:
        raise InvalidParams("group.invalid_group_receipt")
    accepted_at = verified_acceptance_time(receipt, body)
    original_body = {key: value for key, value in body.items() if key not in _INCOMING_CONTROL_FIELDS}
    original_meta = {**meta, "target": {"kind": "group", "did": group_did}}
    auth = params.get("_anp_auth") if isinstance(params.get("_anp_auth"), dict) else None
    origin_proof = auth.get("origin_proof") if isinstance(auth, dict) else None
    if not isinstance(origin_proof, dict) or receipt.get("payload_digest") != origin_proof.get("contentDigest"):
        raise InvalidParams("group.invalid_group_receipt")
    validate_origin_proof_structure(
        auth,
        method="group.send",
        meta=original_meta,
        body=original_body,
        sender_did_document=runtime._resolve_did_document_for_proof(request, sender_did),
        verified_at=accepted_at,
    )
    with get_store(request).connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        view = conn.execute(
            """
            SELECT * FROM group_views
            WHERE owner_did = ? AND group_did = ?
            """,
            (target_did, group_did),
        ).fetchone()
        if not view:
            raise Unauthorized("group.projection_membership_required")
        before_terminal = _accepted_before_terminal(conn, view, meta, receipt, target_did, group_did, event_seq, state_version)
        if view["membership_status"] != "active" and not before_terminal:
            raise Unauthorized("group.projection_membership_required")
        if event_seq > int(view["group_event_seq"]) + 1:
            raise Conflict("group.projection_gap")
        if not _record_inbound(
            conn,
            request,
            method="group.incoming",
            target_did=target_did,
            group_did=group_did,
            event_seq=event_seq,
            body=body,
        ):
            return {"accepted": True, "duplicate": True}
        if event_seq <= int(view["group_event_seq"]) and not before_terminal and not _covered_by_observation(view, request, event_seq, state_version):
            raise Conflict("group.projection_stale_event")
        conn.execute(
            """
            INSERT INTO group_message_views(
              owner_did, group_did, message_id, group_event_seq, group_state_version,
              sender_did, operation_id, content_type, body_json, receipt_json, accepted_at, wire_profile
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target_did,
                group_did,
                message_id,
                event_seq,
                state_version,
                sender_did,
                operation_id,
                content_type,
                _json(original_body),
                _json(receipt),
                body["accepted_at"],
                meta["profile"],
            ),
        )
        conn.execute(
            """
            UPDATE group_views SET updated_at = CASE WHEN group_event_seq <= ? THEN ? ELSE updated_at END,
              group_state_version = MAX(group_state_version, ?), group_event_seq = MAX(group_event_seq, ?), wire_profile = ?
            WHERE owner_did = ? AND group_did = ?
            """,
            (event_seq, body["accepted_at"], state_version, event_seq, meta["profile"], target_did, group_did),
        )
        sync_seq = runtime.add_sync_event(
            conn,
            target_did,
            "group.message.created",
            {
                "thread_kind": "group",
                "thread": {"kind": "group", "group_did": group_did},
                "message": {
                    "id": f"{group_did}:{event_seq}",
                    "message_id": message_id,
                    "server_seq": str(event_seq),
                    "group_event_seq": str(event_seq),
                    "group_did": group_did,
                    "sender_did": sender_did,
                    "content_type": content_type,
                },
            },
        )
    runtime._publish_realtime(
        request,
        target_did,
        "group.incoming",
        body,
        {"owner_did": target_did, "event_type": "group.message.created", "event_seq": str(sync_seq)},
    )
    return {"accepted": True, "group_did": group_did, "message_id": message_id, "group_event_seq": str(event_seq)}


INBOUND_GROUP_HANDLERS = {
    "group.incoming": group_incoming,
    "group.state_changed": group_state_changed,
}


__all__ = ["INBOUND_GROUP_HANDLERS", "group_incoming", "group_state_changed"]
