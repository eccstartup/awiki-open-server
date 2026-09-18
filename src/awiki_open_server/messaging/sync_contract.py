"""Ordinary sync DTOs shared by bootstrap, history and read-state projection."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from awiki_open_server.shared.errors import InvalidParams, Unauthorized

SNAPSHOT_GROUP_FIELDS = (
    "group_did",
    "host_service_did",
    "creator_did",
    "group_state_version",
    "group_event_seq",
    "required_security_profile",
    "group_profile",
    "member_role",
    "membership_status",
    "member_count",
    "updated_at",
)


def conversation_ref(conn, owner: str, peer: str) -> str:
    reference = "conv_" + hashlib.sha256(json.dumps([owner, peer], separators=(",", ":")).encode()).hexdigest()
    conn.execute("INSERT OR IGNORE INTO direct_conversation_refs(owner_did, peer_did, conversation_ref) VALUES (?, ?, ?)", (owner, peer, reference))
    return conn.execute("SELECT conversation_ref FROM direct_conversation_refs WHERE owner_did=? AND peer_did=?", (owner, peer)).fetchone()[0]


def conversation_peer(conn, owner: str, reference: str) -> str:
    row = conn.execute("SELECT peer_did FROM direct_conversation_refs WHERE owner_did=? AND conversation_ref=?", (owner, reference)).fetchone()
    if row is None:
        raise InvalidParams("sync.conversation_ref_unknown")
    return row[0]


def group_source(conn, owner: str, group_did: str) -> tuple[str, str]:
    if conn.execute("SELECT 1 FROM hosted_groups WHERE group_did=?", (group_did,)).fetchone():
        allowed = conn.execute("SELECT 1 FROM hosted_group_members WHERE group_did=? AND agent_did=? AND status='active'", (group_did, owner)).fetchone()
        source = ("hosted_group_messages", "group_event_seq")
    elif conn.execute("SELECT 1 FROM group_views WHERE owner_did=? AND group_did=?", (owner, group_did)).fetchone():
        allowed = conn.execute("SELECT 1 FROM group_views WHERE owner_did=? AND group_did=? AND membership_status='active'", (owner, group_did)).fetchone()
        source = ("group_message_views", "group_event_seq")
    else:
        allowed = conn.execute("SELECT 1 FROM group_members WHERE group_did=? AND member_did=?", (group_did, owner)).fetchone()
        source = ("group_messages", "server_seq")
    if not allowed:
        raise Unauthorized("group.not_member")
    return source


def host_service_did_for_group(group_did: str, configured: str | None = None) -> str:
    if configured:
        return configured
    parts = group_did.split(":")
    if len(parts) >= 3 and parts[0] == "did":
        return ":".join(parts[:3])
    return group_did


def group_snapshot(conn, owner: str, group_did: str, *, host_service_did: str | None = None) -> dict[str, Any] | None:
    row = conn.execute("SELECT g.*, m.role AS member_role, m.status AS membership_status FROM hosted_groups g LEFT JOIN hosted_group_members m ON m.group_did=g.group_did AND m.agent_did=? WHERE g.group_did=?", (owner, group_did)).fetchone()
    if row:
        count = conn.execute("SELECT COUNT(*) FROM hosted_group_members WHERE group_did=? AND status='active'", (group_did,)).fetchone()[0]
        creator = row["creator_did"]
    else:
        row = conn.execute("SELECT * FROM group_views WHERE owner_did=? AND group_did=?", (owner, group_did)).fetchone()
        if not row:
            legacy = conn.execute("SELECT g.*, m.role FROM groups g LEFT JOIN group_members m ON m.group_did=g.group_did AND m.member_did=? WHERE g.group_did=?", (owner, group_did)).fetchone()
            if not legacy:
                return None
            member_count = conn.execute("SELECT COUNT(*) FROM group_members WHERE group_did=?", (group_did,)).fetchone()[0]
            return {
                "group_did": group_did,
                "host_service_did": host_service_did_for_group(group_did, host_service_did),
                "creator_did": None,
                "group_state_version": "1",
                "group_event_seq": "0",
                "required_security_profile": "transport-protected",
                "group_profile": {"display_name": legacy["display_name"], "description": legacy["description"]},
                "member_role": legacy["role"] or "member",
                "membership_status": "active" if legacy["role"] else "removed",
                "member_count": str(member_count),
                "updated_at": legacy["created_at"],
            }
        count = conn.execute("SELECT COUNT(*) FROM group_member_views WHERE owner_did=? AND group_did=? AND status='active'", (owner, group_did)).fetchone()[0]
        creator = None
    return {"group_did": group_did, "host_service_did": row["host_service_did"], "creator_did": creator,
            "group_state_version": str(row["group_state_version"]), "group_event_seq": str(row["group_event_seq"]),
            "required_security_profile": "transport-protected", "group_profile": json.loads(row["profile_json"]),
            "member_role": row["member_role"] or "member", "membership_status": row["membership_status"] or "removed",
            "member_count": str(count), "updated_at": row["updated_at"]}


def group_baseline(conn, owner: str, *, host_service_did: str | None = None) -> list[dict[str, Any]]:
    rows = conn.execute("""SELECT group_did FROM hosted_group_members WHERE agent_did=?
        UNION SELECT group_did FROM group_views WHERE owner_did=?
        UNION SELECT group_did FROM group_members WHERE member_did=?""", (owner, owner, owner)).fetchall()
    return [value for row in rows if (value := group_snapshot(conn, owner, row[0], host_service_did=host_service_did)) is not None]


def read_state_dto(conn, owner: str, row) -> dict[str, Any]:
    thread = row["thread_id"]
    direct = thread.startswith("direct:")
    key = conversation_ref(conn, owner, thread.removeprefix("direct:")) if direct else thread.removeprefix("group:")
    return {"thread_key": key, "thread_kind": "direct" if direct else "group",
            "read_up_to_thread_seq": str(row["read_up_to_seq"]), "read_up_to_message_id": row["read_message_id"],
            "state_version": str(row["state_version"]), "updated_at": row["updated_at"], "updated_by_device_id": None}


def decimal_cursor(value: Any, field: str, *, positive: bool = False) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal() or (len(value) > 1 and value[0] == "0"):
        raise InvalidParams(f"sync.{field}_invalid")
    if len(value) > 20:
        raise InvalidParams(f"sync.{field}_invalid")
    parsed = int(value)
    if positive and parsed == 0:
        raise InvalidParams(f"sync.{field}_invalid")
    return parsed
