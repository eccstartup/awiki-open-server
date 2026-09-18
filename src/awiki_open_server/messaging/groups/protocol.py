from __future__ import annotations

from typing import Any

from awiki_open_server.shared.errors import InvalidParams, NotSupported


BASE_V1 = "anp.group.base.v1"
BASE_V2 = "anp.group.base.v2"
BASE_PROFILES = {BASE_V1, BASE_V2}
HANDLE_FIELDS = {"member_handle", "creator_handle", "subject_handle", "handle_binding_generation", "binding_generation", "member_home_service_did", "wns", "wns_name"}
DEVICE_FIELDS = {"device_id", "device_ids", "devices", "sender_device_id", "recipient_device_id", "recipient_device_ids", "member_device_id", "member_device_ids", "device_selector", "device_selectors", "device_list"}


def validate_v2_shape(method: str, meta: dict[str, Any], body: dict[str, Any]) -> None:
    if meta.get("profile") != BASE_V2:
        return
    if method in {"group.rebind_member", "group.member_did_update"}:
        raise NotSupported("group.method_not_supported_in_v2")
    if HANDLE_FIELDS & body.keys():
        raise InvalidParams("group.v2_handle_identity_not_allowed")
    # Only protocol-owned structures are inspected. Application payload and
    # annotations may legitimately contain a field named device_id.
    structures = [meta, body]
    if isinstance(meta.get("target"), dict):
        structures.append(meta["target"])
    for field in ("group_policy", "group_policy_patch", "group_profile", "group_profile_patch", "group_receipt"):
        if isinstance(body.get(field), dict):
            structures.append(body[field])
    if isinstance(body.get("group_receipt"), dict) and body["group_receipt"].get("e2ee") is not None:
        raise NotSupported("group.e2ee_not_supported")
    if any(DEVICE_FIELDS & item.keys() for item in structures):
        raise InvalidParams("group.v2_device_selector_not_allowed")
    if method == "group.join" and "member_did" in body:
        raise InvalidParams("group.v2_join_uses_authenticated_did")
    if method == "group.create":
        members = body.get("initial_members", [])
        if not isinstance(members, list):
            raise InvalidParams("group.initial_members_invalid")
        for member in members:
            if not isinstance(member, dict) or set(member) - {"member_did", "role"}:
                raise InvalidParams("group.v2_initial_member_invalid")
            if not isinstance(member.get("member_did"), str) or not member["member_did"].startswith("did:"):
                raise InvalidParams("group.member_did_required")
            if member.get("role", "member") not in {"member", "admin"}:
                raise InvalidParams("group.role_invalid")
    if method in {"group.add", "group.remove"}:
        if not isinstance(body.get("member_did"), str) or not body["member_did"].startswith("did:"):
            raise InvalidParams("group.member_did_required")
    if method == "group.add" and body.get("role", "member") not in {"member", "admin"}:
        raise InvalidParams("group.role_invalid")


def require_group_protocol(group: Any, profile: str | None, *, writing: bool = False) -> None:
    if profile in BASE_PROFILES and group["wire_profile"] != profile:
        raise NotSupported("group.protocol_mismatch", data={"required_profile": group["wire_profile"]})
    if writing and group["protocol_state"] == "quiescing":
        raise NotSupported("group.protocol_upgrade_in_progress")


def discovered_group_profile(service: dict[str, Any]) -> str:
    profiles = BASE_PROFILES.intersection(service.get("profiles", []))
    if len(profiles) != 1:
        raise InvalidParams("group.discovery_profile_ambiguous")
    return next(iter(profiles))
