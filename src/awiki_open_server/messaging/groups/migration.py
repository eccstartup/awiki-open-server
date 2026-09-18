"""Explicit local v1-to-v2 cutover, with immutable evidence and no wire rewrite."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from awiki_open_server.app.settings import Settings
from awiki_open_server.messaging.groups.protocol import BASE_V1, BASE_V2
from awiki_open_server.messaging.groups.projection import refresh_hosted_local_projections
from awiki_open_server.protocol.anp_adapter import ed25519_root_fingerprint, require_did_document_binding
from awiki_open_server.service_identity import _sign_did_document
from awiki_open_server.shared import runtime
from awiki_open_server.shared.errors import Conflict, InvalidParams, NotSupported
from awiki_open_server.shared.ids import new_id, now_iso


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def _connection(settings: Settings, *, write: bool = False):
    conn = sqlite3.connect(settings.db_path.resolve().as_uri() + ("?mode=rw" if write else "?mode=ro"), uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        if write:
            conn.execute("BEGIN IMMEDIATE")
        yield conn
        if write:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _group_material(conn, settings: Settings, group_did: str):
    group = conn.execute("SELECT * FROM hosted_groups WHERE group_did = ?", (group_did,)).fetchone()
    document = conn.execute("SELECT * FROM group_did_documents WHERE group_did = ?", (group_did,)).fetchone()
    if group is None or document is None or group["host_service_did"] != settings.service_did:
        raise InvalidParams("group.migration_not_owned")
    if not {"wire_profile", "protocol_state"} <= set(group.keys()):
        raise InvalidParams("group.migration_schema_upgrade_required")
    path = Path(document["key_reference"])
    if path.is_symlink() or not path.resolve().is_relative_to(settings.group_key_dir.resolve()):
        raise InvalidParams("group.migration_key_path_invalid")
    key = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise InvalidParams("group.migration_key_invalid")
    value = json.loads(document["document_json"])
    require_did_document_binding(value)
    if value.get("id") != group_did or group_did.rsplit(":", 1)[-1] != f"e1_{ed25519_root_fingerprint(key.public_key())}":
        raise InvalidParams("group.migration_key_binding_invalid")
    services = [service for service in value.get("service", []) if service.get("type") == "ANPMessageService"]
    if len(services) != 1 or services[0].get("serviceDid") != settings.service_did:
        raise InvalidParams("group.migration_service_binding_invalid")
    return group, document, value, key


def _inspect(conn, settings: Settings, group_did: str) -> dict[str, Any]:
    group, document, value, key = _group_material(conn, settings, group_did)
    roster = [dict(row) for row in conn.execute("SELECT * FROM hosted_group_members WHERE group_did = ? ORDER BY agent_did", (group_did,))]
    deliveries = conn.execute("SELECT delivery_id, target_did, target_service_did, group_event_seq, status, envelope_json FROM group_delivery_outbox WHERE group_did = ? ORDER BY delivery_id", (group_did,)).fetchall()
    anchor = {
        "group_did": group_did, "host_service_did": group["host_service_did"],
        "wire_profile": group["wire_profile"], "document_version": document["document_version"],
        "document_digest": _digest(value), "key_fingerprint": ed25519_root_fingerprint(key.public_key()),
        "roster_digest": _digest(roster), "profile_digest": _digest(group["profile_json"]), "policy_digest": _digest(group["policy_json"]),
        "group_state_version": group["group_state_version"], "group_event_seq": group["group_event_seq"],
        "delivery_inventory_digest": _digest([(row["delivery_id"], _digest(json.loads(row["envelope_json"]))) for row in deliveries]),
    }
    counts: dict[str, int] = {}
    unresolved = []
    for row in deliveries:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
        if row["status"] != "delivered":
            unresolved.append({"target_hash": hashlib.sha256(row["target_did"].encode()).hexdigest()[:16], "service_did": row["target_service_did"], "event_seq": row["group_event_seq"], "status": row["status"]})
    return {**anchor, "plan_digest": _digest(anchor), "protocol_state": group["protocol_state"],
            "active_members": sum(row["status"] == "active" for row in roster), "outbox_counts": counts, "unresolved_deliveries": unresolved}


def inspect_group(settings: Settings, group_did: str) -> dict[str, Any]:
    with _connection(settings) as conn:
        return _inspect(conn, settings, group_did)


def _backup(settings: Settings, destination: Path) -> tuple[str, str]:
    destination = destination.resolve()
    if destination.is_relative_to(settings.data_dir.resolve()) or destination.exists():
        raise InvalidParams("group.migration_backup_path_invalid")
    destination.mkdir(mode=0o700, parents=True)
    target = destination / settings.db_path.name
    with _connection(settings) as source:
        backup = sqlite3.connect(target)
        try:
            source.backup(backup)
            if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise InvalidParams("group.migration_backup_integrity_failed")
        finally:
            backup.close()
    target.chmod(0o600)
    for source_dir in (settings.object_dir, settings.group_key_dir):
        for source in source_dir.rglob("*"):
            if source.is_symlink():
                raise InvalidParams("group.migration_backup_symlink")
            relative = source.relative_to(settings.data_dir)
            copied = destination / relative
            if source.is_dir():
                copied.mkdir(mode=0o700, parents=True, exist_ok=True)
            elif source.is_file():
                copied.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(source, copied)
                copied.chmod(0o600)
    auth_key = settings.data_dir / "auth-token-key.pem"
    if auth_key.exists():
        if auth_key.is_symlink():
            raise InvalidParams("group.migration_backup_symlink")
        shutil.copyfile(auth_key, destination / auth_key.name)
        (destination / auth_key.name).chmod(0o600)
    if settings.service_private_key_pem:
        service_key = destination / "service-key.pem"
        service_key.write_text(settings.service_private_key_pem)
        service_key.chmod(0o600)
    files = {str(path.relative_to(destination)): _file_digest(path) for path in sorted(destination.rglob("*")) if path.is_file()}
    manifest = destination / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "files": files}, sort_keys=True, indent=2) + "\n")
    manifest.chmod(0o600)
    return str(manifest), _file_digest(manifest)


def _verify_backup(path: str, expected_digest: str) -> None:
    manifest = Path(path)
    if manifest.is_symlink() or _file_digest(manifest) != expected_digest:
        raise InvalidParams("group.migration_backup_changed")
    root = manifest.parent.resolve()
    value = json.loads(manifest.read_text())
    if value.get("schema_version") != 1 or not isinstance(value.get("files"), dict):
        raise InvalidParams("group.migration_backup_invalid")
    for name, digest in value["files"].items():
        file = root / name
        if not file.resolve().is_relative_to(root) or file.is_symlink() or _file_digest(file) != digest:
            raise InvalidParams("group.migration_backup_changed")


def prepare_group(settings: Settings, group_did: str, expected_digest: str, backup_dir: Path) -> dict[str, Any]:
    preparation_id = new_id("gpm")
    with _connection(settings, write=True) as conn:
        current = _inspect(conn, settings, group_did)
        if current["wire_profile"] != BASE_V1 or current["plan_digest"] != expected_digest:
            raise Conflict("group.migration_plan_changed")
        previous = conn.execute("SELECT * FROM group_protocol_migrations WHERE group_did = ?", (group_did,)).fetchone()
        if previous is not None and previous["state"] == "prepared" and previous["plan_digest"] == expected_digest and previous["backup_path"]:
            _verify_backup(previous["backup_path"], previous["backup_digest"])
            return {**current, "migration_state": "prepared"}
        document = conn.execute("SELECT document_json FROM group_did_documents WHERE group_did = ?", (group_did,)).fetchone()[0]
        conn.execute("UPDATE hosted_groups SET protocol_state = 'quiescing' WHERE group_did = ?", (group_did,))
        conn.execute("""INSERT INTO group_protocol_migrations(group_did, plan_digest, state, document_before_json, prepared_at, preparation_id)
            VALUES (?, ?, 'preparing', ?, ?, ?) ON CONFLICT(group_did) DO UPDATE SET
            plan_digest=excluded.plan_digest, state='preparing', document_before_json=excluded.document_before_json,
            backup_path=NULL, backup_digest=NULL, prepared_at=excluded.prepared_at, applied_at=NULL, preparation_id=excluded.preparation_id""",
            (group_did, expected_digest, document, now_iso(), preparation_id))
    # Backup I/O happens after the durable group write fence, outside the write
    # transaction. A failure leaves a visible, cancellable preparing state.
    backup_path, backup_digest = _backup(settings, backup_dir)
    with _connection(settings, write=True) as conn:
        current = _inspect(conn, settings, group_did)
        if current["plan_digest"] != expected_digest or current["protocol_state"] != "quiescing":
            raise Conflict("group.migration_plan_changed")
        changed = conn.execute("UPDATE group_protocol_migrations SET state='prepared', backup_path=?, backup_digest=? WHERE group_did=? AND plan_digest=? AND preparation_id=? AND state='preparing'", (backup_path, backup_digest, group_did, expected_digest, preparation_id))
        if changed.rowcount != 1:
            raise Conflict("group.migration_preparation_changed")
    return {**current, "migration_state": "prepared"}


def _require_peer_v2(member: str, settings: Settings) -> None:
    service = runtime._discover_anp_service(member, settings)
    home_did = service.get("serviceDid")
    if not isinstance(home_did, str) or not home_did:
        raise InvalidParams("group.migration_peer_binding_invalid")
    # The member document binds its Home; Home consumes notifications and owns
    # the supported wire versions. A signed older member document may remain v1.
    home = runtime._discover_anp_service(home_did, settings)
    if home.get("serviceDid") != home_did or home.get("serviceEndpoint") != service.get("serviceEndpoint"):
        raise InvalidParams("group.migration_peer_binding_invalid")
    if BASE_V2 not in home.get("profiles", []):
        raise NotSupported("group.migration_peer_v2_required")


def apply_group(settings: Settings, group_did: str, expected_digest: str) -> dict[str, Any]:
    with _connection(settings) as conn:
        record = conn.execute("SELECT * FROM group_protocol_migrations WHERE group_did = ?", (group_did,)).fetchone()
        if record is None or record["plan_digest"] != expected_digest:
            raise Conflict("group.migration_plan_changed")
        if record["state"] == "applied":
            group, _, _, _ = _group_material(conn, settings, group_did)
            if group["wire_profile"] != BASE_V2 or group["protocol_state"] != "active":
                raise Conflict("group.migration_state_inconsistent")
            return {"group_did": group_did, "migration_state": "applied", "plan_digest": expected_digest}
        if record["state"] != "prepared" or not record["backup_path"]:
            raise Conflict("group.migration_not_prepared")
        _verify_backup(record["backup_path"], record["backup_digest"])
        remote = [row["agent_did"] for row in conn.execute("SELECT agent_did FROM hosted_group_members WHERE group_did=? AND status='active' AND home_service_did!=?", (group_did, settings.service_did))]
    # Never hold a SQLite transaction while checking remote capability.
    for member in remote:
        _require_peer_v2(member, settings)
    with _connection(settings, write=True) as conn:
        latest = conn.execute("SELECT * FROM group_protocol_migrations WHERE group_did=?", (group_did,)).fetchone()
        if latest is None or latest["state"] != "prepared" or latest["preparation_id"] != record["preparation_id"] or latest["backup_digest"] != record["backup_digest"]:
            raise Conflict("group.migration_preparation_changed")
        current = _inspect(conn, settings, group_did)
        if current["protocol_state"] != "quiescing" or current["plan_digest"] != expected_digest:
            raise Conflict("group.migration_plan_changed")
        if current["unresolved_deliveries"]:
            raise Conflict("group.migration_outbox_not_drained")
        _, document, value, key = _group_material(conn, settings, group_did)
        for service in value["service"]:
            if service.get("type") == "ANPMessageService":
                service["profiles"] = [BASE_V2 if profile == BASE_V1 else profile for profile in service["profiles"]]
                if BASE_V2 not in service["profiles"]:
                    raise InvalidParams("group.migration_document_profile_invalid")
        value = _sign_did_document(value, key, value["proof"]["verificationMethod"])
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
        conn.execute("UPDATE group_did_documents SET document_json=?, document_version=document_version+1 WHERE group_did=?", (serialized, group_did))
        conn.execute("UPDATE did_documents SET document_json=?, updated_at=? WHERE did=?", (serialized, now_iso(), group_did))
        conn.execute("UPDATE hosted_groups SET wire_profile=?, protocol_state='active' WHERE group_did=?", (BASE_V2, group_did))
        refresh_hosted_local_projections(conn, settings, group_did, updated_at=now_iso())
        conn.execute("UPDATE group_protocol_migrations SET state='applied', applied_at=? WHERE group_did=? AND plan_digest=?", (now_iso(), group_did, expected_digest))
    with runtime._DISCOVERY_CACHE_LOCK:
        runtime._DISCOVERY_CACHE.pop((str(settings.db_path), group_did), None)
    return {"group_did": group_did, "migration_state": "applied", "plan_digest": expected_digest}


def cancel_group(settings: Settings, group_did: str, expected_digest: str) -> dict[str, Any]:
    with _connection(settings, write=True) as conn:
        row = conn.execute("SELECT * FROM group_protocol_migrations WHERE group_did=?", (group_did,)).fetchone()
        if row is None or row["plan_digest"] != expected_digest or row["state"] == "applied":
            raise Conflict("group.migration_cancel_rejected")
        conn.execute("UPDATE hosted_groups SET protocol_state='active' WHERE group_did=? AND wire_profile=?", (group_did, BASE_V1))
        conn.execute("UPDATE group_protocol_migrations SET state='cancelled' WHERE group_did=?", (group_did,))
    return {"group_did": group_did, "migration_state": "cancelled"}
