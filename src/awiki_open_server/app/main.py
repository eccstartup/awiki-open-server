from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
import json
import logging
import threading

from fastapi import FastAPI

from awiki_open_server.app.api_contract import ApiContractMetrics, ApiContractMiddleware
from awiki_open_server.app.realtime import RealtimeHub
from awiki_open_server.app.settings import Settings, load_settings
from awiki_open_server.service_identity import did_document_proof_issue, service_identity_from_settings
from awiki_open_server.messaging.groups.outbox import run_group_outbox
from awiki_open_server.storage.db import Store
from awiki_open_server.messaging.standard_sync import load_or_create_page_ref_key
from awiki_open_server.user_compat.device_auth import load_token_signing_key

logger = logging.getLogger(__name__)

_LEGACY_PROOF_REPORT_LIMIT = 20

# A document the server can no longer verify is withdrawn, not revoked: the
# subject did nothing wrong, the encoding it registered under is no longer
# accepted, and re-registering the same subject restores service. Resolution
# must stop serving it because no peer can verify it either.
UNVERIFIABLE_PROOF_STATUS = "unverifiable_proof"


def report_unverifiable_did_documents(store: Store) -> list[tuple[str, str]]:
    """Find stored DID Documents a resolver can serve but nobody can verify.

    Documents registered before `proofValue` became base58-btc multibase
    (ANP-03 §2.5.5) keep resolving, so an upgrade would otherwise hand peers an
    identity that fails their binding check. The server holds no client key, so
    they can only be re-registered, not repaired; startup withdraws them.
    """
    with store.connect() as conn:
        rows = conn.execute(
            """
            SELECT did, document_json FROM did_documents
            WHERE COALESCE(status, 'active') = 'active' AND revoked_at IS NULL
            """
        ).fetchall()
    flagged: list[tuple[str, str]] = []
    for row in rows:
        try:
            document = json.loads(row["document_json"])
        except ValueError:
            flagged.append((row["did"], "did_document_unparsable"))
            continue
        issue = did_document_proof_issue(document)
        if issue is not None:
            flagged.append((row["did"], issue))
    return flagged


def _report_unverifiable_did_documents(store: Store) -> None:
    flagged = report_unverifiable_did_documents(store)
    if not flagged:
        return
    disabled = disable_did_documents(store, [did for did, _ in flagged])
    shown = ", ".join(f"{did} ({issue})" for did, issue in flagged[:_LEGACY_PROOF_REPORT_LIMIT])
    logger.warning(
        "did_documents_unverifiable_proof: disabled %d active DID Document(s) that fail proof "
        "verification and must be re-registered; showing %d: %s",
        disabled,
        min(len(flagged), _LEGACY_PROOF_REPORT_LIMIT),
        shown,
    )


def disable_did_documents(store: Store, dids: list[str]) -> int:
    """Stop a DID Document from resolving, so no peer is handed an invalid one.

    The server holds no client key, so a document that fails proof verification
    cannot be repaired — only withdrawn until its owner registers again. Returns
    how many rows actually changed, which is 0 once this has already run.
    """
    if not dids:
        return 0
    with store.connect() as conn:
        cursor = conn.executemany(
            """
            UPDATE did_documents SET status = ?
            WHERE did = ? AND COALESCE(status, 'active') = 'active' AND revoked_at IS NULL
            """,
            [(UNVERIFIABLE_PROOF_STATUS, did) for did in dids],
        )
        return cursor.rowcount


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.object_dir.mkdir(parents=True, exist_ok=True)
    settings.group_key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    settings.group_key_dir.chmod(0o700)
    store = Store(settings.db_path, settings.did_domain)
    _report_unverifiable_did_documents(store)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.group_outbox_task = asyncio.create_task(run_group_outbox(app))
        try:
            yield
        finally:
            task = app.state.group_outbox_task
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="Awiki Open Server", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.store = store
    app.state.auth_token_signing_key = load_token_signing_key(settings.data_dir, settings.service_private_key_pem)
    app.state.snapshot_page_ref_key = load_or_create_page_ref_key(settings.data_dir)
    app.state.realtime_hub = RealtimeHub()
    app.state.group_outbox_lock = threading.Lock()
    app.state.group_outbox_last_heartbeat = None
    app.state.group_outbox_last_result = None
    app.state.api_contract_metrics = ApiContractMetrics()
    app.state.service_identity = service_identity_from_settings(
        service_did=settings.service_did,
        endpoint=settings.anp_service_endpoint,
        private_key_pem=settings.service_private_key_pem,
        document_json=settings.service_did_document_json,
    )

    from awiki_open_server.app.routes import mount_routes

    mount_routes(app)
    app.add_middleware(
        ApiContractMiddleware,
        metrics=app.state.api_contract_metrics,
        local_message_paths={settings.im_rpc_path},
    )

    return app


app = create_app
