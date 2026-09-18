# AWiki Open Server Client Compatibility

[English](client-compatibility.md) | [简体中文](client-compatibility.zh-CN.md)

Last reviewed: 2026-09-18. Unpublished candidate evidence and historical released-client evidence are distinguished below.

## Current protocol-upgrade path (R3)

Acceptance uses the official unmodified CLI from `https://awiki.info/cli/stable/manifest.json`: version **1.0.52**, commit `dde0a9c54eebf29a2ec97089e90a1fa77ba768c5`, linux-amd64 SHA-256 `a055da8dad2969739c50cee4f2ee0bf34b45f5354ea74617f103534b239f9d1a`. Do not use candidate16, `--community`, or an unreleased 1.0.53 Community build as the current path.

New identities use official `id register` with a handle plus phone verification material. Open Server does not send SMS; `send_otp` with purpose `awiki.identity.register.v1` stores a one-time local operator code under the data directory. Pass that code as `--otp`. The reliable listener requires an actual single-device Manifest/binding. Official CLI 1.0.52 always requests P5/P6; Open Server returns `sync.lanes_not_supported` and does not implement E2EE. Ordinary Schema 3 Snapshot recovery is implemented for the single device. Open does not provide identity/Handle recovery or Root Transfer.

R2 unpublished CLI 1.0.53 / SHA `8169383d86a57eaed23e015dc948f8176216e9f81903d16f590dd03c513f847f` over `c61fa4b419b96fdabdbd321f1a8e47cdd7f77302` is historical only.

## 1. Historical evidence and client scope

| Client/peer | Position | Known capabilities | Key limitations |
| --- | --- | --- | --- |
| `awiki-cli` | Primary compatibility client | 1.0.43 `bbeb8a5c`: local Attachment/members/mark-read/restart, Realtime Sync v2, and bidirectional Direct/Group cross-domain gates verified | Sync v2 is single-device pull only; no device sharing, second device, or E2EE. Ordinary Schema 3 Snapshot recovery is implemented for that device. |
| AWiki Me | Basic product compatibility target | Identity/messages/attachments on a custom tenant require continuous validation | Agent realm allowlist, no E2EE, and no claim of every app feature. |
| Other ANP peer | Selected public methods | Capability, Direct, selected Group/Attachment | Not complete federation; origin proof and service signature required. |
| Legacy AWiki client | Compatibility routes | User/Message Service-shaped routes | Shims are not production identity providers or a complete hosted platform. |

## 2. awiki-cli

Repository and public gates cover DID registration; Direct send, Inbox, and History; Group create/get/list/add/join/members/update/send/messages/leave/remove in both host directions; People follow/status/following/followers; Site root/pages; and attachments as implemented.

Those are gate targets, not a claim that every future client passes automatically. A clean `awiki-cli` 1.0.43 build at commit `bbeb8a5c` was verified on 2026-08-08. The real-CLI gates cover binary Direct/Group Attachment download with byte comparison, members and cursor pagination, idempotent mark-read and restart persistence, foreground Realtime with `awiki.sync.changed.v2`, listener/server restart recovery, and two independent TLS domains with bidirectional plaintext Direct and a Community Group hosted in each direction. The v2 sync profile is a wire-version contract, not a multi-device claim: Open Server binds one DID to exactly one device and one client instance and rejects additional devices/instances. Empty accounts may use tail-only bootstrap; log gaps and expired cursors recover through Schema 3 paged Snapshot (`awiki.message-sync.explicit-negotiation.v1`, `sync.snapshot_paging.v1`), then ordinary delta. Official CLI 1.0.52 still requests P5/P6 lanes, which Open Server rejects with `sync.lanes_not_supported` (no silent empty-lane accept, no E2EE). Cross-device state sharing is not provided.

Run the gates separately:

```bash
# Connection gate: configure, register, and perform a plaintext Direct write.
uv run --locked python scripts/awiki_open_cli.py smoke-rust-cli-connect \
  --awiki-cli-bin /path/to/pinned/awiki-cli --clean

# Complete local gate. Standard HTTPS is required for attachment DID discovery;
# the script creates an isolated Linux network namespace and test CA.
uv run --locked python scripts/awiki_open_cli.py smoke-rust-cli-local \
  --awiki-cli-bin /path/to/pinned/awiki-cli --standard-https --clean

# Foreground Realtime/Sync v2 plus listener and OpenServer restart recovery.
uv run --locked python scripts/awiki_open_cli.py smoke-rust-cli-realtime-restart \
  --awiki-cli-bin /path/to/pinned/awiki-cli --clean

# Two TLS OpenServer domains, bidirectional plaintext Direct and both Group Host directions.
uv run --locked python scripts/awiki_open_cli.py smoke-rust-cli-cross-domain \
  --awiki-cli-bin /path/to/pinned/awiki-cli --clean
```

The namespace-backed HTTPS gates require Linux `unshare`, `mount`, and `ip`. They do not alter the host network or install a listener service. The opt-in pytest wrapper is:

```bash
AWIKI_RUN_RUST_CLI_SYSTEM_TESTS=1 AWIKI_CLI_BIN=/path/to/pinned/awiki-cli \
uv run --locked python -m pytest tests/test_rust_cli_system.py -q
```

Reports must distinguish `connection-and-write passed`, `single-device sync v2 passed`, and `full local user journey passed`. Record the CLI commit, `awiki-cli version`, artifact SHA-256, Open Server commit, and date.

Candidate connection example, after configuring [CLI identity secret storage](https://github.com/AgentConnect/awiki-cli-rs2/blob/c61fa4b419b96fdabdbd321f1a8e47cdd7f77302/docs/architecture/identity-secret-storage.md):

```bash
awiki-cli tenant create open \
  --backend-base-url https://open.example.com \
  --did-host open.example.com
awiki-cli tenant use open
awiki-cli id register --handle alice --phone +15550000001
awiki-cli id register --handle alice --phone +15550000001 --otp <local-operator-code>
```

Do not use `--secure required` or treat the Contact Verification development shim as real SMS/email. Group admission is immediate-active `group.add` or `group.join`; clients must not expect invitation tokens, join codes, pending membership, or an accept-invite command.

## 3. AWiki Me

A basic tenant needs a reachable backend base URL, matching DID host, compatibility routes for the app version, reachable attachment URLs/tickets, and matching WebSocket route/ticket flow.

Verify registration/login; Direct send/receive/history; unread/read; Group create/add/join/update/send/messages/leave/remove; attachment send/download/open; People/Contact/Profile; and app restart/local sync recovery.

### Agent/Daemon limitation

AWiki Me enables Agent/Daemon APIs only for `awiki.ai`, `awiki.info`, and `anpclaw.com`. A normal self-hosted domain may support login and messages while the Agent page remains unsupported. Open Server compatibility routes do not bypass the app realm policy.

### E2EE

Open Server implements neither Direct nor Group E2EE. AWiki Me must treat it as a non-E2EE tenant and must not show a misleading end-to-end-encrypted state.

## 4. Public ANP methods

Public `/anp-im/rpc` exposes `anp.get_capabilities`, `direct.send`, the Community Group Host methods (`group.create/get_info/join/add/remove/rebind_member/leave/update_profile/update_policy/send`), the `group.incoming` and `group.state_changed` Notifications, and `attachment.get_download_ticket`. Local `/im/rpc` additionally contains Inbox, History, Sync, Read State, local Group views, and attachment-control methods. Do not expose all local compatibility RPC as a cross-domain contract.

## 5. Meaning of compatibility routes

User Service/Message Service-shaped routes are implemented locally and do not proxy `awiki.info`. They let current clients reuse existing shapes, provide local profile/token/DID/relationship/message entry points, return `contact_verification_not_enabled` when appropriate, and provide local verification headers for integrations such as Nginx `auth_request`.

Compatibility does not mean a complete hosted platform, production identity provider, complete Agent orchestration, large-group/complex governance, or permanent compatibility with every future client.

## 6. Verification record

```text
Date: YYYY-MM-DD
Open Server commit/version:
Client name/version/commit:
Domain/base URL:
ANP SDK version:

Passed:
- identity
- direct
- inbox/history
- read/sync
- Community Group v1 lifecycle and both cross-domain host directions
- attachment
- people/profile/site
- websocket/restart

Limitations/failures:
- agent
- secure
- large-group/complex governance
- ...
```

Custom tenants do not automatically discover another tenant’s legacy credentials. Explicitly import with `awiki-cli --migration id import-v1 --name <name> --credentials-dir <legacy-credentials-directory>`. The source override applies only to this import; it does not change tenant configuration or enable the reliable listener.
