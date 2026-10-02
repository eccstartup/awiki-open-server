from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import json
from urllib.parse import urlsplit

from awiki_open_server.service_identity import load_private_key_setting


DEFAULT_ATTACHMENT_MIME_TYPES = (
    "application/anp-attachment-manifest+json",
    "application/json",
    "application/octet-stream",
    "application/pdf",
    "image/gif",
    "image/jpeg",
    "image/png",
    "text/plain",
)


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    public_base_url: str
    service_did: str
    did_domain: str
    did_authority: str = ""
    service_private_key_pem: str | None = None
    service_did_document_json: str | None = None
    allow_unsigned_peer_dev: bool = False
    allow_peer_declared_message_service: bool = False
    im_rpc_path: str = "/im/rpc"
    anp_public_rpc_path: str = "/anp-im/rpc"
    ws_path: str = "/im/ws"
    object_upload_path: str = "/objects/upload"
    object_download_path: str = "/objects"
    max_attachment_bytes: int = 10 * 1024 * 1024
    attachment_allowed_mime_types: tuple[str, ...] = DEFAULT_ATTACHMENT_MIME_TYPES
    did_resolver_base_urls: dict[str, str] | None = None
    did_verify_dev_code: str = "666666"
    enable_contact_verification_compat: bool = False
    contact_verification_dev_otp: str = "123456"
    group_max_message_bytes: int = 64 * 1024
    group_outbox_max_pending: int = 10_000
    operations_token: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.did_authority:
            object.__setattr__(
                self, "did_authority", _did_authority_from_service_did(self.service_did, self.did_domain)
            )
        object.__setattr__(self, "im_rpc_path", _normalize_route_path(self.im_rpc_path))
        object.__setattr__(self, "anp_public_rpc_path", _normalize_route_path(self.anp_public_rpc_path))
        object.__setattr__(self, "ws_path", _normalize_route_path(self.ws_path))
        object.__setattr__(self, "object_upload_path", _normalize_route_path(self.object_upload_path))
        object.__setattr__(self, "object_download_path", _normalize_route_path(self.object_download_path))
        object.__setattr__(self, "max_attachment_bytes", max(1, int(self.max_attachment_bytes)))
        object.__setattr__(self, "group_max_message_bytes", max(1, int(self.group_max_message_bytes)))
        object.__setattr__(self, "group_outbox_max_pending", max(1, int(self.group_outbox_max_pending)))
        object.__setattr__(
            self,
            "attachment_allowed_mime_types",
            tuple(sorted({_normalize_mime_type(value) for value in self.attachment_allowed_mime_types if str(value).strip()})),
        )

    @property
    def db_path(self) -> Path:
        return self.data_dir / "awiki-open-server.sqlite3"

    @property
    def object_dir(self) -> Path:
        return self.data_dir / "objects"

    @property
    def group_key_dir(self) -> Path:
        return self.data_dir / "group-keys"

    @property
    def anp_service_endpoint(self) -> str:
        return f"{self.public_base_url.rstrip('/')}{self.anp_public_rpc_path}"


def _did_authority(host: str, declared_base_url: str | None) -> str:
    """本机 DID 的主机段（ANP-03 §2.1）：非默认端口必须写成 `host%3Aport`。

    DID 里的 host 段回答的是"托管这份文档的服务器在哪"，端口属于它，所以
    `did:wba:localhost%3A8765:user:alice:e1_<fp>` 与 `did:wba:localhost:user:alice:e1_<fp>`
    是两条不同的 DID（§2.1），客户端也按前者去取 `https://localhost:8765/.../did.json`。

    端口只能由部署自己声明：`uvicorn --port` 是启动器的参数，应用进程看不到它。
    这里只认**显式给出的** `AWIKI_PUBLIC_BASE_URL`——它的内置默认值
    `http://127.0.0.1:8000` 在任何真实部署里都是假的（那个 host 也不一定就是
    did_domain），跟着它取端口等于把假值刻进 DID。没有显式来源就退回裸域。
    """
    if not declared_base_url:
        return host
    parsed = urlsplit(declared_base_url)
    if parsed.port is None or parsed.port == (443 if parsed.scheme == "https" else 80):
        return host
    return f"{host}%3A{parsed.port}"


def _did_authority_from_service_did(service_did: str, fallback: str) -> str:
    """服务自发布的那条 DID 的 host 段。

    本机 DID 的 host 段只有这一个真相源：`AWIKI_SERVICE_DID` 是运维对"本机是哪条
    DID"的声明，用户的 DID 只是挂在它下面（`...:users:<handle>:e1_<fp>`）。两个旋钮
    各算各的会让服务端发布一条 DID、却按另一条收注册，所以一律跟着它走。
    """
    parts = str(service_did or "").split(":")
    if len(parts) >= 3 and parts[0] == "did" and parts[1] == "wba" and parts[2]:
        return parts[2]
    return fallback


def load_settings() -> Settings:
    data_dir = Path(os.environ.get("AWIKI_DATA_DIR", ".awiki-open-server")).resolve()
    public_base_url = os.environ.get("AWIKI_PUBLIC_BASE_URL", "http://127.0.0.1:8000")
    did_domain = os.environ.get("AWIKI_DID_DOMAIN", "localhost")
    service_did = os.environ.get("AWIKI_SERVICE_DID") or f"did:wba:{_did_authority(did_domain, os.environ.get('AWIKI_PUBLIC_BASE_URL'))}"
    service_private_key_pem = load_private_key_setting(
        os.environ.get("AWIKI_SERVICE_PRIVATE_KEY_PEM"),
        os.environ.get("AWIKI_SERVICE_PRIVATE_KEY_PATH"),
    )
    resolver_base_urls = _load_resolver_base_urls(os.environ.get("AWIKI_DID_RESOLVER_BASE_URLS"))
    return Settings(
        data_dir=data_dir,
        public_base_url=public_base_url,
        service_did=service_did,
        did_domain=did_domain,
        service_private_key_pem=service_private_key_pem,
        service_did_document_json=os.environ.get("AWIKI_SERVICE_DID_DOCUMENT_JSON"),
        allow_unsigned_peer_dev=os.environ.get("AWIKI_ALLOW_UNSIGNED_PEER_DEV", "").lower() in {"1", "true", "yes"},
        allow_peer_declared_message_service=os.environ.get("AWIKI_ALLOW_PEER_DECLARED_MESSAGE_SERVICE", "").lower()
        in {"1", "true", "yes"},
        im_rpc_path=os.environ.get("AWIKI_IM_RPC_PATH", "/im/rpc"),
        anp_public_rpc_path=os.environ.get("AWIKI_ANP_PUBLIC_RPC_PATH", "/anp-im/rpc"),
        ws_path=os.environ.get("AWIKI_WS_PATH", "/im/ws"),
        object_upload_path=os.environ.get("AWIKI_OBJECT_UPLOAD_PATH", "/objects/upload"),
        object_download_path=os.environ.get("AWIKI_OBJECT_DOWNLOAD_PATH", "/objects"),
        max_attachment_bytes=int(os.environ.get("AWIKI_MAX_ATTACHMENT_BYTES", str(10 * 1024 * 1024))),
        attachment_allowed_mime_types=_load_mime_types(os.environ.get("AWIKI_ATTACHMENT_ALLOWED_MIME_TYPES")),
        did_resolver_base_urls=resolver_base_urls,
        did_verify_dev_code=os.environ.get("AWIKI_DID_VERIFY_DEV_CODE") or os.environ.get("DEV_BYPASS_CODE") or "666666",
        enable_contact_verification_compat=os.environ.get("AWIKI_ENABLE_CONTACT_VERIFICATION_COMPAT", "").lower() in {"1", "true", "yes"},
        contact_verification_dev_otp=os.environ.get("AWIKI_CONTACT_VERIFICATION_DEV_OTP", "123456"),
        group_max_message_bytes=int(os.environ.get("AWIKI_GROUP_MAX_MESSAGE_BYTES", str(64 * 1024))),
        group_outbox_max_pending=int(os.environ.get("AWIKI_GROUP_OUTBOX_MAX_PENDING", "10000")),
        operations_token=_load_optional_secret(
            os.environ.get("AWIKI_OPERATIONS_TOKEN"),
            os.environ.get("AWIKI_OPERATIONS_TOKEN_FILE"),
        ),
    )


def _normalize_route_path(path: str) -> str:
    normalized = str(path or "").strip()
    if not normalized:
        raise ValueError("route path must not be empty")
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    while len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    return normalized


def _load_optional_secret(value: str | None, path: str | None) -> str | None:
    secret = str(value or "").strip()
    if not secret and path:
        secret = Path(path).expanduser().read_text(encoding="utf-8").strip()
    return secret or None


def _normalize_mime_type(value: str) -> str:
    return str(value or "").split(";", 1)[0].strip().lower()


def _load_mime_types(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return DEFAULT_ATTACHMENT_MIME_TYPES
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _load_resolver_base_urls(raw: str | None) -> dict[str, str] | None:
    if not raw:
        return None
    value = raw.strip()
    if not value:
        return None
    if value.startswith("{"):
        data = json.loads(value)
        if not isinstance(data, dict):
            raise ValueError("AWIKI_DID_RESOLVER_BASE_URLS must be an object")
        return {str(domain).lower(): str(base).rstrip("/") for domain, base in data.items()}
    mapping: dict[str, str] = {}
    for item in value.split(","):
        if not item.strip():
            continue
        if "=" not in item:
            raise ValueError("AWIKI_DID_RESOLVER_BASE_URLS entries must be domain=base_url")
        domain, base_url = item.split("=", 1)
        mapping[domain.strip().lower()] = base_url.strip().rstrip("/")
    return mapping or None
