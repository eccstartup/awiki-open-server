"""Bounded direct HTTP requests to a single validated DNS resolution."""

from __future__ import annotations

import http.client
import io
import ipaddress
import socket
import ssl
import time
import urllib.parse

from awiki_open_server.shared.errors import InvalidParams


class _DeadlineReader(io.RawIOBase):
    def __init__(self, transport):
        self.transport = transport
        transport.readers += 1

    def readable(self):
        return True

    def readinto(self, buffer):
        self.transport.limit_timeout()
        return self.transport.socket.recv_into(buffer)

    def close(self):
        if not self.closed:
            self.transport.readers -= 1
            self.transport.close_if_unused()
        super().close()


class _DeadlineSocket:
    def __init__(self, sock, deadline: float):
        self.socket = sock
        self.deadline = deadline
        self.readers = 0
        self.closed = False

    def limit_timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("outbound request timed out")
        self.socket.settimeout(remaining)

    def sendall(self, data):
        self.limit_timeout()
        self.socket.sendall(data)

    def makefile(self, mode):
        if mode != "rb":
            raise ValueError("outbound response requires a binary reader")
        return io.BufferedReader(_DeadlineReader(self))

    def close_if_unused(self):
        if self.closed and self.readers == 0:
            self.socket.close()

    def close(self):
        self.closed = True
        self.close_if_unused()


def resolve_target(url: str, *, allow_private: bool = False):
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise InvalidParams("outbound_url_invalid") from exc
    if parsed.username or parsed.password:
        raise InvalidParams("outbound_url_userinfo_not_allowed")
    if parsed.scheme not in ({"http", "https"} if allow_private else {"https"}):
        raise InvalidParams("outbound_url_scheme_not_allowed")
    if not parsed.hostname:
        raise InvalidParams("outbound_url_host_required")
    if parsed.fragment or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url) or "\\" in url or not 1 <= port <= 65535:
        raise InvalidParams("outbound_url_invalid")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        if not addresses:
            raise ValueError("empty DNS response")
        for family, _, _, _, address in addresses:
            if family not in {socket.AF_INET, socket.AF_INET6}:
                raise ValueError("unsupported address family")
            ip = ipaddress.ip_address(address[0])
            if not allow_private and not ip.is_global:
                raise InvalidParams("outbound_url_private_address_not_allowed", data={"host": parsed.hostname})
    except (OSError, ValueError) as exc:
        raise InvalidParams("outbound_url_host_unresolvable", data={"host": parsed.hostname}) from exc
    return parsed, addresses


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, parsed: urllib.parse.SplitResult, addresses, *, timeout: float = 15):
        self._target = parsed
        self._addresses = addresses
        self._deadline = time.monotonic() + timeout
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        super().__init__(parsed.hostname, port, timeout=timeout)

    def connect(self):
        deadline = self._deadline
        last_error = None
        for family, socktype, protocol, _, address in self._addresses:
            sock = socket.socket(family, socktype, protocol)
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("outbound connection timed out")
                sock.settimeout(remaining)
                sock.connect(address)
                if self._target.scheme == "https":
                    sock.settimeout(max(0.001, deadline - time.monotonic()))
                    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self._target.hostname)
                self.sock = _DeadlineSocket(sock, deadline)
                return
            except (OSError, ssl.SSLError) as exc:
                last_error = exc
                sock.close()
        raise last_error or OSError("outbound connection unavailable")


def request_bytes(url: str, *, method: str, headers=None, body: bytes | None = None, allow_private: bool = False, limit: int = 1024 * 1024) -> bytes:
    parsed, addresses = resolve_target(url, allow_private=allow_private)
    connection = PinnedConnection(parsed, addresses)
    request_headers = dict(headers or {})
    for key in list(request_headers):
        if key.lower() == "host":
            if request_headers.pop(key).lower() != parsed.netloc.lower():
                raise InvalidParams("outbound_host_header_mismatch")
    request_headers["Host"] = parsed.netloc
    target = parsed.path or "/"
    if parsed.query:
        target += f"?{parsed.query}"
    response = None
    try:
        connection.request(method, target, body=body, headers=request_headers)
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            # Redirects are never followed; credentials/signatures stay on the
            # exact endpoint which was discovered and validated.
            raise InvalidParams("remote_http_status", data={"status": response.status})
        raw = response.read(limit + 1)
        if len(raw) > limit:
            raise InvalidParams("remote_response_too_large", data={"max_bytes": limit})
        return raw
    finally:
        if response is not None:
            response.close()
        connection.close()
