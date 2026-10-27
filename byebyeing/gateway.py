#!/usr/bin/env python3
"""OpenAI-compatible reverse proxy that repairs Qwen3.8-Flash-Next conversations.

The gateway is deliberately small and stdlib-only: it listens on loopback,
adds request ids and admission control, optionally requires a bearer key, and
passes everything else through to an upstream OpenAI-compatible server. SSE is
relayed with ``read1`` + flush so a streamed completion is not buffered until
the upstream closes.

Local endpoints (never authenticated, never proxied)::

    GET /health   gateway liveness
    GET /status   gateway counters + active/queue depth + request id

Everything else, including ``GET /metrics``, is proxied.

Banned words: when ``bad_words`` is set, every JSON ``POST`` to a
``/completions`` or ``/chat/completions`` path gets those strings merged into
its vLLM ``bad_words`` sampling field, so the model cannot emit them whatever
the client sends. Used for Qwen3.8's memorised Alibaba OSS proxy URL.

Rewriting: when a ``rewriter`` (``rewrite.Rewriter``) is set, completion
requests have their history scrubbed and their responses (JSON or SSE)
rewritten, so denied strings neither reach the model nor the client. If a key is
configured (``api_key`` or the environment variable named by ``key_env``), a
valid ``Authorization: Bearer <key>`` is required; the header is never logged.
"""

from __future__ import annotations

import hmac
import http.client
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .rewrite import Rewriter

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)


class GatewayServer:
    """Loopback reverse proxy with admission control and optional bearer auth."""

    def __init__(
        self,
        upstream: str | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        upstream_base: str | None = None,
        upstream_url: str | None = None,
        api_key: str | None = None,
        key: str | None = None,
        key_env: str | None = None,
        api_key_env: str | None = None,
        max_queue: int | None = None,
        max_active: int | None = None,
        coalesce_ms: float = 0.0,
        timeout: float = 600.0,
        name: str = "byebyeing-gateway",
        bad_words: list[str] | None = None,
        rewriter: Rewriter | None = None,
    ) -> None:
        base = upstream or upstream_base or upstream_url
        if not base:
            raise ValueError("upstream base URL is required")
        split = urlsplit(base)
        if split.scheme not in ("http", "https") or not split.netloc:
            raise ValueError(f"invalid upstream URL: {base!r}")
        self.upstream = base.rstrip("/")
        self._scheme = split.scheme
        self._netloc = split.netloc
        self._base_path = split.path.rstrip("/")

        self.host = host
        self.port = port
        self.name = name
        self.timeout = float(timeout)
        self.coalesce_ms = max(0.0, float(coalesce_ms))
        if self.coalesce_ms > 1000.0:
            raise ValueError("coalesce_ms must be <= 1000")

        env_name = key_env if key_env is not None else api_key_env
        resolved_key = api_key if api_key is not None else key
        if resolved_key is None and env_name:
            resolved_key = os.environ.get(env_name)
        self.api_key = resolved_key or None

        limit = max_active if max_active is not None else max_queue
        self.max_active = int(limit) if limit is not None else None

        self.bad_words = _clean_words(bad_words)
        self.rewriter = rewriter
        self._injected = 0

        self._lock = threading.Lock()
        self._start_lock = threading.Lock()
        self._active = 0
        self.max_active_seen = 0
        self._requests = 0
        self._rejected = 0
        self._failed = 0
        self._started_at = time.monotonic()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "GatewayServer":
        with self._start_lock:
            if self._httpd is not None:
                return self
            httpd = ThreadingHTTPServer((self.host, self.port), _GatewayHandler)
            httpd.daemon_threads = True
            setattr(httpd, "gateway", self)
            self._httpd = httpd
            self.port = int(httpd.server_address[1])
            self._started_at = time.monotonic()
            self._thread = threading.Thread(
                target=httpd.serve_forever,
                name="serving-gateway",
                daemon=True,
            )
            self._thread.start()
        return self

    def stop(self) -> None:
        with self._start_lock:
            httpd = self._httpd
            thread = self._thread
            self._httpd = None
            self._thread = None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5.0)

    def __enter__(self) -> "GatewayServer":
        return self.start()

    def __exit__(self, *_exc: Any) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        host = "127.0.0.1" if self.host in ("", "0.0.0.0", "::") else self.host
        return f"http://{host}:{self.port}"

    # -- counters ----------------------------------------------------------
    def try_admit(self) -> bool:
        with self._lock:
            if self.max_active is not None and self._active >= self.max_active:
                self._rejected += 1
                return False
            self._active += 1
            self._requests += 1
            self.max_active_seen = max(self.max_active_seen, self._active)
            return True

    def release(self) -> None:
        with self._lock:
            self._active = max(0, self._active - 1)

    def mark_failed(self) -> None:
        with self._lock:
            self._failed += 1

    @property
    def active(self) -> int:
        with self._lock:
            return self._active

    def status(self, request_id: str | None = None) -> dict[str, Any]:
        if request_id is None:
            request_id = uuid.uuid4().hex
        with self._lock:
            active = self._active
            return {
                "status": "ok",
                "gateway": self.name,
                "upstream": self.upstream,
                "request_id": request_id,
                "active": active,
                "active_requests": active,
                "queue": 0,
                "queue_depth": 0,
                "queued": 0,
                "queued_requests": 0,
                "max_active": self.max_active,
                "max_active_seen": self.max_active_seen,
                "requests": self._requests,
                "requests_total": self._requests,
                "rejected": self._rejected,
                "failed": self._failed,
                "uptime_s": round(time.monotonic() - self._started_at, 3),
                "auth": "bearer" if self.api_key else "none",
                "coalesce_ms": self.coalesce_ms,
                "bad_words": len(self.bad_words),
                "bad_words_injected": self._injected,
                "rewrites": dict(self.rewriter.counts) if self.rewriter else None,
            }

    # -- proxy helpers -----------------------------------------------------
    def upstream_target(self, raw_path: str) -> str:
        split = urlsplit(raw_path)
        path = split.path or "/"
        if self._base_path and not (
            path == self._base_path or path.startswith(self._base_path + "/")
        ):
            path = self._base_path + path
        target = path
        if split.query:
            target += "?" + split.query
        return target

    @staticmethod
    def is_completion(method: str, raw_path: str) -> bool:
        return method == "POST" and urlsplit(raw_path).path.rstrip("/").endswith("/completions")

    def prepare_body(self, method: str, raw_path: str, body: bytes, request_id: str = "") -> bytes:
        """Merge banned words into, and scrub the history of, a completion request.

        Bodies that are not a JSON object are passed through unchanged; the
        upstream rejects them anyway.
        """
        if not (self.bad_words or self.rewriter) or not body or not self.is_completion(method, raw_path):
            return body
        try:
            payload = json.loads(body)
        except ValueError:
            return body
        if not isinstance(payload, dict):
            return body
        if self.bad_words:
            existing = payload.get("bad_words")
            merged = _clean_words(existing if isinstance(existing, list) else [])
            merged += [word for word in self.bad_words if word not in merged]
            payload["bad_words"] = merged
            with self._lock:
                self._injected += 1
        if self.rewriter:
            self.rewriter.scrub_request(payload, request_id)
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def inject_bad_words(self, method: str, raw_path: str, body: bytes) -> bytes:
        """Back-compat alias used by older callers and tests."""
        return self.prepare_body(method, raw_path, body)

    def authorized(self, authorization: str | None) -> bool:
        if not self.api_key:
            return True
        if not authorization:
            return False
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer":
            return False
        # Constant-time comparison; the value is never logged.
        return hmac.compare_digest(
            token.strip().encode("utf-8"), self.api_key.encode("utf-8")
        )


def _clean_words(words: Any) -> list[str]:
    out: list[str] = []
    for word in words or []:
        if isinstance(word, str) and word.strip() and word not in out:
            out.append(word)
    return out


def load_bad_words(path: str) -> list[str]:
    """Read banned words from a JSON list or a ``{"bad_words": [...]}`` object."""
    with open(path, encoding="utf-8") as stream:
        data = json.load(stream)
    if isinstance(data, dict):
        data = data.get("bad_words", [])
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a list of strings")
    return _clean_words(data)


class _GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    _headers_sent = False

    @property
    def gateway(self) -> GatewayServer:
        return getattr(self.server, "gateway")

    def log_message(self, *_args: Any) -> None:
        # Never log headers: Authorization must not reach logs.
        return

    # -- methods -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle()

    def do_PATCH(self) -> None:  # noqa: N802
        self._handle()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._handle()

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle()

    # -- dispatch ----------------------------------------------------------
    def _handle(self) -> None:
        gateway = self.gateway
        self._headers_sent = False
        request_id = self.headers.get("X-Request-Id") or uuid.uuid4().hex
        path = urlsplit(self.path).path.rstrip("/") or "/"

        if path == "/health":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "gateway": gateway.name,
                    "upstream": gateway.upstream,
                    "request_id": request_id,
                },
                request_id,
            )
            return
        if path == "/status":
            self._send_json(200, gateway.status(request_id), request_id)
            return

        if not gateway.authorized(self.headers.get("Authorization")):
            self.close_connection = True
            self._send_json(
                401,
                {
                    "error": {
                        "message": "missing or invalid bearer token",
                        "type": "authentication_error",
                        "code": 401,
                    }
                },
                request_id,
                extra_headers={"WWW-Authenticate": "Bearer"},
            )
            return

        if not gateway.try_admit():
            self.close_connection = True
            self._send_json(
                429,
                {
                    "error": {
                        "message": f"gateway max_active ({gateway.max_active}) reached",
                        "type": "rate_limit_error",
                        "code": 429,
                    }
                },
                request_id,
                extra_headers={"Retry-After": "1"},
            )
            return

        try:
            body = gateway.prepare_body(self.command, self.path, self._read_body(), request_id)
            if gateway.coalesce_ms:
                # Optional, deliberately small batching window.  Default is 0:
                # a multi-second wait is terrible for a single interactive
                # request, and vLLM already batches at scheduler iterations.
                time.sleep(gateway.coalesce_ms / 1000.0)
            self._proxy(gateway, request_id, body)
        finally:
            gateway.release()

    # -- upstream ----------------------------------------------------------
    def _proxy(self, gateway: GatewayServer, request_id: str, body: bytes) -> None:
        headers: dict[str, str] = {}
        for key, value in self.headers.items():
            lower = key.lower()
            if lower in HOP_BY_HOP or lower in ("host", "content-length", "expect", "x-request-id"):
                continue
            headers[key] = value
        headers["X-Request-Id"] = request_id
        if body:
            headers["Content-Length"] = str(len(body))
        elif self.command in ("POST", "PUT", "PATCH"):
            headers["Content-Length"] = "0"

        target = gateway.upstream_target(self.path)
        connection_cls = (
            http.client.HTTPSConnection
            if gateway._scheme == "https"
            else http.client.HTTPConnection
        )
        conn = connection_cls(gateway._netloc, timeout=gateway.timeout)
        upstream: http.client.HTTPResponse | None = None
        try:
            conn.request(self.command, target, body=body or None, headers=headers)
            upstream = conn.getresponse()
            if gateway.rewriter and gateway.is_completion(self.command, self.path):
                self._relay_rewritten(upstream, request_id, gateway.rewriter)
            else:
                self._relay_response(upstream, request_id, body_allowed=self.command != "HEAD")
        except (OSError, http.client.HTTPException) as exc:
            gateway.mark_failed()
            if not self._headers_sent:
                self._send_json(
                    502,
                    {
                        "error": {
                            "message": f"upstream request failed: {type(exc).__name__}",
                            "type": "gateway_error",
                            "code": 502,
                        }
                    },
                    request_id,
                    extra_headers={"Retry-After": "1"},
                )
            else:
                self.close_connection = True
        finally:
            if upstream is not None:
                upstream.close()
            conn.close()

    def _relay_response(
        self,
        upstream: http.client.HTTPResponse,
        request_id: str,
        *,
        body_allowed: bool,
    ) -> None:
        content_length = upstream.getheader("Content-Length")
        self.send_response(upstream.status)
        for key, value in upstream.getheaders():
            lower = key.lower()
            if lower in HOP_BY_HOP or lower in (
                "content-length",
                "server",
                "date",
                "x-request-id",
            ):
                continue
            self.send_header(key, value)
        if content_length is not None:
            self.send_header("Content-Length", content_length)
        self.send_header("X-Request-Id", request_id)
        if content_length is None:
            # No framing for the response: signal EOF to the client. SSE
            # upstreams normally fall into this branch.
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self._headers_sent = True

        if not body_allowed:
            return
        # read1 returns as soon as bytes are available, unlike read(n), which
        # would wait for the full n-byte buffer and buffer the SSE stream.
        while True:
            try:
                chunk = upstream.read1(65536)
            except AttributeError:  # pragma: no cover - Python without read1
                chunk = upstream.read(1)
            if not chunk:
                break
            self.wfile.write(chunk)
            self.wfile.flush()

    def _relay_rewritten(
        self,
        upstream: http.client.HTTPResponse,
        request_id: str,
        rewriter: Rewriter,
    ) -> None:
        ctype = (upstream.getheader("Content-Type") or "").lower()
        if "text/event-stream" in ctype:
            self._relay_sse(upstream, request_id, rewriter)
            return
        raw = upstream.read()
        if "json" in ctype:
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = None
            if isinstance(payload, dict):
                raw = json.dumps(rewriter.rewrite_response(payload, request_id),
                                 separators=(",", ":")).encode("utf-8")
        self.send_response(upstream.status)
        for key, value in upstream.getheaders():
            lower = key.lower()
            if lower in HOP_BY_HOP or lower in ("content-length", "server", "date", "x-request-id"):
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Request-Id", request_id)
        self.end_headers()
        self._headers_sent = True
        self.wfile.write(raw)

    def _relay_sse(self, upstream: http.client.HTTPResponse, request_id: str, rewriter: Rewriter) -> None:
        self.send_response(upstream.status)
        for key, value in upstream.getheaders():
            lower = key.lower()
            if lower in HOP_BY_HOP or lower in ("content-length", "server", "date", "x-request-id"):
                continue
            self.send_header(key, value)
        self.send_header("X-Request-Id", request_id)
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        self._headers_sent = True

        state = rewriter.stream(request_id)
        pending = b""
        done = False

        def emit_obj(obj: dict[str, Any]) -> None:
            self.wfile.write(b"data: " + json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n\n")

        def handle_event(event: bytes) -> None:
            nonlocal done
            out_lines = []
            for line in event.split(b"\n"):
                if line.startswith(b"data:"):
                    data = line[5:].strip()
                    if data == b"[DONE]":
                        for obj in state.drain():
                            emit_obj(obj)
                        done = True
                        out_lines.append(b"data: [DONE]")
                        continue
                    try:
                        obj = json.loads(data)
                    except ValueError:
                        out_lines.append(line)
                        continue
                    if isinstance(obj, dict):
                        obj = state.chunk(obj)
                    out_lines.append(b"data: " + json.dumps(obj, separators=(",", ":")).encode("utf-8"))
                else:
                    out_lines.append(line)
            self.wfile.write(b"\n".join(out_lines) + b"\n\n")

        while True:
            try:
                chunk = upstream.read1(65536)
            except AttributeError:  # pragma: no cover - Python without read1
                chunk = upstream.read(1)
            if not chunk:
                break
            pending += chunk.replace(b"\r\n", b"\n")
            while b"\n\n" in pending:
                event, pending = pending.split(b"\n\n", 1)
                if event.strip():
                    handle_event(event)
            self.wfile.flush()
        if pending.strip():
            handle_event(pending)
        if not done:
            for obj in state.drain():
                emit_obj(obj)
        self.wfile.flush()

    # -- request/response helpers -----------------------------------------
    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        request_id: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Request-Id", request_id)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self._headers_sent = True
        self.wfile.write(body)
