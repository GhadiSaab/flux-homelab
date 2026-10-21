#!/usr/bin/env python3
import datetime
import hmac
import json
import os
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import error as urlerror
from urllib import request as urlrequest

PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
DEFAULT_PROTOCOL = "2024-11-05"

UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:8081/mcp")
UPSTREAM_HEALTH_URL = os.environ.get("UPSTREAM_HEALTH_URL", "http://127.0.0.1:8081/healthz")
AUTH_TOKENS_FILE = os.environ.get("AUTH_TOKENS_FILE", "/etc/mcp-auth/tokens")
MAX_REQUEST_BYTES = int(os.environ.get("MAX_REQUEST_BYTES", "1048576"))
MAX_RESPONSE_BYTES = int(os.environ.get("MAX_RESPONSE_BYTES", "262144"))
MAX_UPSTREAM_BYTES = int(os.environ.get("MAX_UPSTREAM_BYTES", "2097152"))
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT_SECONDS", "15"))
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_BURST = int(os.environ.get("RATE_LIMIT_BURST", "10"))
MAX_CONCURRENCY = int(os.environ.get("MAX_CONCURRENCY", "4"))
GATEWAY_VERSION = os.environ.get("GATEWAY_VERSION", "hom24-1")
UNTRUSTED_AUDIT_HEADERS = (
    "X-Paperclip-Agent",
    "X-Paperclip-Issue",
    "X-Paperclip-Run",
)

NS_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")

SECRET_PATTERNS = (
    (
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
        "Bearer [REDACTED]",
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.S,
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    (
        re.compile(r"(?i)(https?://[^/\s:@]+:)[^/\s@]+@"),
        r"\1[REDACTED]@",
    ),
    (
        re.compile(
            r"(?i)\b(password|passwd|secret|token|api[_-]?key|client[_-]?secret|authorization)\b"
            r"(\s*[:=]\s*)([\"']?)([^\s\"',}]+)"
        ),
        r"\1\2\3[REDACTED]",
    ),
)


class InvalidArguments(Exception):
    pass


class UpstreamError(Exception):
    def __init__(self, code, message, detail=""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail


def log_event(**fields):
    fields.setdefault("ts", datetime.datetime.now(datetime.timezone.utc).isoformat())
    sys.stdout.write(json.dumps(fields, sort_keys=True, default=str) + "\n")
    sys.stdout.flush()


def load_tokens(path):
    tokens = {}
    with open(path, "r", encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"invalid token entry on line {lineno}")
            label, value = line.split("=", 1)
            label = label.strip()
            value = value.strip()
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", label):
                raise ValueError(f"invalid caller label on line {lineno}")
            if len(value) < 24:
                raise ValueError(f"token too short on line {lineno}")
            if label in tokens:
                raise ValueError(f"duplicate caller label {label}")
            tokens[label] = value
    if not tokens:
        raise ValueError("no tokens configured")
    return tokens


def identify(authorization, tokens):
    if not authorization:
        return None
    scheme, _, supplied = authorization.partition(" ")
    if scheme.lower() != "bearer" or not supplied:
        return None
    supplied = supplied.strip()
    matched = None
    for label, token in tokens.items():
        if hmac.compare_digest(supplied, token):
            matched = label
    return matched


def sanitize(text):
    if not isinstance(text, str):
        return text
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def bound_text(text, limit=None):
    limit = MAX_RESPONSE_BYTES if limit is None else limit
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    cut = encoded[:limit].decode("utf-8", "ignore")
    return cut + f"\n[truncated at {limit} bytes; {len(encoded) - limit} bytes omitted]"


def cap_table(text, limit):
    lines = text.splitlines()
    if len(lines) <= limit + 1:
        return text
    kept = lines[: limit + 1]
    return "\n".join(kept) + f"\n[truncated: showing {limit} of {len(lines) - 1} rows]"


def parse_timestamp(value):
    value = value.strip()
    if not value:
        return None
    candidates = (value, re.sub(r"\.\d+", "", value))
    formats = (
        "%Y-%m-%d %H:%M:%S %z %Z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
    )
    for candidate in candidates:
        for fmt in formats:
            try:
                return datetime.datetime.strptime(candidate, fmt).timestamp()
            except ValueError:
                continue
    return None


def filter_events(text, since_minutes, limit, now=None):
    now = time.time() if now is None else now
    cutoff = now - since_minutes * 60
    parts = re.split(r"(?m)^- InvolvedObject:", text)
    if len(parts) <= 1:
        return cap_table(text, limit)
    intro = parts[0].strip()
    entries = []
    for part in parts[1:]:
        block = "- InvolvedObject:" + part
        match = re.search(r"(?m)^\s+(?:Timestamp|LastTimestamp|EventTime):\s*(.+?)\s*$", block)
        timestamp = parse_timestamp(match.group(1)) if match else None
        entries.append((timestamp, block.rstrip()))
    recent = [entry for entry in entries if entry[0] is not None and entry[0] >= cutoff]
    unknown = [entry for entry in entries if entry[0] is None]
    recent.sort(key=lambda entry: entry[0], reverse=True)
    selected = (recent + unknown)[:limit]
    header = intro + f"\n# window={since_minutes}m returned={len(selected)} parsed={len(entries)}"
    return header + "\n" + "\n".join(block for _, block in selected)


class RateLimiter:
    def __init__(self, per_minute, burst, clock=time.monotonic):
        self.rate = per_minute / 60.0
        self.burst = float(burst)
        self.clock = clock
        self.state = {}
        self.lock = threading.Lock()

    def allow(self, label):
        now = self.clock()
        with self.lock:
            tokens, last = self.state.get(label, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                self.state[label] = (tokens - 1.0, now)
                return True, 0.0
            self.state[label] = (tokens, now)
            return False, (1.0 - tokens) / self.rate


class Upstream:
    def __init__(self, url=None, timeout=None):
        self.url = url or UPSTREAM_URL
        self.timeout = timeout or UPSTREAM_TIMEOUT

    def _post(self, payload, timeout):
        body = json.dumps(payload).encode("utf-8")
        request = urlrequest.Request(
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            method="POST",
        )
        try:
            with urlrequest.urlopen(request, timeout=timeout) as response:
                raw = response.read(MAX_UPSTREAM_BYTES + 1)
        except urlerror.HTTPError as exc:
            detail = exc.read(2048).decode("utf-8", "ignore")
            raise UpstreamError(
                f"upstream_http_{exc.code}", f"upstream returned HTTP {exc.code}", detail
            ) from exc
        except (urlerror.URLError, socket.timeout, TimeoutError, OSError) as exc:
            raise UpstreamError("upstream_unavailable", "upstream is unreachable", str(exc)) from exc
        if len(raw) > MAX_UPSTREAM_BYTES:
            raise UpstreamError(
                "upstream_response_too_large",
                f"upstream response exceeded {MAX_UPSTREAM_BYTES} bytes",
            )
        text = raw.decode("utf-8", "replace")
        if not text.lstrip().startswith("{"):
            for line in text.splitlines():
                if line.startswith("data:"):
                    text = line[5:].strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise UpstreamError("upstream_protocol_error", "upstream returned invalid JSON") from exc

    def call(self, tool, arguments, timeout=None):
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
        message = self._post(payload, timeout or self.timeout)
        if "error" in message:
            error = message.get("error") or {}
            raise UpstreamError(
                "upstream_rpc_error",
                str(error.get("message", "upstream RPC error")),
            )
        result = message.get("result") or {}
        texts = [
            item.get("text", "")
            for item in result.get("content", [])
            if item.get("type") == "text"
        ]
        text = "\n".join(texts)
        if result.get("isError"):
            raise UpstreamError("upstream_tool_error", text or "upstream reported an error")
        return text

    def healthy(self):
        try:
            with urlrequest.urlopen(UPSTREAM_HEALTH_URL, timeout=2) as response:
                return 200 <= response.status < 300
        except (urlerror.URLError, socket.timeout, TimeoutError, OSError):
            return False


def require_namespace(value, field="namespace"):
    if not isinstance(value, str) or not NS_RE.fullmatch(value) or len(value) > 63:
        raise InvalidArguments(f"{field} must be a Kubernetes namespace name")
    return value


def require_name(value, field="name"):
    if not isinstance(value, str) or not NAME_RE.fullmatch(value) or len(value) > 253:
        raise InvalidArguments(f"{field} must be a Kubernetes object name")
    return value


def optional_namespace(arguments):
    if "namespace" not in arguments or arguments["namespace"] is None:
        return None
    return require_namespace(arguments["namespace"])


def bounded_int(arguments, key, default, minimum, maximum):
    value = arguments.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidArguments(f"{key} must be an integer")
    if value < minimum or value > maximum:
        raise InvalidArguments(f"{key} must be between {minimum} and {maximum}")
    return value


def optional_bool(arguments, key, default=False):
    value = arguments.get(key, default)
    if not isinstance(value, bool):
        raise InvalidArguments(f"{key} must be a boolean")
    return value


def reject_unknown(arguments, allowed):
    extra = set(arguments) - set(allowed)
    if extra:
        raise InvalidArguments(f"unknown argument(s): {', '.join(sorted(extra))}")


TOOLS = {
    "pods_list": {
        "description": "List pods, optionally in one namespace, with a bounded number of rows.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "namespace": {"type": "string", "description": "Optional namespace."},
                "limit": {
                    "type": "integer",
                    "description": "Maximum pod rows (default 100, max 500).",
                    "minimum": 1,
                    "maximum": 500,
                },
            },
        },
    },
    "pod_get": {
        "description": "Get one pod manifest with status for diagnosis.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string"},
                "namespace": {"type": "string"},
            },
            "required": ["name"],
        },
    },
    "pod_logs": {
        "description": "Read bounded recent logs from one pod.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string"},
                "namespace": {"type": "string"},
                "container": {"type": "string"},
                "previous": {"type": "boolean"},
                "tailLines": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "description": "Number of trailing lines (default 100).",
                },
            },
            "required": ["name"],
        },
    },
    "events_recent": {
        "description": "List recent Kubernetes events within a bounded time window.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "namespace": {"type": "string"},
                "sinceMinutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1440,
                    "description": "Time window in minutes (default 60).",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "description": "Maximum events (default 50).",
                },
                "warningsOnly": {"type": "boolean"},
            },
        },
    },
    "workloads_status": {
        "description": "Summarize Deployments, StatefulSets and DaemonSets readiness.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "namespace": {"type": "string"},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                },
            },
        },
    },
    "services_endpoints": {
        "description": "List Services and Endpoints, optionally in one namespace.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "namespace": {"type": "string"},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                },
            },
        },
    },
    "flux_status": {
        "description": "Show Flux Kustomization, HelmRelease, GitRepository, OCIRepository, HelmRepository and HelmChart readiness and revisions.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "namespace": {"type": "string"},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                },
            },
        },
    },
    "nodes_status": {
        "description": "Show node readiness, capacity and current resource consumption.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string", "description": "Optional node name."},
            },
        },
    },
    "resource_usage": {
        "description": "Show pod CPU and memory consumption from the metrics API.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "namespace": {"type": "string"},
                "allNamespaces": {"type": "boolean"},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                },
            },
        },
    },
}


class Diagnostics:
    def __init__(self, upstream=None):
        self.upstream = upstream or Upstream()

    def pods_list(self, arguments):
        reject_unknown(arguments, ("namespace", "limit"))
        namespace = optional_namespace(arguments)
        limit = bounded_int(arguments, "limit", 100, 1, 500)
        if namespace:
            text = self.upstream.call("pods_list_in_namespace", {"namespace": namespace})
        else:
            text = self.upstream.call("pods_list", {})
        return cap_table(text, limit)

    def pod_get(self, arguments):
        reject_unknown(arguments, ("name", "namespace"))
        name = require_name(arguments.get("name"))
        namespace = optional_namespace(arguments)
        params = {"name": name}
        if namespace:
            params["namespace"] = namespace
        return self.upstream.call("pods_get", params)

    def pod_logs(self, arguments):
        reject_unknown(arguments, ("name", "namespace", "container", "previous", "tailLines"))
        name = require_name(arguments.get("name"))
        namespace = optional_namespace(arguments)
        tail = bounded_int(arguments, "tailLines", 100, 1, 500)
        previous = optional_bool(arguments, "previous")
        params = {"name": name, "tail": tail, "previous": previous}
        if namespace:
            params["namespace"] = namespace
        if "container" in arguments:
            params["container"] = require_name(arguments["container"], "container")
        return self.upstream.call("pods_log", params)

    def events_recent(self, arguments):
        reject_unknown(arguments, ("namespace", "sinceMinutes", "limit", "warningsOnly"))
        namespace = optional_namespace(arguments)
        since = bounded_int(arguments, "sinceMinutes", 60, 1, 1440)
        limit = bounded_int(arguments, "limit", 50, 1, 200)
        warnings = optional_bool(arguments, "warningsOnly")
        params = {}
        if namespace:
            params["namespace"] = namespace
        if warnings:
            params["fieldSelector"] = "type=Warning"
        text = self.upstream.call("events_list", params)
        return filter_events(text, since, limit)

    def workloads_status(self, arguments):
        reject_unknown(arguments, ("namespace", "limit"))
        namespace = optional_namespace(arguments)
        limit = bounded_int(arguments, "limit", 100, 1, 200)
        sections = []
        for kind in ("Deployment", "StatefulSet", "DaemonSet"):
            params = {"apiVersion": "apps/v1", "kind": kind}
            if namespace:
                params["namespace"] = namespace
            text = self.upstream.call("resources_list", params)
            sections.append(f"## {kind}\n{cap_table(text, limit)}")
        return "\n\n".join(sections)

    def services_endpoints(self, arguments):
        reject_unknown(arguments, ("namespace", "limit"))
        namespace = optional_namespace(arguments)
        limit = bounded_int(arguments, "limit", 100, 1, 200)
        sections = []
        for kind in ("Service", "Endpoints"):
            params = {"apiVersion": "v1", "kind": kind}
            if namespace:
                params["namespace"] = namespace
            text = self.upstream.call("resources_list", params)
            sections.append(f"## {kind}\n{cap_table(text, limit)}")
        return "\n\n".join(sections)

    def flux_status(self, arguments):
        reject_unknown(arguments, ("namespace", "limit"))
        namespace = optional_namespace(arguments)
        limit = bounded_int(arguments, "limit", 100, 1, 200)
        resources = (
            ("kustomize.toolkit.fluxcd.io/v1", "Kustomization"),
            ("helm.toolkit.fluxcd.io/v2", "HelmRelease"),
            ("source.toolkit.fluxcd.io/v1", "GitRepository"),
            ("source.toolkit.fluxcd.io/v1", "OCIRepository"),
            ("source.toolkit.fluxcd.io/v1", "HelmRepository"),
            ("source.toolkit.fluxcd.io/v1", "HelmChart"),
        )
        sections = []
        for api_version, kind in resources:
            params = {"apiVersion": api_version, "kind": kind}
            if namespace:
                params["namespace"] = namespace
            text = self.upstream.call("resources_list", params)
            sections.append(f"## {kind}\n{cap_table(text, limit)}")
        return "\n\n".join(sections)

    def nodes_status(self, arguments):
        reject_unknown(arguments, ("name",))
        sections = []
        if "name" in arguments and arguments["name"] is not None:
            name = require_name(arguments["name"])
            sections.append(
                "## Node\n"
                + self.upstream.call("resources_get", {"apiVersion": "v1", "kind": "Node", "name": name})
            )
            sections.append("## Node usage\n" + self.upstream.call("nodes_top", {"name": name}))
        else:
            sections.append(
                "## Nodes\n" + self.upstream.call("resources_list", {"apiVersion": "v1", "kind": "Node"})
            )
            sections.append("## Node usage\n" + self.upstream.call("nodes_top", {}))
        return "\n\n".join(sections)

    def resource_usage(self, arguments):
        reject_unknown(arguments, ("namespace", "allNamespaces", "limit"))
        namespace = optional_namespace(arguments)
        limit = bounded_int(arguments, "limit", 100, 1, 500)
        all_namespaces = optional_bool(arguments, "allNamespaces", namespace is None)
        params = {"all_namespaces": all_namespaces}
        if namespace:
            params["namespace"] = namespace
        text = self.upstream.call("pods_top", params)
        return cap_table(text, limit)

    def call(self, name, arguments):
        handler = getattr(self, name, None)
        if name not in TOOLS or handler is None:
            raise InvalidArguments(f"Unknown tool: {name}")
        return handler(arguments)


class Gateway:
    def __init__(self, tokens, diagnostics=None, limiter=None, semaphore=None, upstream_health=None):
        self.tokens = tokens
        self.diagnostics = diagnostics or Diagnostics()
        self.limiter = limiter or RateLimiter(RATE_LIMIT_PER_MINUTE, RATE_LIMIT_BURST)
        self.semaphore = semaphore or threading.BoundedSemaphore(MAX_CONCURRENCY)
        self.upstream_health = upstream_health or self.diagnostics.upstream.healthy
        self._health_lock = threading.Lock()
        self._health_value = False
        self._health_at = 0.0

    def healthy(self):
        now = time.monotonic()
        with self._health_lock:
            if now - self._health_at >= 5:
                self._health_value = self.upstream_health()
                self._health_at = now
            return self._health_value

    def tool_list(self):
        return [
            {"name": name, "description": spec["description"], "inputSchema": spec["inputSchema"]}
            for name, spec in TOOLS.items()
        ]

    def handle_rpc(self, message):
        method = message.get("method")
        request_id = message.get("id")
        if method == "initialize":
            requested = (message.get("params") or {}).get("protocolVersion")
            protocol = requested if requested in PROTOCOL_VERSIONS else DEFAULT_PROTOCOL
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": protocol,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "homelab-mcp-diagnostics", "version": GATEWAY_VERSION},
                    "instructions": "Read-only, bounded homelab Kubernetes diagnostics.",
                },
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": self.tool_list()}}
        if method == "tools/call":
            params = message.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(name, str):
                raise InvalidArguments("tools/call requires a tool name")
            if not isinstance(arguments, dict):
                raise InvalidArguments("tools/call arguments must be an object")
            if name not in TOOLS:
                raise InvalidArguments(f"Unknown tool: {name}")
            if not self.semaphore.acquire(timeout=1.0):
                raise UpstreamError("busy", "too many concurrent tool calls")
            try:
                text = self.diagnostics.call(name, arguments)
            finally:
                self.semaphore.release()
            text = bound_text(sanitize(text))
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": False},
            }
        raise KeyError(method)


def audit_arguments(arguments):
    safe = {}
    if not isinstance(arguments, dict):
        return safe
    for key, value in arguments.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe[str(key)[:64]] = sanitize(str(value)[:200]) if isinstance(value, str) else value
    return safe


def make_handler(gateway):
    class Handler(BaseHTTPRequestHandler):
        server_version = "homelab-mcp-gateway"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def _send_json(self, status, payload, extra_headers=None):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for key, value in (extra_headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _auth(self):
            header = self.headers.get("Authorization")
            caller = identify(header, gateway.tokens)
            if caller is None:
                log_event(
                    event="auth_failure",
                    remote=self.client_address[0],
                    reason="missing_or_invalid_token",
                )
                self._send_json(
                    401,
                    {"error": "unauthorized"},
                    {"WWW-Authenticate": 'Bearer realm="homelab-mcp-diagnostics"'},
                )
                return None
            return caller

        def _audit_context(self):
            return {
                key: self.headers.get(key, "")[:200]
                for key in UNTRUSTED_AUDIT_HEADERS
                if self.headers.get(key)
            }

        def do_GET(self):
            if self.path != "/healthz":
                self._send_json(404, {"error": "not_found"})
                return
            if gateway.healthy():
                self._send_json(200, {"status": "ok"})
            else:
                self._send_json(503, {"status": "degraded", "reason": "upstream_unavailable"})

        def do_DELETE(self):
            if self.path == "/mcp":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send_json(404, {"error": "not_found"})

        def do_POST(self):
            if self.path != "/mcp":
                self._send_json(404, {"error": "not_found"})
                return
            caller = self._auth()
            if caller is None:
                return
            allowed, retry_after = gateway.limiter.allow(caller)
            if not allowed:
                log_event(
                    event="rate_limited",
                    caller=caller,
                    remote=self.client_address[0],
                    retry_after_s=round(retry_after, 2),
                )
                self._send_json(
                    429,
                    {"error": "rate_limited"},
                    {"Retry-After": str(max(1, int(retry_after + 0.999)))},
                )
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_REQUEST_BYTES:
                self._send_json(413, {"error": "invalid_request_size"})
                return
            raw = self.rfile.read(length)
            try:
                message = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(
                    400,
                    {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
                )
                return
            if isinstance(message, list):
                self._send_json(
                    400,
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32600, "message": "Batch requests are not supported"},
                    },
                )
                return
            if not isinstance(message, dict) or "method" not in message:
                self._send_json(
                    400,
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id") if isinstance(message, dict) else None,
                        "error": {"code": -32600, "message": "Invalid Request"},
                    },
                )
                return
            if "id" not in message:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            request_id = message.get("id")
            method = message.get("method")
            started = time.monotonic()
            audit = {
                "event": "mcp_call",
                "caller": caller,
                "method": method,
                "remote": self.client_address[0],
                "audit": self._audit_context(),
            }
            try:
                response = gateway.handle_rpc(message)
            except InvalidArguments as exc:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": str(exc)},
                }
                audit.update(status="denied", reason=str(exc)[:200])
            except UpstreamError as exc:
                if exc.code == "busy":
                    self._send_json(503, {"error": "busy"}, {"Retry-After": "1"})
                    audit.update(status="busy")
                    log_event(**audit, latency_ms=round((time.monotonic() - started) * 1000, 1))
                    return
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": bound_text(sanitize(f"{exc.code}: {exc.message}")),
                            }
                        ],
                        "isError": True,
                    },
                }
                audit.update(status="upstream_error", upstream_error=exc.code)
            except KeyError:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "Method not found"},
                }
                audit.update(status="method_not_found")
            except Exception as exc:
                log_event(
                    event="internal_error",
                    caller=caller,
                    method=method,
                    error_type=type(exc).__name__,
                )
                self._send_json(
                    500,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32603, "message": "Internal error"},
                    },
                )
                return
            if method == "tools/call":
                params = message.get("params") or {}
                audit["tool"] = str(params.get("name"))[:128]
                audit["arguments"] = audit_arguments(params.get("arguments"))
            body = json.dumps(response).encode("utf-8")
            audit.setdefault("status", "ok")
            audit["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
            audit["response_bytes"] = len(body)
            log_event(**audit)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main():
    tokens = load_tokens(AUTH_TOKENS_FILE)
    gateway = Gateway(tokens)
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(gateway))
    server.daemon_threads = True
    log_event(event="gateway_start", port=port, tools=len(TOOLS), callers=sorted(tokens))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
