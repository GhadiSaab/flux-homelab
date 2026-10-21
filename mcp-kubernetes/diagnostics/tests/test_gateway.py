import json
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib import error as urlerror
from urllib import request as urlrequest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gateway  # noqa: E402

TOKEN = "test-token-value-0123456789abcdef"
PROHIBITED = (
    "configuration_view",
    "resources_get",
    "resources_list",
    "nodes_log",
    "nodes_stats_summary",
    "namespaces_list",
    "projects_list",
    "pods_delete",
    "apply",
    "exec",
)


class FakeUpstream:
    def __init__(self, responses=None, failures=None, healthy=True):
        self.calls = []
        self.responses = responses or {}
        self.failures = failures or {}
        self.is_healthy = healthy

    def healthy(self):
        return self.is_healthy

    def call(self, tool, arguments, timeout=None):
        self.calls.append((tool, arguments))
        if tool in self.failures:
            raise self.failures[tool]
        return self.responses.get(tool, f"{tool}-ok")


def diagnostics(responses=None, failures=None, healthy=True):
    return gateway.Diagnostics(FakeUpstream(responses, failures, healthy))


class TokenTests(unittest.TestCase):
    def test_load_tokens_and_identify(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write(f"# comment\npaperclip-agent={TOKEN}\nhost-sre={'b' * 32}\n")
            path = handle.name
        try:
            tokens = gateway.load_tokens(path)
        finally:
            os.unlink(path)
        self.assertEqual(sorted(tokens), ["host-sre", "paperclip-agent"])
        self.assertEqual(
            gateway.identify(f"Bearer {TOKEN}", tokens), "paperclip-agent"
        )
        self.assertIsNone(gateway.identify("Bearer wrong-token-value-0123456789", tokens))
        self.assertIsNone(gateway.identify(None, tokens))
        self.assertIsNone(gateway.identify(f"Basic {TOKEN}", tokens))

    def test_load_tokens_rejects_bad_entries(self):
        import tempfile

        for body in ("no-separator\n", "BAD LABEL=abcdefghijklmnopqrstuvwx\n", "a=short\n"):
            with tempfile.NamedTemporaryFile("w", delete=False) as handle:
                handle.write(body)
                path = handle.name
            try:
                with self.assertRaises(ValueError):
                    gateway.load_tokens(path)
            finally:
                os.unlink(path)


class SanitizerTests(unittest.TestCase):
    def test_redacts_secret_like_values(self):
        text = (
            "password: hunter2\n"
            "api_key=abc123\n"
            "Authorization: Bearer abcdefghijklmnop\n"
            "url https://user:pass@example.test/x\n"
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"
        )
        cleaned = gateway.sanitize(text)
        for leaked in ("hunter2", "abc123", "abcdefghijklmnop", ":pass@", "MIIE"):
            self.assertNotIn(leaked, cleaned)

    def test_leaves_ordinary_text(self):
        text = "app.kubernetes.io/name=kubernetes-mcp-server status: Running"
        self.assertEqual(gateway.sanitize(text), text)

    def test_bound_text(self):
        text = gateway.bound_text("a" * 500, limit=100)
        self.assertLess(len(text), 200)
        self.assertIn("truncated at 100 bytes", text)


class EventTests(unittest.TestCase):
    FIXTURE = """# The following events (YAML format) were found:
- InvolvedObject:
    Kind: Pod
    Name: old-pod
  Timestamp: 2026-10-21 08:00:00 +0000 UTC
  Type: Warning
- InvolvedObject:
    Kind: Pod
    Name: new-pod
  Timestamp: 2026-10-21 10:05:00 +0000 UTC
  Type: Warning
- InvolvedObject:
    Kind: Pod
    Name: newest-pod
  Timestamp: 2026-10-21T10:09:00Z
  Type: Normal
"""

    def test_filters_window_and_orders_newest_first(self):
        now = gateway.parse_timestamp("2026-10-21 10:10:00 +0000 UTC")
        text = gateway.filter_events(self.FIXTURE, 30, 10, now=now)
        self.assertNotIn("old-pod", text)
        self.assertIn("newest-pod", text)
        self.assertLess(text.index("newest-pod"), text.index("new-pod"))
        self.assertIn("returned=2", text)

    def test_limit_applies(self):
        now = gateway.parse_timestamp("2026-10-21 10:10:00 +0000 UTC")
        text = gateway.filter_events(self.FIXTURE, 30, 1, now=now)
        self.assertEqual(text.count("- InvolvedObject:"), 1)
        self.assertIn("newest-pod", text)
        self.assertNotIn("new-pod", text)

    def test_unparseable_events_are_bounded(self):
        text = gateway.filter_events("not events\n" * 10, 30, 3)
        self.assertIn("truncated", text)


class RateLimiterTests(unittest.TestCase):
    def test_burst_then_refill(self):
        now = [100.0]
        limiter = gateway.RateLimiter(60, 2, clock=lambda: now[0])
        self.assertTrue(limiter.allow("a")[0])
        self.assertTrue(limiter.allow("a")[0])
        allowed, retry = limiter.allow("a")
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)
        now[0] += 1.0
        self.assertTrue(limiter.allow("a")[0])
        self.assertTrue(limiter.allow("b")[0])


class ToolTests(unittest.TestCase):
    def test_pods_list_uses_namespace_and_caps_rows(self):
        upstream = FakeUpstream(
            responses={"pods_list_in_namespace": "HEADER\n" + "\n".join(f"row{i}" for i in range(20))}
        )
        diag = gateway.Diagnostics(upstream)
        text = diag.pods_list({"namespace": "flux-system", "limit": 5})
        self.assertEqual(upstream.calls[0], ("pods_list_in_namespace", {"namespace": "flux-system"}))
        self.assertIn("row4", text)
        self.assertNotIn("row5", text)
        self.assertIn("showing 5 of 20 rows", text)

    def test_namespace_validation(self):
        diag = diagnostics()
        for bad in ("../etc", "UPPER", "a" * 64, "", 7):
            with self.assertRaises(gateway.InvalidArguments):
                diag.pods_list({"namespace": bad})

    def test_rejects_unknown_arguments_and_tools(self):
        diag = diagnostics()
        with self.assertRaises(gateway.InvalidArguments):
            diag.pods_list({"name": "x"})
        with self.assertRaises(gateway.InvalidArguments):
            diag.call("configuration_view", {})
        with self.assertRaises(gateway.InvalidArguments):
            diag.call("resources_list", {"apiVersion": "v1", "kind": "Secret"})

    def test_pod_logs_bounds_and_maps_arguments(self):
        upstream = FakeUpstream(responses={"pods_log": "log-line\n"})
        diag = gateway.Diagnostics(upstream)
        diag.pod_logs(
            {"name": "pod-a", "namespace": "default", "tailLines": 20, "previous": True}
        )
        self.assertEqual(
            upstream.calls[0],
            (
                "pods_log",
                {"name": "pod-a", "tail": 20, "previous": True, "namespace": "default"},
            ),
        )
        with self.assertRaises(gateway.InvalidArguments):
            diag.pod_logs({"name": "pod-a", "tailLines": 9999})

    def test_events_recent_maps_warnings_and_window(self):
        upstream = FakeUpstream(responses={"events_list": EventTests.FIXTURE})
        diag = gateway.Diagnostics(upstream)
        text = diag.events_recent({"warningsOnly": True, "sinceMinutes": 30})
        self.assertEqual(
            upstream.calls[0],
            ("events_list", {"fieldSelector": "type=Warning"}),
        )
        self.assertIn("new-pod", text)
        self.assertNotIn("old-pod", text)

    def test_flux_status_uses_allowlisted_kinds(self):
        upstream = FakeUpstream()
        diag = gateway.Diagnostics(upstream)
        diag.flux_status({"limit": 10})
        kinds = [args["kind"] for _, args in upstream.calls]
        self.assertEqual(
            kinds,
            [
                "Kustomization",
                "HelmRelease",
                "GitRepository",
                "OCIRepository",
                "HelmRepository",
                "HelmChart",
            ],
        )

    def test_upstream_failure_propagates_with_code(self):
        failure = gateway.UpstreamError("upstream_timeout", "timed out")
        diag = diagnostics(failures={"pods_list": failure})
        with self.assertRaises(gateway.UpstreamError) as caught:
            diag.pods_list({})
        self.assertEqual(caught.exception.code, "upstream_timeout")


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = FakeUpstream(
            responses={"pods_list_in_namespace": "NAMESPACE NAME\nns pod-a\n"}
        )
        cls.gateway = gateway.Gateway(
            {"paperclip-agent": TOKEN},
            diagnostics=gateway.Diagnostics(cls.upstream),
            limiter=gateway.RateLimiter(600, 100),
        )
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.make_handler(cls.gateway))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def rpc(self, payload, token=TOKEN):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urlrequest.Request(
            self.url + "/mcp", data=json.dumps(payload).encode(), headers=headers, method="POST"
        )
        try:
            with urlrequest.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urlerror.HTTPError as exc:
            body = exc.read()
            return exc.code, json.loads(body) if body else {}

    def test_missing_and_invalid_auth_are_denied(self):
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        self.assertEqual(self.rpc(payload, token=None)[0], 401)
        self.assertEqual(self.rpc(payload, token="invalid-token-value-012345")[0], 401)

    def test_initialize_and_tool_discovery(self):
        status, body = self.rpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["serverInfo"]["name"], "homelab-mcp-diagnostics")
        status, body = self.rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {tool["name"] for tool in body["result"]["tools"]}
        self.assertIn("pods_list", names)
        self.assertIn("flux_status", names)
        for name in PROHIBITED:
            self.assertNotIn(name, names)

    def test_tool_call_and_prohibited_denial(self):
        status, body = self.rpc(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "pods_list", "arguments": {"namespace": "mcp-kubernetes"}},
            }
        )
        self.assertEqual(status, 200)
        self.assertIn("pod-a", body["result"]["content"][0]["text"])
        for name in PROHIBITED:
            status, body = self.rpc(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": {}},
                }
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["error"]["code"], -32602)
            self.assertIn("Unknown tool", body["error"]["message"])

    def test_invalid_arguments_are_visible(self):
        status, body = self.rpc(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "pods_list", "arguments": {"namespace": "../bad"}},
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["error"]["code"], -32602)

    def test_upstream_error_is_visible_tool_error(self):
        failing = FakeUpstream(failures={"pods_list": gateway.UpstreamError("upstream_timeout", "timed out")})
        local = gateway.Gateway(
            {"paperclip-agent": TOKEN},
            diagnostics=gateway.Diagnostics(failing),
            limiter=gateway.RateLimiter(600, 100),
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.make_handler(local))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            request = urlrequest.Request(
                f"http://127.0.0.1:{port}/mcp",
                data=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "tools/call",
                        "params": {"name": "pods_list", "arguments": {}},
                    }
                ).encode(),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"},
                method="POST",
            )
            with urlrequest.urlopen(request, timeout=5) as response:
                body = json.loads(response.read())
            self.assertTrue(body["result"]["isError"])
            self.assertIn("upstream_timeout", body["result"]["content"][0]["text"])
        finally:
            server.shutdown()
            server.server_close()

    def test_health_and_rate_limit(self):
        with urlrequest.urlopen(self.url + "/healthz", timeout=5) as response:
            self.assertEqual(response.status, 200)
        limited = gateway.Gateway(
            {"paperclip-agent": TOKEN},
            diagnostics=diag_with_health(True),
            limiter=gateway.RateLimiter(1, 1),
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.make_handler(limited))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            headers = {"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"}
            body = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}).encode()
            first = urlrequest.urlopen(
                urlrequest.Request(f"http://127.0.0.1:{port}/mcp", data=body, headers=headers), timeout=5
            )
            first.read()
            with self.assertRaises(urlerror.HTTPError) as caught:
                urlrequest.urlopen(
                    urlrequest.Request(f"http://127.0.0.1:{port}/mcp", data=body, headers=headers), timeout=5
                )
            self.assertEqual(caught.exception.code, 429)
        finally:
            server.shutdown()
            server.server_close()

    def test_response_is_bounded(self):
        huge = FakeUpstream(responses={"pods_list_in_namespace": "x" * (gateway.MAX_RESPONSE_BYTES + 500)})
        diag = gateway.Diagnostics(huge)
        text = gateway.bound_text(gateway.sanitize(diag.pods_list({"namespace": "default"})))
        self.assertIn("truncated at", text)
        self.assertLessEqual(len(text.encode()), gateway.MAX_RESPONSE_BYTES + 200)


def diag_with_health(value):
    fake = FakeUpstream(healthy=value)
    return gateway.Diagnostics(fake)


if __name__ == "__main__":
    unittest.main()
