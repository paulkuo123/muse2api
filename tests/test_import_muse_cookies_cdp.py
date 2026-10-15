"""Offline tests for tools/import_muse_cookies_cdp.py.

Uses a local fake CDP websocket and a fake muse2api HTTP server.
Does not connect to Chrome, ports 9234/9235/9239, or the real API on 18610.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "import_muse_cookies_cdp.py"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

KEY = "m2a_TESTKEY_9f3c1b7e_DO_NOT_PRINT"
SESS = "SESS_VALUE_a91f33c0_DO_NOT_PRINT"
GW = "GW_VALUE_b82e44d1_DO_NOT_PRINT"
VML = "VML_VALUE_c73d55e2_DO_NOT_PRINT"
DEV = "DEV_VALUE_d64c66f3_DO_NOT_PRINT"
OTHER = "OTHER_DOMAIN_e55b77a4_DO_NOT_PRINT"
TRICK = "TRICK_NOTMUSE_f46a88b5_DO_NOT_PRINT"
EVIL = "EVIL_SUFFIX_g37b99c6_DO_NOT_PRINT"
ENV_SENTINEL = "ENV_SENTINEL_MUSE2API_KEY_DO_NOT_PRINT"
ENV_OTHER = "ENVFILE_OTHER_SECRET_DO_NOT_PRINT"

FRAGMENTS = (
    "m2a_TESTKEY",
    "SESS_VALUE_a91f",
    "GW_VALUE_b82e",
    "VML_VALUE_c73d",
    "DEV_VALUE_d64c",
    "OTHER_DOMAIN_e55b",
    "TRICK_NOTMUSE_f46a",
    "EVIL_SUFFIX_g37b",
    "ENV_SENTINEL_MUSE",
    "ENVFILE_OTHER_SEC",
    "DO_NOT_PRINT",
    "[redacted]",
)
SECRETS = (KEY, SESS, GW, VML, DEV, OTHER, TRICK, EVIL, ENV_SENTINEL, ENV_OTHER) + FRAGMENTS


def _load():
    spec = importlib.util.spec_from_file_location("import_muse_cookies_cdp", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


IMP = _load()


def muse_cookies():
    return [
        {"name": "hatch_sess", "value": SESS, "domain": ".muse.ai", "expires": 1890000000},
        {"name": "hatch_gw", "value": GW, "domain": "muse.ai", "expires": 1890000001.5},
        {"name": "hatch_vml", "value": VML, "domain": "www.muse.ai", "expires": 1890000002},
        {"name": "hatch_native_auth_device", "value": DEV, "domain": ".www.muse.ai", "expires": -1},
        {"name": "sid", "value": OTHER, "domain": ".google.com", "expires": 1890000003},
        {"name": "trick", "value": TRICK, "domain": "notmuse.ai", "expires": 1890000004},
        {"name": "evil", "value": EVIL, "domain": "cdn.muse.ai.evil.com", "expires": 1890000005},
    ]


def _read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def _read_frame(conn: socket.socket):
    header = _read_exact(conn, 2)
    opcode = header[0] & 0x0F
    masked = header[1] & 0x80
    length = header[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", _read_exact(conn, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _read_exact(conn, 8))[0]
    mask = _read_exact(conn, 4) if masked else b""
    payload = _read_exact(conn, length) if length else b""
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def _write_text(conn: socket.socket, text: str) -> None:
    data = text.encode("utf-8")
    header = bytearray([0x81])
    n = len(data)
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header += struct.pack(">H", n)
    else:
        header.append(127)
        header += struct.pack(">Q", n)
    conn.sendall(bytes(header) + data)


def _handshake(conn: socket.socket) -> str:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
    lines = head.split("\r\n")
    path = lines[0].split(" ")[1]
    key = ""
    for line in lines[1:]:
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")
    conn.sendall(
        (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        ).encode("ascii")
    )
    return path


class CDPSocket(threading.Thread):
    def __init__(self, cookies, browser_fail=False):
        super().__init__(daemon=True)
        self.cookies = cookies
        self.browser_fail = browser_fail
        self.calls = []
        self._lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn: socket.socket):
        conn.settimeout(5)
        try:
            path = _handshake(conn)
            while True:
                opcode, payload = _read_frame(conn)
                if opcode == 0x8:
                    break
                if opcode == 0x9:
                    _write_text(conn, "")
                    continue
                if opcode != 0x1:
                    continue
                msg = json.loads(payload.decode("utf-8"))
                method = msg.get("method")
                params = msg.get("params") or {}
                with self._lock:
                    self.calls.append({"path": path, "method": method, "params": params})
                if method == "Network.getCookies" and not (
                    self.browser_fail and "/devtools/browser/" in path
                ):
                    reply = {"id": msg.get("id"), "result": {"cookies": self.cookies}}
                else:
                    reply = {
                        "id": msg.get("id"),
                        "error": {"code": -32601, "message": "unavailable"},
                    }
                _write_text(conn, json.dumps(reply))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


class _Quiet(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _json(self, code: int, obj) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class CDPHttp(_Quiet):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        self.server.hits.append(("GET", path))
        if path == "/json/version":
            self._json(200, {"webSocketDebuggerUrl": self.server.ws_url})
        elif path == "/json/list":
            self._json(200, self.server.targets)
        else:
            self._json(404, {"error": "not-found"})

    def do_PUT(self):
        path = self.path.split("?", 1)[0]
        self.server.hits.append(("PUT", path))
        self._json(500, {"error": "rejected"})


class APIHttp(_Quiet):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        path = self.path.split("?", 1)[0]
        self.server.records.append({
            "path": path,
            "auth": self.headers.get("Authorization", ""),
            "content_type": self.headers.get("Content-Type", ""),
            "body": raw,
        })
        mode = self.server.mode
        if path == "/admin/accounts" and mode == "401":
            self._json(401, {"detail": self.server.echo})
            return
        if path == "/admin/accounts":
            echo = self.server.echo if mode == "echo" else ""
            self._json(200, {
                "added": [{"id": "acc-test-1", "label": "x", "cookie_count": 4}],
                "count": 1,
                "echo": echo,
            })
            return
        if path == "/admin/accounts/acc-test-1/test":
            self._json(200, {"ok": mode != "test-fail", "message": "checked"})
            return
        self._json(404, {"error": "not-found"})


def _serve(handler, setup):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    setup(server)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


class CDPStack:
    def __init__(self, cookies=None, browser_fail=False, with_page=True):
        self.ws = CDPSocket(muse_cookies() if cookies is None else cookies, browser_fail=browser_fail)
        self.ws.start()
        page = f"ws://127.0.0.1:{self.ws.port}/devtools/page/existing"
        targets = []
        if with_page:
            targets.append({
                "id": "page-1",
                "type": "page",
                "url": "https://muse.ai/",
                "webSocketDebuggerUrl": page,
            })

        def setup(server):
            server.hits = []
            server.ws_url = f"ws://127.0.0.1:{self.ws.port}/devtools/browser/test"
            server.targets = targets

        self.http, self.http_thread = _serve(CDPHttp, setup)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.http.server_address[1]}"

    def stop(self):
        self.http.shutdown()
        self.http.server_close()
        self.ws.stop()


class APIStack:
    def __init__(self, mode="ok", echo=""):
        def setup(server):
            server.records = []
            server.mode = mode
            server.echo = echo

        self.http, self.thread = _serve(APIHttp, setup)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.http.server_address[1]}"

    def stop(self):
        self.http.shutdown()
        self.http.server_close()


def write_env(directory: str, key: str = KEY) -> str:
    path = os.path.join(directory, "env")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, (
            f"# comment\nexport MUSE2API_KEY=\"{key}\"\nOTHER={ENV_OTHER}\n"
        ).encode())
    finally:
        os.close(fd)
    return path


class _LoopbackSockets:
    """Fail the test if this process connects anywhere except loopback."""

    def __enter__(self):
        import socket as socket_mod

        self._socket_mod = socket_mod
        self._real = socket_mod.socket
        self.attempts = []
        real = self._real
        attempts = self.attempts

        class GuardSocket(real):
            def connect(self, address):
                host = address[0] if isinstance(address, tuple) else str(address)
                attempts.append(host)
                if host not in {"127.0.0.1", "::1", "localhost"}:
                    raise AssertionError(f"non-loopback connect {host}")
                return super().connect(address)

        socket_mod.socket = GuardSocket
        return self

    def __exit__(self, exc_type, exc, tb):
        self._socket_mod.socket = self._real
        return False


def run_cli(args: list[str], env_file: str, tmpdir: str) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(SCRIPT), "--env-file", env_file, "--timeout", "5", *args]
    text = " ".join(cmd)
    banned = (
        "127.0.0.1:9234",
        "127.0.0.1:9235",
        "127.0.0.1:9239",
        "127.0.0.1:18610",
        "localhost:9234",
        "localhost:9235",
        "localhost:9239",
        "localhost:18610",
        "[::1]:9234",
        "[::1]:9235",
        "[::1]:9239",
        "[::1]:18610",
    )
    if any(item in text for item in banned):
        raise AssertionError("test tried to use a real CDP port or the real API")
    if "--endpoint" not in args and "--ports" not in args:
        raise AssertionError("test omitted a fake CDP endpoint and would use port 9234")
    env = os.environ.copy()
    env.pop("MUSE2API_KEY", None)
    env["MUSE2API_KEY"] = ENV_SENTINEL
    env["TMPDIR"] = tmpdir
    return subprocess.run(
        cmd, cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=20,
    )


def url_host(url: str) -> str:
    return urlparse(url).hostname or ""


def assert_clean(test: unittest.TestCase, proc: subprocess.CompletedProcess) -> None:
    blob = proc.stdout + proc.stderr
    for secret in SECRETS:
        test.assertNotIn(secret, blob)


class ImportTests(unittest.TestCase):
    def test_defaults_do_not_connect(self):
        self.assertEqual(IMP.DEFAULT_ENDPOINT, "http://127.0.0.1:9234")
        self.assertFalse(hasattr(IMP, "DEFAULT_PORTS"))
        args = IMP.parse_args([])
        self.assertEqual(args.endpoint, "http://127.0.0.1:9234")
        self.assertEqual(args.ports, "")
        self.assertNotIn("9235", args.endpoint)
        self.assertNotIn("9235", args.ports)
        self.assertEqual(args.env_file, "/workspace/muse2api/.env")
        self.assertEqual(args.base, "http://localhost:18610")
        self.assertFalse(args.dry_run)

    def test_filter_keeps_only_muse_domains(self):
        cookies, expires = IMP.filter_muse_cookies(muse_cookies())
        self.assertEqual(set(cookies), {
            "hatch_sess", "hatch_gw", "hatch_vml", "hatch_native_auth_device",
        })
        self.assertEqual(cookies["hatch_sess"], SESS)
        self.assertEqual(expires["hatch_sess"], 1890000000)
        self.assertEqual(expires["hatch_gw"], 1890000001)
        self.assertNotIn("hatch_native_auth_device", expires)
        self.assertNotIn("sid", cookies)
        self.assertNotIn("trick", cookies)
        self.assertNotIn("evil", cookies)

    def test_load_key_quotes_without_printing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_env(tmp)
            self.assertEqual(IMP.load_api_key(path), KEY)
            with self.assertRaises(IMP.ImportFailure):
                IMP.load_api_key(os.path.join(tmp, "missing"))

    def test_loopback_allowlist_is_exact(self):
        allowed = (
            "http://localhost:18610",
            "http://127.0.0.1:9",
            "http://[::1]:9",
            "https://localhost/admin/accounts",
            "ws://127.0.0.1:9/devtools/browser/x",
            "wss://[::1]:9/devtools/browser/x",
        )
        refused = (
            "http://example.com",
            "http://8.8.8.8:80",
            "http://[2001:db8::1]:9",
            "ws://203.0.113.10:9/devtools/browser/x",
            "http://127.0.0.2:9",
            "http://0.0.0.0:9",
            "http://localhost.evil.com",
            "http://127.0.0.1.nip.io",
            "file:///etc/passwd",
            "file://localhost/etc/passwd",
        )
        for url in allowed:
            IMP.require_loopback(url, "probe")
        for url in refused:
            with self.assertRaises(IMP.ImportFailure):
                IMP.require_loopback(url, "probe")

    def test_refuses_non_loopback_base_without_requests(self):
        cdp = CDPStack()
        api = APIStack()
        try:
            with _LoopbackSockets() as guard:
                with self.assertRaises(IMP.ImportFailure) as ctx:
                    IMP.run(IMP.parse_args([
                        "--endpoint", cdp.base,
                        "--base", "http://203.0.113.10:80",
                        "--label", "nope",
                        "--env-file", os.path.join(tempfile.gettempdir(), "missing-env"),
                    ]))
            self.assertIn("host must be localhost, 127.0.0.1, or ::1", str(ctx.exception))
            self.assertIn("203.0.113.10", str(ctx.exception))
            self.assertEqual(guard.attempts, [])
            self.assertEqual(cdp.http.hits, [])
            self.assertEqual(cdp.ws.calls, [])
            self.assertEqual(api.http.records, [])
            with tempfile.TemporaryDirectory() as tmp:
                proc = run_cli(
                    ["--endpoint", cdp.base, "--base", "http://203.0.113.10:80", "--label", "nope"],
                    write_env(tmp), tmp,
                )
            assert_clean(self, proc)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("host must be localhost, 127.0.0.1, or ::1", proc.stderr)
            self.assertIn("203.0.113.10", proc.stderr)
            self.assertNotIn("cookies:", proc.stdout)
            self.assertNotIn("import:", proc.stdout)
            self.assertEqual(cdp.http.hits, [])
            self.assertEqual(cdp.ws.calls, [])
            self.assertEqual(api.http.records, [])
        finally:
            api.stop()
            cdp.stop()

    def test_refuses_non_loopback_endpoint_without_requests(self):
        api = APIStack()
        endpoints = (
            "http://203.0.113.10:9",
            "ws://203.0.113.11:9/devtools/browser/x",
        )
        try:
            for endpoint in endpoints:
                with self.subTest(endpoint=endpoint):
                    with _LoopbackSockets() as guard:
                        with self.assertRaises(IMP.ImportFailure) as ctx:
                            IMP.run(IMP.parse_args([
                                "--endpoint", endpoint,
                                "--base", api.base,
                                "--label", "nope",
                                "--env-file", os.path.join(tempfile.gettempdir(), "missing-env"),
                            ]))
                    self.assertIn("host must be localhost, 127.0.0.1, or ::1", str(ctx.exception))
                    self.assertIn(url_host(endpoint), str(ctx.exception))
                    self.assertEqual(guard.attempts, [])
                    self.assertEqual(api.http.records, [])
                    with tempfile.TemporaryDirectory() as tmp:
                        proc = run_cli(
                            ["--endpoint", endpoint, "--base", api.base, "--label", "nope"],
                            write_env(tmp), tmp,
                        )
                    assert_clean(self, proc)
                    self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                    self.assertIn("host must be localhost, 127.0.0.1, or ::1", proc.stderr)
                    self.assertIn(url_host(endpoint), proc.stderr)
                    self.assertNotIn("cookies:", proc.stdout)
                    self.assertNotIn("import:", proc.stdout)
                    self.assertEqual(api.http.records, [])
        finally:
            api.stop()

    def test_refuses_remote_websocket_from_loopback_endpoint(self):
        def setup(server):
            server.hits = []
            server.ws_url = "ws://203.0.113.20:9/devtools/browser/remote"
            server.targets = [{
                "type": "page",
                "url": "https://muse.ai/",
                "webSocketDebuggerUrl": "ws://203.0.113.21:9/devtools/page/remote",
            }]

        http, _thread = _serve(CDPHttp, setup)
        api = APIStack()
        try:
            base = f"http://127.0.0.1:{http.server_address[1]}"
            with _LoopbackSockets() as guard:
                with self.assertRaises(IMP.ImportFailure) as ctx:
                    IMP.resolve_cdp(base, [], 2)
            self.assertIn("CDP websocket", str(ctx.exception))
            self.assertIn("203.0.113.20", str(ctx.exception))
            self.assertTrue(guard.attempts)
            self.assertTrue(all(host == "127.0.0.1" for host in guard.attempts))
            self.assertEqual([path for _, path in http.hits], ["/json/version"])
            http.hits.clear()
            with tempfile.TemporaryDirectory() as tmp:
                proc = run_cli(
                    ["--endpoint", base, "--base", api.base, "--label", "nope"],
                    write_env(tmp), tmp,
                )
            assert_clean(self, proc)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("CDP websocket", proc.stderr)
            self.assertIn("203.0.113.20", proc.stderr)
            self.assertNotIn("cookies:", proc.stdout)
            self.assertNotIn("import:", proc.stdout)
            self.assertEqual([path for _, path in http.hits], ["/json/version"])
            self.assertEqual(api.http.records, [])
        finally:
            api.stop()
            http.shutdown()
            http.server_close()

    def test_refuses_remote_page_websocket_from_json_list(self):
        cdp = CDPStack(browser_fail=True)
        api = APIStack()
        try:
            cdp.http.targets = [{
                "id": "page-1",
                "type": "page",
                "url": "https://muse.ai/",
                "webSocketDebuggerUrl": "ws://203.0.113.21:9/devtools/page/remote",
            }]
            with tempfile.TemporaryDirectory() as tmp:
                proc = run_cli(
                    ["--endpoint", cdp.base, "--base", api.base],
                    write_env(tmp), tmp,
                )
            assert_clean(self, proc)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("CDP websocket", proc.stderr)
            self.assertIn("203.0.113.21", proc.stderr)
            self.assertNotIn("import:", proc.stdout)
            paths = [path for _, path in cdp.http.hits]
            self.assertIn("/json/version", paths)
            self.assertIn("/json/list", paths)
            self.assertEqual(api.http.records, [])
            self.assertEqual([call["method"] for call in cdp.ws.calls], ["Network.getCookies"])
            self.assertTrue(all("/devtools/page/" not in call["path"] for call in cdp.ws.calls))
        finally:
            api.stop()
            cdp.stop()

    def test_discover_uses_first_live_port(self):
        def setup_first(server):
            server.hits = []
            server.ws_url = "ws://127.0.0.1:9/devtools/browser/first"
            server.targets = []

        def setup_second(server):
            server.hits = []
            server.ws_url = "ws://127.0.0.1:9/devtools/browser/second"
            server.targets = []

        first, _first_thread = _serve(CDPHttp, setup_first)
        second, _second_thread = _serve(CDPHttp, setup_second)
        try:
            found = IMP.discover_cdp([
                first.server_address[1],
                second.server_address[1],
            ], timeout=2)
            self.assertEqual(found.http_base, f"http://127.0.0.1:{first.server_address[1]}")
            self.assertIn("/devtools/browser/first", found.ws_url)
            self.assertEqual(second.hits, [])
            self.assertTrue(any(path == "/json/version" for _, path in first.hits))
        finally:
            first.shutdown()
            second.shutdown()
            first.server_close()
            second.server_close()

    def test_import_posts_popup_payload_and_verifies(self):
        cdp = CDPStack()
        api = APIStack()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                env_file = write_env(tmp)
                proc = run_cli(
                    ["--endpoint", cdp.base, "--base", api.base, "--label", "cdp-import"],
                    env_file, tmp,
                )
                assert_clean(self, proc)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn("cookies: 4", proc.stdout)
                self.assertIn("import: HTTP 200 success", proc.stdout)
                self.assertIn("test: HTTP 200 success", proc.stdout)
                self.assertEqual(os.listdir(tmp), ["env"])
            self.assertEqual(len(api.http.records), 2)
            imported, tested = api.http.records
            self.assertEqual(imported["path"], "/admin/accounts")
            self.assertEqual(imported["auth"], "Bearer " + KEY)
            self.assertIn("application/json", imported["content_type"])
            body = json.loads(imported["body"])
            self.assertEqual(set(body), {"label", "cookies", "expires"})
            self.assertEqual(body["label"], "cdp-import")
            self.assertEqual(body["cookies"], {
                "hatch_sess": SESS,
                "hatch_gw": GW,
                "hatch_vml": VML,
                "hatch_native_auth_device": DEV,
            })
            self.assertEqual(body["expires"]["hatch_sess"], 1890000000)
            self.assertEqual(body["expires"]["hatch_gw"], 1890000001)
            self.assertEqual(body["expires"]["hatch_vml"], 1890000002)
            self.assertNotIn("hatch_native_auth_device", body["expires"])
            self.assertEqual(tested["path"], "/admin/accounts/acc-test-1/test")
            self.assertEqual(tested["auth"], "Bearer " + KEY)
            methods = [call["method"] for call in cdp.ws.calls]
            self.assertEqual(methods, ["Network.getCookies"])
            self.assertEqual(
                cdp.ws.calls[0]["params"]["urls"],
                ["https://muse.ai/", "https://www.muse.ai/"],
            )
            paths = [path for _, path in cdp.http.hits]
            self.assertIn("/json/version", paths)
            self.assertNotIn("/json/list", paths)
            self.assertFalse(any(path.startswith("/json/new") or path.startswith("/json/close") for path in paths))
        finally:
            api.stop()
            cdp.stop()

    def test_dry_run_prints_count_without_posting(self):
        cdp = CDPStack()
        api = APIStack()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = run_cli(
                    ["--endpoint", cdp.base, "--base", api.base, "--dry-run"],
                    os.path.join(tmp, "absent-env"), tmp,
                )
                assert_clean(self, proc)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn("cookies: 4", proc.stdout)
                self.assertIn("dry-run: skipped", proc.stdout)
                self.assertNotIn("import:", proc.stdout)
                self.assertEqual(api.http.records, [])
                self.assertEqual(os.listdir(tmp), [])
        finally:
            api.stop()
            cdp.stop()

    def test_stdout_has_no_secrets_when_api_echoes_them(self):
        echo = KEY + " " + SESS + " " + GW + " " + VML + " " + DEV
        cdp = CDPStack()
        api = APIStack(mode="401", echo=echo)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                env_file = write_env(tmp)
                proc = run_cli(
                    ["--endpoint", cdp.base, "--base", api.base, "--label", "cdp-import"],
                    env_file, tmp,
                )
                assert_clean(self, proc)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("import: HTTP 401 fail", proc.stdout)
                self.assertNotIn("test:", proc.stdout)
                self.assertEqual(len(api.http.records), 1)
                self.assertIn(SESS, api.http.records[0]["body"].decode())
        finally:
            api.stop()
            cdp.stop()

    def test_success_body_echo_is_not_printed(self):
        cdp = CDPStack()
        api = APIStack(mode="echo", echo=SESS + KEY)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = run_cli(
                    ["--endpoint", cdp.base, "--base", api.base],
                    write_env(tmp), tmp,
                )
                assert_clean(self, proc)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn("test: HTTP 200 success", proc.stdout)
                self.assertEqual(len(api.http.records), 2)
        finally:
            api.stop()
            cdp.stop()

    def test_missing_essential_does_not_post(self):
        cookies = [c for c in muse_cookies() if c["name"] != "hatch_native_auth_device"]
        cdp = CDPStack(cookies=cookies)
        api = APIStack()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = run_cli(
                    ["--endpoint", cdp.base, "--base", api.base],
                    write_env(tmp), tmp,
                )
                assert_clean(self, proc)
                self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
                self.assertIn("cookies: 3", proc.stdout)
                self.assertIn("missing: hatch_native_auth_device", proc.stdout)
                self.assertIn("import: skipped", proc.stdout)
                self.assertEqual(api.http.records, [])
        finally:
            api.stop()
            cdp.stop()

    def test_failed_account_test(self):
        cdp = CDPStack()
        api = APIStack(mode="test-fail")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = run_cli(
                    ["--endpoint", cdp.base, "--base", api.base],
                    write_env(tmp), tmp,
                )
                assert_clean(self, proc)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn("import: HTTP 200 success", proc.stdout)
                self.assertIn("test: HTTP 200 fail", proc.stdout)
        finally:
            api.stop()
            cdp.stop()

    def test_readonly_page_attach_when_browser_target_rejects(self):
        cdp = CDPStack(browser_fail=True)
        api = APIStack()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = run_cli(
                    ["--endpoint", cdp.base, "--base", api.base],
                    write_env(tmp), tmp,
                )
                assert_clean(self, proc)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn("cookies: 4", proc.stdout)
            paths = [path for _, path in cdp.http.hits]
            self.assertIn("/json/version", paths)
            self.assertIn("/json/list", paths)
            self.assertFalse(any("new" in path or "close" in path for path in paths))
            methods = [(call["path"], call["method"]) for call in cdp.ws.calls]
            self.assertEqual(methods, [
                ("/devtools/browser/test", "Network.getCookies"),
                ("/devtools/page/existing", "Network.getCookies"),
            ])
        finally:
            api.stop()
            cdp.stop()

    def test_direct_websocket_does_not_open_targets(self):
        cdp = CDPStack()
        api = APIStack()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = run_cli(
                    ["--endpoint", cdp.http.ws_url, "--base", api.base, "--dry-run"],
                    write_env(tmp), tmp,
                )
                assert_clean(self, proc)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn("cookies: 4", proc.stdout)
                self.assertEqual(cdp.http.hits, [])
                self.assertEqual(api.http.records, [])
                self.assertEqual([c["method"] for c in cdp.ws.calls], ["Network.getCookies"])
        finally:
            api.stop()
            cdp.stop()

    def test_cli_port_order_stops_at_first_success(self):
        first = CDPStack(cookies=[
            {"name": "hatch_sess", "value": SESS, "domain": "muse.ai", "expires": 1890000000},
        ])
        second = CDPStack()
        api = APIStack()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = run_cli(
                    [
                        "--endpoint", "",
                        "--ports",
                        f"{first.http.server_address[1]},{second.http.server_address[1]}",
                        "--base", api.base,
                        "--dry-run",
                    ],
                    write_env(tmp), tmp,
                )
                assert_clean(self, proc)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn("cookies: 1", proc.stdout)
                self.assertEqual(second.http.hits, [])
                self.assertEqual(api.http.records, [])
        finally:
            api.stop()
            second.stop()
            first.stop()


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(("PASS" if result.wasSuccessful() else "FAIL"), result.testsRun, "tests")
    sys.exit(0 if result.wasSuccessful() else 1)
