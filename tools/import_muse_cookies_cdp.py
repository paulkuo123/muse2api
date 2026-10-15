#!/usr/bin/env python3
"""Read muse.ai cookies from an already-open Chrome and import them into muse2api.

The browser is attach-only: this process never closes, navigates, or modifies
tabs, and it does not open a new tab. Output is limited to counts, success or
failure, and HTTP status. The API key and cookie values are never printed.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import tempfile
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cdp import CDP, http_json  # noqa: E402

DEFAULT_ENV_FILE = "/workspace/muse2api/.env"
DEFAULT_BASE = "http://localhost:18610"
DEFAULT_PORTS = (9235, 9239)
MUSE_COOKIE_URLS = (
    "https://muse.ai/",
    "https://www.muse.ai/",
)
ESSENTIAL = (
    "hatch_sess",
    "hatch_gw",
    "hatch_vml",
    "hatch_native_auth_device",
)
_SECRET_MIN = 8


class ImportFailure(RuntimeError):
    """Failure whose message is already safe to print."""


@dataclass(frozen=True)
class CdpEndpoint:
    ws_url: str
    http_base: str


class Redactor:
    """Drops registered secret strings from anything that reaches the terminal."""

    def __init__(self) -> None:
        self._secrets: list[str] = []

    def secret(self, value: object) -> None:
        if value is None:
            return
        text = str(value)
        if len(text) < _SECRET_MIN or text in self._secrets:
            return
        self._secrets.append(text)

    def scrub(self, text: str) -> str:
        out = str(text)
        for secret in sorted(self._secrets, key=len, reverse=True):
            if secret in out:
                out = out.replace(secret, "[redacted]")
        return out

    def emit(self, text: str, stream=None) -> None:
        print(self.scrub(text), file=stream or sys.stdout, flush=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import muse.ai cookies from an already-logged-in Chrome via CDP."
    )
    parser.add_argument(
        "--env-file",
        default=DEFAULT_ENV_FILE,
        help="file containing MUSE2API_KEY (default: /workspace/muse2api/.env)",
    )
    parser.add_argument(
        "--endpoint",
        default="",
        help="CDP websocket URL or http://host:port debug base; "
        "default probes ports 9235 then 9239",
    )
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="comma-separated CDP ports to try, in order (default: 9235,9239)",
    )
    parser.add_argument(
        "--base",
        default=DEFAULT_BASE,
        help="muse2api base URL (default: http://localhost:18610)",
    )
    parser.add_argument("--label", default="", help="account label stored with the import")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="read muse.ai cookies and print the count only; do not POST",
    )
    parser.add_argument("--timeout", type=float, default=20.0, help="network timeout seconds")
    return parser.parse_args(argv)


def parse_ports(text: str) -> list[int]:
    ports: list[int] = []
    for part in text.split(","):
        item = part.strip()
        if not item:
            continue
        port = int(item)
        if port <= 0 or port > 65535:
            raise ImportFailure(f"invalid CDP port {port}")
        ports.append(port)
    if not ports:
        raise ImportFailure("no CDP ports configured")
    return ports


def load_api_key(path: str) -> str:
    """Read MUSE2API_KEY from a dotenv-style file. Does not log the value."""
    try:
        raw = Path(path).read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ImportFailure(f"cannot read env file ({exc.errno})") from None
    key = ""
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export "):].strip()
        name, sep, value = stripped.partition("=")
        if sep != "=" or name.strip() != "MUSE2API_KEY":
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        key = value
    if not key:
        raise ImportFailure("MUSE2API_KEY is missing from env file")
    return key


def _muse_domain(domain: object) -> bool:
    dom = str(domain or "").lstrip(".").lower()
    return dom == "muse.ai" or dom.endswith(".muse.ai")


def filter_muse_cookies(raw_cookies: list) -> tuple[dict[str, str], dict[str, int]]:
    """Keep cookies whose domain is muse.ai. Session cookies omit expires."""
    cookies: dict[str, str] = {}
    expires: dict[str, int] = {}
    for item in raw_cookies or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name or not _muse_domain(item.get("domain")):
            continue
        value = item.get("value")
        if value is None:
            continue
        cookies[name] = str(value)
        exp_raw = item.get("expires", item.get("expirationDate"))
        try:
            exp = math.floor(float(exp_raw))
        except (TypeError, ValueError):
            continue
        if exp > 0:
            expires[name] = exp
    return cookies, expires


def _cookies_from_message(msg: object) -> list:
    if not isinstance(msg, dict):
        return []
    result = msg.get("result", msg)
    if isinstance(result, dict) and isinstance(result.get("cookies"), list):
        return result["cookies"]
    return []


def discover_cdp(ports: list[int], host: str = "127.0.0.1", timeout: float = 2.0) -> CdpEndpoint:
    """Probe debug ports in order and return the first browser websocket."""
    for port in ports:
        version_url = f"http://{host}:{port}/json/version"
        try:
            data = http_json(version_url, timeout=timeout)
        except Exception:
            continue
        ws = data.get("webSocketDebuggerUrl") if isinstance(data, dict) else None
        if isinstance(ws, str) and ws.startswith(("ws://", "wss://")):
            return CdpEndpoint(ws, f"http://{host}:{port}")
    raise ImportFailure("CDP endpoint not found")


def _http_base_from_ws(ws_url: str) -> str:
    parsed = urlparse(ws_url)
    if not parsed.hostname or not parsed.port:
        raise ImportFailure("CDP websocket URL is missing a host")
    scheme = "https" if parsed.scheme == "wss" else "http"
    return f"{scheme}://{parsed.hostname}:{parsed.port}"


def resolve_cdp(endpoint: str, ports: list[int], timeout: float) -> CdpEndpoint:
    text = (endpoint or "").strip()
    if not text:
        return discover_cdp(ports, timeout=min(timeout, 2.0))
    if text.startswith(("ws://", "wss://")):
        return CdpEndpoint(text, _http_base_from_ws(text))
    if text.startswith(("http://", "https://")):
        parsed = urlparse(text)
        if not parsed.netloc:
            raise ImportFailure("CDP endpoint is missing a host")
        base = f"{parsed.scheme}://{parsed.netloc}"
        try:
            data = http_json(base.rstrip("/") + "/json/version", timeout=timeout)
        except Exception:
            raise ImportFailure("CDP /json/version failed") from None
        ws = data.get("webSocketDebuggerUrl") if isinstance(data, dict) else None
        if not isinstance(ws, str) or not ws.startswith(("ws://", "wss://")):
            raise ImportFailure("CDP /json/version has no websocket")
        return CdpEndpoint(ws, base)
    if text.isdigit():
        return discover_cdp([int(text)], timeout=min(timeout, 2.0))
    raise ImportFailure("CDP endpoint must be a ws URL, http base, or port")


def _get_cookies(ws_url: str, timeout: float) -> list:
    client = CDP(ws_url, timeout=timeout)
    try:
        msg = client.send(
            "Network.getCookies",
            {"urls": list(MUSE_COOKIE_URLS)},
            timeout=timeout,
        )
    finally:
        client.close()
    return _cookies_from_message(msg)


def _existing_page_ws(http_base: str, timeout: float) -> str | None:
    """Read /json/list. Does not create, close, or activate a target."""
    try:
        targets = http_json(http_base.rstrip("/") + "/json/list", timeout=timeout)
    except Exception:
        return None
    if not isinstance(targets, list):
        return None
    pages = [
        t for t in targets
        if isinstance(t, dict) and t.get("type") == "page" and t.get("webSocketDebuggerUrl")
    ]
    for target in pages:
        url = str(target.get("url") or "")
        if url.startswith("https://muse.ai") or url.startswith("https://www.muse.ai"):
            return str(target["webSocketDebuggerUrl"])
    if pages:
        return str(pages[0]["webSocketDebuggerUrl"])
    return None


def read_muse_cookies(location: CdpEndpoint, timeout: float) -> tuple[dict[str, str], dict[str, int]]:
    """Network.getCookies on the browser target, else one existing page.

    Attaching to an existing page is read-only: the only CDP method issued is
    Network.getCookies. No target is created and nothing is navigated.
    """
    try:
        raw = _get_cookies(location.ws_url, timeout)
    except Exception:
        page_ws = _existing_page_ws(location.http_base, timeout)
        if not page_ws:
            raise ImportFailure("Network.getCookies failed") from None
        try:
            raw = _get_cookies(page_ws, timeout)
        except Exception:
            raise ImportFailure("Network.getCookies failed") from None
    return filter_muse_cookies(raw)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


def post_json(url: str, key: str, payload: dict | None, timeout: float) -> tuple[int, object]:
    body = b"{}" if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + key,
        },
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirect)
    status = 0
    raw = b""
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            raw = exc.read()
        except Exception:
            raw = b""
    except urllib.error.URLError:
        raise ImportFailure("request failed") from None
    parsed: object = None
    if raw:
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            parsed = None
    return status, parsed


def _account_id(parsed: object) -> str | None:
    if not isinstance(parsed, dict):
        return None
    added = parsed.get("added")
    if not isinstance(added, list) or not added or not isinstance(added[0], dict):
        return None
    aid = added[0].get("id")
    if isinstance(aid, str) and aid.isascii() and all(c.isalnum() or c in "-_" for c in aid):
        return aid
    return None


def _test_ok(status: int, parsed: object) -> bool:
    return 200 <= status < 300 and isinstance(parsed, dict) and parsed.get("ok") is True


@contextmanager
def private_temp_file(prefix: str = "muse-cdp-"):
    """Empty temp file created with umask 077 and mode 600, removed on exit."""
    old = os.umask(0o077)
    fd, path = tempfile.mkstemp(prefix=prefix)
    try:
        os.fchmod(fd, 0o600)
        os.close(fd)
        fd = -1
        yield path
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.remove(path)
        except OSError:
            pass
        os.umask(old)


def _register_cookie_secrets(redactor: Redactor, cookies: dict[str, str]) -> None:
    for value in cookies.values():
        redactor.secret(value)


def run(args: argparse.Namespace, redactor: Redactor | None = None) -> int:
    out = redactor or Redactor()
    old_umask = os.umask(0o077)
    try:
        location = resolve_cdp(args.endpoint, parse_ports(args.ports), args.timeout)
        cookies, expires = read_muse_cookies(location, args.timeout)
        _register_cookie_secrets(out, cookies)
        out.emit(f"cookies: {len(cookies)}")
        if args.dry_run:
            out.emit("dry-run: skipped")
            return 0 if cookies else 2
        if not cookies:
            out.emit("import: fail")
            return 2
        missing = [name for name in ESSENTIAL if name not in cookies]
        if missing:
            out.emit("missing: " + ",".join(missing))
            out.emit("import: skipped")
            return 3
        key = load_api_key(args.env_file)
        out.secret(key)
        base = args.base.rstrip("/")
        # Same body as extension/popup.js and tools/muse2api_cookie_importer.user.js.
        payload = {"label": args.label, "cookies": cookies, "expires": expires}
        status, parsed = post_json(base + "/admin/accounts", key, payload, args.timeout)
        if not (200 <= status < 300):
            out.emit(f"import: HTTP {status} fail")
            return 1
        aid = _account_id(parsed)
        if not aid:
            out.emit(f"import: HTTP {status} fail")
            return 1
        out.emit(f"import: HTTP {status} success")
        test_status, test_parsed = post_json(
            f"{base}/admin/accounts/{aid}/test", key, None, args.timeout
        )
        if _test_ok(test_status, test_parsed):
            out.emit(f"test: HTTP {test_status} success")
            return 0
        out.emit(f"test: HTTP {test_status} fail")
        return 1
    finally:
        os.umask(old_umask)


def main(argv: list[str] | None = None) -> int:
    out = Redactor()
    try:
        args = parse_args(argv)
        return run(args, out)
    except ImportFailure as exc:
        out.emit(f"error: {exc}", sys.stderr)
        return 1
    except Exception as exc:
        out.emit(f"error: {type(exc).__name__}", sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
