import ipaddress
import json
import logging
import mimetypes
import os
import re
import shutil
import threading
import time
import unicodedata
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from rehub import drill
from rehub.auth import Auth, cookie_header, load_or_create_token, parse_cookie
from rehub.doctor import Report, run_doctor
from rehub.pipeline import (
    RECORD,
    investigation_dir,
    list_investigations,
    load_record,
    read_status,
    run_investigation,
)
from rehub.serialize import to_jsonable
from rehub.tools import Executor, subprocess_executor

log = logging.getLogger("rehub.api")

ID_RE = re.compile(r"^[0-9a-f]{12}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
CHUNK = 1 << 20
JSON_BODY_LIMIT = 64 * 1024
DEFAULT_ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]"})
MUTATING = frozenset({"POST", "PUT", "DELETE"})
UI_DIR = Path(__file__).parent / "ui"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'self'"
)
FORM_LIMIT = 4096
DOCTOR_TTL = 30.0


class HttpError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(slots=True)
class Config:
    data_dir: Path
    host: str = "127.0.0.1"
    port: int = 8080
    max_file_bytes: int = 8 << 30
    max_draft_bytes: int = 16 << 30
    allowed_hosts: frozenset[str] = DEFAULT_ALLOWED_HOSTS
    workers: int = 1
    timeout: float = 1800.0
    token: str = ""
    public_url: str = ""

    @classmethod
    def from_env(cls, data_dir: Path) -> "Config":
        extra = {
            h.strip().lower()
            for h in os.environ.get("REHUB_ALLOWED_HOSTS", "").split(",")
            if h.strip()
        }
        return cls(
            data_dir=data_dir,
            host=os.environ.get("REHUB_HOST", "127.0.0.1"),
            port=int(os.environ.get("REHUB_PORT", "8080")),
            max_file_bytes=int(os.environ.get("REHUB_MAX_UPLOAD_BYTES", str(8 << 30))),
            max_draft_bytes=int(os.environ.get("REHUB_MAX_DRAFT_BYTES", str(16 << 30))),
            allowed_hosts=DEFAULT_ALLOWED_HOSTS | extra,
            workers=int(os.environ.get("REHUB_WORKERS", "1")),
            token="" if os.environ.get("REHUB_NO_AUTH") == "1" else load_or_create_token(data_dir),
            public_url=os.environ.get("REHUB_PUBLIC_URL", "").rstrip("/"),
        )


def host_allowed(header: str | None, allowed: frozenset[str]) -> bool:
    if not header:
        return False
    host = header.lower()
    host = (
        host.split("]")[0] + "]"
        if host.startswith("[")
        else host.rsplit(":", 1)[0]
        if ":" in host
        else host
    )
    return host in allowed


def safe_name(raw: str) -> str:
    name = PurePosixPath(unquote(raw).replace("\\", "/")).name
    name = "".join(c for c in name if unicodedata.category(c)[0] != "C").strip()
    if not name or name in (".", "..") or len(name) > 200:
        raise HttpError(400, "invalid file name")
    return name


@dataclass(slots=True)
class App:
    config: Config
    execute: Executor = subprocess_executor
    pool: ThreadPoolExecutor = field(init=False)
    queued: set[str] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)
    auth: Auth = field(init=False)
    last_doctor: Report | None = None
    doctor_lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self.auth = Auth(self.config.token)
        self.pool = ThreadPoolExecutor(
            max_workers=self.config.workers, thread_name_prefix="rehub-job"
        )
        self.recover()

    @property
    def uploads(self) -> Path:
        return self.config.data_dir / "uploads"

    def recover(self) -> None:
        root = self.config.data_dir / "investigations"
        for inv_dir in root.iterdir() if root.is_dir() else []:
            status = read_status(self.config.data_dir, inv_dir.name)
            if status and status["stage"] not in ("done", "failed"):
                (inv_dir / "status.json").write_text(
                    json.dumps(
                        {"stage": "failed", "detail": "interrupted by restart", "updated": ""}
                    )
                )

    def doctor(self, force: bool = False) -> dict[str, Any]:
        with self.doctor_lock:
            stale = (
                self.last_doctor is None or time.time() - self.last_doctor.checked_at > DOCTOR_TTL
            )
            if force or stale:
                self.last_doctor = run_doctor(
                    self.config.data_dir, self.execute, auth_enabled=self.auth.enabled
                )
            report = self.last_doctor
        assert report is not None
        return {**to_jsonable(report), "status": report.status}

    def shutdown(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)

    def _job(self, inv_id: str, files: list[Path], plc_ips: dict[str, str]) -> None:
        try:
            run_investigation(
                files,
                self.config.data_dir,
                plc_ips=plc_ips,
                execute=self.execute,
                timeout=self.config.timeout,
                investigation_id=inv_id,
            )
        except Exception:
            log.exception("investigation %s failed", inv_id)
        finally:
            with self.lock:
                self.queued.discard(inv_id)

    def create(self) -> dict[str, Any]:
        inv_id = uuid.uuid4().hex[:12]
        (self.uploads / inv_id).mkdir(parents=True)
        return {"id": inv_id}

    def draft_dir(self, inv_id: str) -> Path:
        path = self.uploads / inv_id
        if not path.is_dir():
            raise HttpError(404, "no such draft")
        return path

    def draft_files(self, inv_id: str) -> list[dict[str, Any]]:
        return [
            {"name": p.name, "size": p.stat().st_size}
            for p in sorted(self.draft_dir(inv_id).iterdir())
            if p.is_file() and not p.name.endswith(".part")
        ]

    def is_started(self, inv_id: str) -> bool:
        with self.lock:
            return inv_id in self.queued or investigation_dir(self.config.data_dir, inv_id).exists()

    def start(self, inv_id: str, body: dict[str, Any]) -> dict[str, Any]:
        draft = self.draft_dir(inv_id)
        plc_ips = body.get("plc_ips", {})
        if not isinstance(plc_ips, dict) or len(plc_ips) > 100:
            raise HttpError(400, "plc_ips must be an object of file name to IP")
        for name, ip in plc_ips.items():
            try:
                ipaddress.ip_address(str(ip))
            except ValueError as exc:
                raise HttpError(400, f"invalid IP for {name}") from exc
        with self.lock:
            if inv_id in self.queued or investigation_dir(self.config.data_dir, inv_id).exists():
                raise HttpError(409, "already started")
            files = sorted(
                p for p in draft.iterdir() if p.is_file() and not p.name.endswith(".part")
            )
            if not files:
                raise HttpError(400, "no files uploaded")
            self.queued.add(inv_id)
        self.pool.submit(self._job, inv_id, files, {str(k): str(v) for k, v in plc_ips.items()})
        return {"id": inv_id, "stage": "queued"}

    def save_upload(self, inv_id: str, name: str, length: int, stream: Any) -> dict[str, Any]:
        draft = self.draft_dir(inv_id)
        if self.is_started(inv_id):
            raise HttpError(409, "investigation already started")
        if length > self.config.max_file_bytes:
            raise HttpError(413, "file too large")
        target = draft / name
        if target.exists():
            raise HttpError(409, f"{name} already uploaded")
        used = sum(p.stat().st_size for p in draft.iterdir() if p.is_file())
        if used + length > self.config.max_draft_bytes:
            raise HttpError(413, "upload total too large")
        part = draft / f"{name}.part"
        received = 0
        try:
            with part.open("wb") as out:
                while received < length:
                    chunk = stream.read(min(CHUNK, length - received))
                    if not chunk:
                        break
                    out.write(chunk)
                    received += len(chunk)
            if received != length:
                raise HttpError(400, "upload ended early")
            part.replace(target)
        except OSError as exc:
            raise HttpError(507, f"cannot store upload: {exc.strerror}") from exc
        finally:
            part.unlink(missing_ok=True)
        return {"name": name, "size": received}

    def investigation(self, inv_id: str) -> dict[str, Any]:
        data = self.config.data_dir
        record = load_record(data, inv_id)
        if record is not None:
            return {"id": inv_id, "status": {"stage": "done"}, "record": to_jsonable(record)}
        status = read_status(data, inv_id)
        if status:
            return {"id": inv_id, "status": status}
        with self.lock:
            queued = inv_id in self.queued
        if queued:
            return {"id": inv_id, "status": {"stage": "queued"}}
        return {"id": inv_id, "status": {"stage": "draft"}, "files": self.draft_files(inv_id)}

    def delete(self, inv_id: str) -> None:
        if self.is_started(inv_id) and (read_status(self.config.data_dir, inv_id) or {}).get(
            "stage"
        ) not in ("done", "failed"):
            raise HttpError(409, "investigation is running")
        found = False
        for path in (investigation_dir(self.config.data_dir, inv_id), self.uploads / inv_id):
            if path.exists():
                shutil.rmtree(path)
                found = True
        if not found:
            raise HttpError(404, "no such investigation")


class Handler(BaseHTTPRequestHandler):
    server_version = "rehub"

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined, no-any-return]

    def log_message(self, format: str, *args: Any) -> None:
        log.debug("%s %s", self.address_string(), format % args)

    def _send(
        self, status: int, body: bytes, ctype: str, extra: dict[str, str] | None = None
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: Any) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _body_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > JSON_BODY_LIMIT:
            raise HttpError(413, "body too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError as exc:
            raise HttpError(400, "invalid JSON") from exc
        if not isinstance(data, dict):
            raise HttpError(400, "JSON object expected")
        return data

    def _bearer_ok(self) -> bool:
        header = self.headers.get("Authorization", "")
        return header.startswith("Bearer ") and self.app.auth.check_token(header[7:])

    def _cookie_ok(self) -> bool:
        return self.app.auth.valid_cookie(parse_cookie(self.headers.get("Cookie")))

    def _authed(self) -> bool:
        return not self.app.auth.enabled or self._bearer_ok() or self._cookie_ok()

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        return not origin or host_allowed(urlsplit(origin).netloc, self.app.config.allowed_hosts)

    def _guard(self, method: str) -> None:
        if not host_allowed(self.headers.get("Host"), self.app.config.allowed_hosts):
            raise HttpError(403, "host not allowed")
        if method not in MUTATING or urlsplit(self.path).path == "/login":
            return
        if self.app.auth.enabled and self._bearer_ok():
            return
        if self.headers.get("X-Rehub") != "1":
            raise HttpError(403, "missing X-Rehub header")
        if not self._origin_ok():
            raise HttpError(403, "origin not allowed")

    def _redirect(self, status: int, location: str, cookie: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _login_page(self, status: int, message: str = "") -> None:
        html = (UI_DIR / "login.html").read_text()
        error = f'<p class="callout err" role="alert">{message}</p>' if message else ""
        self._send(
            status,
            html.replace("<!--ERROR-->", error).encode(),
            "text/html; charset=utf-8",
            {"Content-Security-Policy": CSP},
        )

    def _root(self, query: dict[str, list[str]]) -> None:
        auth = self.app.auth
        supplied = query.get("token", [""])[0]
        if supplied:
            if auth.locked_out():
                return self._login_page(429, "Too many attempts. Wait a minute and try again.")
            if auth.check_token(supplied):
                return self._redirect(302, "/", cookie_header(auth.make_cookie()))
            auth.record_failure()
            return self._login_page(401, "That token is not right.")
        if self._authed():
            return self._static(["index.html"], authed=True)
        self._login_page(200)

    def _login(self) -> None:
        auth = self.app.auth
        if not self._origin_ok() or self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise HttpError(403, "origin not allowed")
        if auth.locked_out():
            return self._login_page(429, "Too many attempts. Wait a minute and try again.")
        length = int(self.headers.get("Content-Length") or 0)
        if length > FORM_LIMIT:
            raise HttpError(413, "body too large")
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        if auth.check_token(form.get("token", [""])[0]):
            return self._redirect(303, "/", cookie_header(auth.make_cookie()))
        auth.record_failure()
        self._login_page(401, "That token is not right.")

    def do_GET(self) -> None:
        self._run("GET")

    def do_POST(self) -> None:
        self._run("POST")

    def do_PUT(self) -> None:
        self._run("PUT")

    def do_DELETE(self) -> None:
        self._run("DELETE")

    def _run(self, method: str) -> None:
        try:
            self._guard(method)
            self._route(method)
        except HttpError as exc:
            self.close_connection = True
            self._json(exc.status, {"error": exc.message})
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:
            log.exception("unhandled error")
            self.close_connection = True
            self._json(500, {"error": "internal error"})

    def _route(self, method: str) -> None:
        url = urlsplit(self.path)
        parts = [unquote(p) for p in url.path.split("/") if p]
        query = parse_qs(url.query)
        app = self.app
        if method == "GET" and not parts:
            return self._root(query)
        if method == "POST" and parts == ["login"]:
            return self._login()
        if method == "GET" and parts[:1] == ["ui"]:
            return self._static(parts[1:])
        if parts[:1] != ["api"]:
            raise HttpError(404, "not found")
        route = parts[1:]
        if route == ["health"] and method == "GET":
            return self._json(200, {"ok": True, "auth": app.auth.enabled})
        if not self._authed():
            raise HttpError(401, "login required")
        if route == ["logout"] and method == "POST":
            return self._logout()
        if route == ["doctor"] and method == "GET":
            return self._json(200, app.doctor(force=_int(query, "force", 0, 0, 1) == 1))
        if route == ["investigations"]:
            if method == "GET":
                return self._json(200, {"investigations": list_investigations(app.config.data_dir)})
            if method == "POST":
                return self._json(201, app.create())
        if len(route) >= 2 and route[0] == "investigations":
            inv_id = route[1]
            if not ID_RE.match(inv_id):
                raise HttpError(404, "not found")
            return self._investigation_route(method, inv_id, route[2:], query, url.query)
        raise HttpError(404, "not found")

    def _investigation_route(
        self, method: str, inv_id: str, rest: list[str], query: dict[str, list[str]], raw_query: str
    ) -> None:
        app = self.app
        if not rest:
            if method == "GET":
                if (
                    not (app.uploads / inv_id).is_dir()
                    and not investigation_dir(app.config.data_dir, inv_id).is_dir()
                ):
                    raise HttpError(404, "no such investigation")
                return self._json(200, app.investigation(inv_id))
            if method == "DELETE":
                app.delete(inv_id)
                return self._json(200, {"deleted": inv_id})
        if rest == ["files"] and method == "PUT":
            name = safe_name(query.get("name", [""])[0])
            raw_len = self.headers.get("Content-Length")
            if raw_len is None or not raw_len.isdigit():
                raise HttpError(411, "Content-Length required")
            return self._json(201, app.save_upload(inv_id, name, int(raw_len), self.rfile))
        if rest == ["run"] and method == "POST":
            return self._json(202, app.start(inv_id, self._body_json()))
        record = load_record(app.config.data_dir, inv_id)
        if record is None:
            raise HttpError(404, "investigation not finished")
        if len(rest) == 2 and rest[0] == "evidence" and method == "GET":
            return self._download(record, rest[1])
        if len(rest) == 3 and rest[0] == "evidence" and rest[2] == "lines" and method == "GET":
            return self._lines(record, rest[1], query)
        if len(rest) == 3 and rest[0] == "flows" and rest[2] == "packets" and method == "GET":
            limit = _int(query, "limit", 200, 1, 2000)
            rows, truncated = drill.flow_packets(app.config.data_dir, record, rest[1], limit)
            return self._json(200, {"packets": rows, "truncated": truncated})
        raise HttpError(404, "not found")

    def _evidence_file(self, record: Any, sha: str) -> tuple[Path, Any]:
        if not SHA_RE.match(sha):
            raise HttpError(404, "not found")
        path = drill.evidence_path(self.app.config.data_dir, record, sha)
        ev = drill.find_evidence(record, sha)
        if path is None or ev is None:
            raise HttpError(404, "evidence not found")
        return path, ev

    def _download(self, record: Any, sha: str) -> None:
        path, ev = self._evidence_file(record, sha)
        filename = re.sub(r"[^\w.\-]+", "_", PurePosixPath(ev.name).name) or "evidence"
        size = path.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        with path.open("rb") as fh:
            shutil.copyfileobj(fh, self.wfile, CHUNK)

    def _lines(self, record: Any, sha: str, query: dict[str, list[str]]) -> None:
        path, _ = self._evidence_file(record, sha)
        if not drill.is_text(path):
            raise HttpError(415, "binary evidence has no line view")
        start = _int(query, "start", 1, 1, 10**9)
        count = _int(query, "count", 20, 1, drill.MAX_LINES)
        self._json(200, drill.read_lines(path, start, count))

    def _logout(self) -> None:
        self.send_response(200)
        body = b'{"ok": true}'
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", cookie_header("", 0))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _static(self, parts: list[str], authed: bool = False) -> None:
        rel = "/".join(parts) or "index.html"
        if rel in ("index.html", "login.html") and not authed:
            return (
                self._login_page(200) if not self._authed() else self._static(["index.html"], True)
            )
        target = (UI_DIR / rel).resolve()
        if not target.is_relative_to(UI_DIR.resolve()) or not target.is_file():
            raise HttpError(404, "not found")
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._send(
            200,
            target.read_bytes(),
            f"{ctype}; charset=utf-8"
            if ctype.startswith("text/") or "javascript" in ctype
            else ctype,
            {"Content-Security-Policy": CSP},
        )


def _int(query: dict[str, list[str]], key: str, default: int, lo: int, hi: int) -> int:
    raw = query.get(key, [str(default)])[0]
    if not raw.lstrip("-").isdigit():
        raise HttpError(400, f"{key} must be an integer")
    return max(lo, min(hi, int(raw)))


def make_server(app: App) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((app.config.host, app.config.port), Handler)
    server.app = app  # type: ignore[attr-defined]
    server.daemon_threads = True
    return server


def access_url(config: Config, port: int | None = None) -> str:
    shown_host = "localhost" if config.host in ("0.0.0.0", "::") else config.host
    base = config.public_url or f"http://{shown_host}:{port or config.port}"
    return f"{base}/?token={config.token}" if config.token else base


def print_doctor(report: Report) -> None:
    marks = {"ok": "ok  ", "warn": "warn", "fail": "FAIL"}
    for check in report.checks:
        print(f"  [{marks[check.status]}] {check.label}: {check.detail}", flush=True)
        if check.status != "ok" and check.fix:
            print(f"         {check.fix}", flush=True)
    print(f"Startup check: {report.status}", flush=True)


def serve(config: Config, execute: Executor = subprocess_executor) -> None:
    app = App(config, execute)
    server = make_server(app)
    url = access_url(config, server.server_port)
    print_doctor(run_doctor(config.data_dir, execute, auth_enabled=bool(config.token)))
    if config.token:
        print(f"ReHub is running. Open this link, it signs you in:\n  {url}", flush=True)
    else:
        print(f"ReHub is running at {url}", flush=True)
        print(
            "WARNING: authentication is off. Anyone who can reach this port can use ReHub.",
            flush=True,
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.shutdown()


__all__ = ["RECORD", "App", "Config", "access_url", "make_server", "serve"]
