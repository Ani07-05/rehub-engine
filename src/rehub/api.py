import ipaddress
import json
import logging
import mimetypes
import os
import re
import shutil
import threading
import unicodedata
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from rehub import drill
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
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)


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

    def __post_init__(self) -> None:
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

    def _guard(self, method: str) -> None:
        if not host_allowed(self.headers.get("Host"), self.app.config.allowed_hosts):
            raise HttpError(403, "host not allowed")
        if method in MUTATING:
            if self.headers.get("X-Rehub") != "1":
                raise HttpError(403, "missing X-Rehub header")
            origin = self.headers.get("Origin")
            if origin and not host_allowed(urlsplit(origin).netloc, self.app.config.allowed_hosts):
                raise HttpError(403, "origin not allowed")

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
        if method == "GET" and (not parts or parts[0] == "ui"):
            return self._static(parts[1:] if parts else [])
        if parts[:1] != ["api"]:
            raise HttpError(404, "not found")
        route = parts[1:]
        if route == ["health"] and method == "GET":
            return self._json(200, {"ok": True})
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

    def _static(self, parts: list[str]) -> None:
        rel = "/".join(parts) or "index.html"
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


def serve(config: Config, execute: Executor = subprocess_executor) -> None:
    app = App(config, execute)
    server = make_server(app)
    print(f"ReHub listening on http://{config.host}:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.shutdown()


__all__ = ["RECORD", "App", "Config", "make_server", "serve"]
