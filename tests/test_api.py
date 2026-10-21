import hashlib
import http.client
import json
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from rehub.api import App, Config, make_server
from tests.helpers import FIXTURES, FixtureExecutor

PCAP = FIXTURES / "ot-demo.pcap"
PUMP = FIXTURES / "plc" / "pump.st"
HEADERS = {"X-Rehub": "1"}


class Client:
    def __init__(self, port: int) -> None:
        self.port = port

    def call(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"X-Rehub": "1"} if method in ("POST", "PUT", "DELETE") else {}
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read()
        out = (resp.status, {k.lower(): v for k, v in resp.getheaders()}, data)
        conn.close()
        return out

    def json(self, method: str, path: str, payload: Any = None, **kw: Any) -> tuple[int, Any]:
        body = json.dumps(payload).encode() if payload is not None else None
        status, _, data = self.call(method, path, body, **kw)
        return status, json.loads(data)

    def upload(self, inv: str, name: str, content: bytes) -> tuple[int, Any]:
        status, _, data = self.call("PUT", f"/api/investigations/{inv}/files?name={name}", content)
        return status, json.loads(data)

    def wait_done(self, inv: str, timeout: float = 15) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _, body = self.json("GET", f"/api/investigations/{inv}")
            if body["status"]["stage"] in ("done", "failed"):
                return body  # type: ignore[no-any-return]
            time.sleep(0.05)
        raise AssertionError("investigation did not finish")


def start_server(config: Config, execute: Any) -> tuple[App, Any, Client]:
    app = App(config, execute)
    server = make_server(app)
    threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True).start()
    return app, server, Client(server.server_port)


@pytest.fixture
def env(tmp_path: Path) -> Iterator[tuple[Client, Config]]:
    config = Config(data_dir=tmp_path / "data", port=0)
    app, server, client = start_server(config, FixtureExecutor())
    yield client, config
    server.shutdown()
    server.server_close()
    app.shutdown()


@pytest.fixture
def client(env: tuple[Client, Config]) -> Client:
    return env[0]


def analyzed(client: Client) -> tuple[str, dict[str, Any]]:
    _, created = client.json("POST", "/api/investigations")
    inv = created["id"]
    assert client.upload(inv, "ot-demo.pcap", PCAP.read_bytes())[0] == 201
    assert client.upload(inv, "pump.st", PUMP.read_bytes())[0] == 201
    status, started = client.json(
        "POST", f"/api/investigations/{inv}/run", {"plc_ips": {"pump.st": "10.0.0.20"}}
    )
    assert status == 202 and started["stage"] == "queued"
    return inv, client.wait_done(inv)


def test_health_and_static_ui(client: Client) -> None:
    assert client.json("GET", "/api/health") == (200, {"ok": True, "auth": False})
    status, headers, body = client.call("GET", "/")
    assert status == 200 and b"ReHub" in body
    assert "default-src 'self'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"


def test_static_path_traversal_blocked(client: Client) -> None:
    for path in ("/ui/../api.py", "/ui/%2e%2e/api.py", "/ui/..%2fapi.py", "/ui/nope.js"):
        assert client.call("GET", path)[0] == 404


def test_full_flow_over_http(client: Client) -> None:
    inv, done = analyzed(client)
    assert done["status"]["stage"] == "done"
    record = done["record"]
    titles = {d["title"] for d in record["investigation"]["detections"]}
    assert {"S7comm PLC Stop", "Modbus WRITE_SINGLE_REGISTER"} <= titles
    single = next(
        d
        for d in record["investigation"]["detections"]
        if d["title"] == "Modbus WRITE_SINGLE_REGISTER"
    )
    assert single["corroborated"] is True
    assert single["plc"][0]["variable"] == "Setpoint"
    _, listing = client.json("GET", "/api/investigations")
    [item] = listing["investigations"]
    assert item["id"] == inv and item["stage"] == "done" and item["high"] == 1


def test_evidence_download_is_attachment_and_exact(client: Client) -> None:
    inv, done = analyzed(client)
    by_name = {e["name"]: e for e in done["record"]["evidence"]}
    for name, expected in (("ot-demo.pcap", PCAP.read_bytes()), ("zeek/conn.log", None)):
        sha = by_name[name]["sha256"]
        status, headers, body = client.call("GET", f"/api/investigations/{inv}/evidence/{sha}")
        assert status == 200
        assert headers["content-type"] == "application/octet-stream"
        assert headers["content-disposition"].startswith("attachment;")
        assert hashlib.sha256(body).hexdigest() == sha
        if expected is not None:
            assert body == expected


def test_line_drilldown(client: Client) -> None:
    inv, done = analyzed(client)
    sha = next(e["sha256"] for e in done["record"]["evidence"] if e["name"] == "zeek/conn.log")
    status, body = client.json(
        "GET", f"/api/investigations/{inv}/evidence/{sha}/lines?start=2&count=2"
    )
    assert status == 200 and body["start"] == 2 and len(body["lines"]) == 2
    assert '"uid"' in body["lines"][0]
    pcap_sha = next(e["sha256"] for e in done["record"]["evidence"] if e["name"] == "ot-demo.pcap")
    assert client.call("GET", f"/api/investigations/{inv}/evidence/{pcap_sha}/lines")[0] == 415
    assert client.call("GET", f"/api/investigations/{inv}/evidence/{sha}/lines?start=x")[0] == 400


def test_packet_drilldown_for_a_flow(client: Client) -> None:
    from urllib.parse import quote

    inv, done = analyzed(client)
    flows = done["record"]["investigation"]["flows"]
    rogue = next(f for f in flows.values() if f["src"] == "10.0.0.66" and f["dport"] == 502)
    path = f"/api/investigations/{inv}/flows/{quote(rogue['key'], safe='')}/packets"
    status, body = client.json("GET", path)
    assert status == 200 and not body["truncated"]
    assert len(body["packets"]) == rogue["packets"] == 14
    _, capped = client.json("GET", path + "?limit=3")
    assert len(capped["packets"]) == 3 and capped["truncated"]


def test_host_header_allowlist_blocks_dns_rebinding(client: Client) -> None:
    status, _, _ = client.call("GET", "/api/health", headers={"Host": "evil.example.com"})
    assert status == 403
    assert client.call("GET", "/api/health", headers={"Host": "localhost:8080"})[0] == 200
    assert client.call("GET", "/api/health", headers={"Host": "[::1]:8080"})[0] == 200


def test_mutations_need_header_and_same_origin(client: Client) -> None:
    conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=5)
    conn.request("POST", "/api/investigations")
    assert conn.getresponse().status == 403
    conn.close()
    status, _, _ = client.call(
        "POST", "/api/investigations", headers={"Origin": "https://evil.example"}
    )
    assert status == 403
    status, _, _ = client.call(
        "POST", "/api/investigations", headers={"Origin": "http://localhost:8080"}
    )
    assert status == 201


def test_upload_name_is_sanitized(env: tuple[Client, Config]) -> None:
    client, config = env
    _, created = client.json("POST", "/api/investigations")
    inv = created["id"]
    status, body = client.upload(inv, "..%2F..%2Fescape.txt", b"x")
    assert status == 201 and body["name"] == "escape.txt"
    status, body = client.upload(inv, "C%3A%5Cevil%5Cwin.ini", b"x")
    assert body["name"] == "win.ini"
    assert not (config.data_dir.parent / "escape.txt").exists()
    assert {p.name for p in (config.data_dir / "uploads" / inv).iterdir()} == {
        "escape.txt",
        "win.ini",
    }
    assert client.upload(inv, "%2E%2E", b"x")[0] == 400
    assert client.upload(inv, "", b"x")[0] == 400


def test_upload_rules(client: Client) -> None:
    _, created = client.json("POST", "/api/investigations")
    inv = created["id"]
    assert client.upload(inv, "a.pcap", PCAP.read_bytes())[0] == 201
    assert client.upload(inv, "a.pcap", b"again")[0] == 409
    assert (
        client.json("POST", f"/api/investigations/{inv}/run", {"plc_ips": {"x": "nope"}})[0] == 400
    )
    assert client.json("POST", f"/api/investigations/{inv}/run", {"plc_ips": []})[0] == 400
    assert client.json("POST", f"/api/investigations/{inv}/run", {})[0] == 202
    client.wait_done(inv)
    assert client.upload(inv, "late.pcap", b"x")[0] == 409
    assert client.json("POST", f"/api/investigations/{inv}/run", {})[0] == 409


def test_run_with_no_files_rejected(client: Client) -> None:
    _, created = client.json("POST", "/api/investigations")
    assert client.json("POST", f"/api/investigations/{created['id']}/run", {})[0] == 400


def test_draft_status_lists_files(client: Client) -> None:
    _, created = client.json("POST", "/api/investigations")
    inv = created["id"]
    client.upload(inv, "a.txt", b"hello")
    _, body = client.json("GET", f"/api/investigations/{inv}")
    assert body["status"]["stage"] == "draft"
    assert body["files"] == [{"name": "a.txt", "size": 5}]


def test_content_length_required(client: Client) -> None:
    _, created = client.json("POST", "/api/investigations")
    conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=5)
    conn.putrequest("PUT", f"/api/investigations/{created['id']}/files?name=x.bin")
    conn.putheader("X-Rehub", "1")
    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
    conn.send(b"1\r\nx\r\n0\r\n\r\n")
    assert conn.getresponse().status == 411
    conn.close()


def test_truncated_upload_leaves_no_file(env: tuple[Client, Config]) -> None:
    client, config = env
    _, created = client.json("POST", "/api/investigations")
    inv = created["id"]
    sock = socket.create_connection(("127.0.0.1", client.port), timeout=5)
    sock.sendall(
        f"PUT /api/investigations/{inv}/files?name=cut.bin HTTP/1.1\r\nHost: localhost\r\n"
        "X-Rehub: 1\r\nContent-Length: 100\r\n\r\nonly-a-few-bytes".encode()
    )
    sock.shutdown(socket.SHUT_WR)
    sock.recv(4096)
    sock.close()
    time.sleep(0.2)
    assert list((config.data_dir / "uploads" / inv).iterdir()) == []


def test_size_limits(tmp_path: Path) -> None:
    config = Config(data_dir=tmp_path / "d", port=0, max_file_bytes=10, max_draft_bytes=15)
    app, server, client = start_server(config, FixtureExecutor())
    try:
        _, created = client.json("POST", "/api/investigations")
        inv = created["id"]
        assert client.upload(inv, "big.bin", b"x" * 11)[0] == 413
        assert client.upload(inv, "a.bin", b"x" * 9)[0] == 201
        assert client.upload(inv, "b.bin", b"x" * 9)[0] == 413
    finally:
        server.shutdown()
        server.server_close()
        app.shutdown()


def test_unknown_and_malformed_ids(client: Client) -> None:
    assert client.call("GET", "/api/investigations/aaaaaaaaaaaa")[0] == 404
    assert client.call("GET", "/api/investigations/../health")[0] in (404, 403)
    assert client.call("GET", "/api/investigations/NOTHEX")[0] == 404
    assert client.call("GET", "/api/nothing")[0] == 404
    inv, _ = analyzed(client)
    assert client.call("GET", f"/api/investigations/{inv}/evidence/{'0' * 64}")[0] == 404
    assert client.call("GET", f"/api/investigations/{inv}/evidence/../../x")[0] == 404


def test_delete_removes_investigation(env: tuple[Client, Config]) -> None:
    client, config = env
    inv, _ = analyzed(client)
    assert client.json("DELETE", f"/api/investigations/{inv}")[0] == 200
    assert client.call("GET", f"/api/investigations/{inv}")[0] == 404
    assert not (config.data_dir / "investigations" / inv).exists()
    assert not (config.data_dir / "uploads" / inv).exists()
    assert client.json("DELETE", f"/api/investigations/{inv}")[0] == 404


def test_restart_marks_interrupted_runs_failed(tmp_path: Path) -> None:
    inv_dir = tmp_path / "data" / "investigations" / "abcdefabcdef"
    inv_dir.mkdir(parents=True)
    (inv_dir / "status.json").write_text('{"stage": "analyze", "detail": "", "updated": ""}')
    app = App(Config(data_dir=tmp_path / "data", port=0))
    try:
        assert json.loads((inv_dir / "status.json").read_text())["stage"] == "failed"
    finally:
        app.shutdown()


def test_one_click_demo_runs_the_packaged_case(client: Client) -> None:
    status, started = client.json("POST", "/api/demo")
    assert status == 202 and started["stage"] == "queued"
    done = client.wait_done(started["id"])
    record = done["record"]
    assert {e["name"] for e in record["evidence"]} >= {"ot-demo.pcap", "pump.st"}
    titles = {d["title"] for d in record["investigation"]["detections"]}
    assert {"S7comm PLC Stop", "Modbus WRITE_SINGLE_REGISTER"} <= titles
    assert record["investigation"]["assets"]["10.0.0.20"]["plc_projects"] == ["pump"]
    assert client.call("POST", "/api/demo", headers={"X-Rehub": ""})[0] == 403


def test_status_exposes_tool_states(client: Client) -> None:
    inv, done = analyzed(client)
    assert done["status"]["stage"] == "done"
    _, listing = client.json("GET", "/api/investigations")
    assert listing["investigations"][0]["stage"] == "done"


def test_packaged_demo_files_match_the_fixtures() -> None:
    from rehub.api import DEMO_DIR

    assert (DEMO_DIR / "ot-demo.pcap").read_bytes() == PCAP.read_bytes()
    assert (DEMO_DIR / "pump.st").read_bytes() == PUMP.read_bytes()
