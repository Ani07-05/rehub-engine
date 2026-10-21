import asyncio
import contextlib
import http.client
import threading
from pathlib import Path

import pytest

from rehub.api import App, Config, make_server
from rehub.gateway import parse_hostport, serve_gateway
from tests.helpers import FixtureExecutor


class GatewayThread:
    def __init__(self, upstream_port: int) -> None:
        self.upstream_port = upstream_port
        self.port = 0
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.ready = threading.Event()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        fut: asyncio.Future[int] = self.loop.create_future()

        async def main() -> None:
            task = asyncio.create_task(
                serve_gateway("127.0.0.1", 0, "127.0.0.1", self.upstream_port, fut)
            )
            self.port = await fut
            self.ready.set()
            await task

        with contextlib.suppress(asyncio.CancelledError):
            self.loop.run_until_complete(main())

    def start(self) -> "GatewayThread":
        self.thread.start()
        assert self.ready.wait(5)
        return self

    def stop(self) -> None:
        for task in asyncio.all_tasks(self.loop):
            self.loop.call_soon_threadsafe(task.cancel)
        self.thread.join(timeout=3)


@pytest.fixture
def stack(tmp_path: Path):  # type: ignore[no-untyped-def]
    app = App(Config(data_dir=tmp_path / "data", port=0), FixtureExecutor())
    server = make_server(app)
    threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True).start()
    gateway = GatewayThread(server.server_port).start()
    yield gateway.port
    gateway.stop()
    server.shutdown()
    server.server_close()
    app.shutdown()


def test_api_works_through_the_gateway(stack: int) -> None:
    conn = http.client.HTTPConnection("127.0.0.1", stack, timeout=10)
    conn.request("GET", "/api/health")
    resp = conn.getresponse()
    assert resp.status == 200 and b'"ok": true' in resp.read()


def test_large_streamed_upload_survives_the_gateway(stack: int) -> None:
    def call(method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", stack, timeout=20)
        conn.request(method, path, body=body, headers={"X-Rehub": "1"})
        resp = conn.getresponse()
        return resp.status, resp.read()

    import json

    inv = json.loads(call("POST", "/api/investigations")[1])["id"]
    payload = bytes(range(256)) * (6 << 12)
    status, body = call("PUT", f"/api/investigations/{inv}/files?name=big.bin", payload)
    assert status == 201 and json.loads(body)["size"] == len(payload)


def test_host_allowlist_still_enforced_behind_the_gateway(stack: int) -> None:
    conn = http.client.HTTPConnection("127.0.0.1", stack, timeout=10)
    conn.request("GET", "/api/health", headers={"Host": "evil.example"})
    assert conn.getresponse().status == 403


def test_dead_upstream_closes_the_client_connection() -> None:
    gateway = GatewayThread(1).start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", gateway.port, timeout=5)
        with pytest.raises((http.client.HTTPException, ConnectionError, OSError)):
            conn.request("GET", "/")
            conn.getresponse()
    finally:
        gateway.stop()


def test_parse_hostport() -> None:
    assert parse_hostport("engine:8080", 1) == ("engine", 8080)
    assert parse_hostport("0.0.0.0:9", 1) == ("0.0.0.0", 9)
    assert parse_hostport(":7", 1) == ("0.0.0.0", 7)
    assert parse_hostport("engine", 8080) == ("engine", 8080)
    with pytest.raises(ValueError):
        parse_hostport("engine:abc", 1)
