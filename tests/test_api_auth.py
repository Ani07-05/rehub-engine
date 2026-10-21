import http.client
import json
import threading
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlencode

import pytest

from rehub.api import App, Config, access_url, make_server
from rehub.auth import MAX_FAILURES
from tests.helpers import FixtureExecutor

TOKEN = "test-token-123"


class Raw:
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
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        out = (resp.status, {k.lower(): v for k, v in resp.getheaders()}, data)
        conn.close()
        return out


@pytest.fixture
def web(tmp_path: Path) -> Iterator[tuple[Raw, Config]]:
    config = Config(data_dir=tmp_path / "data", port=0, token=TOKEN)
    app = App(config, FixtureExecutor())
    server = make_server(app)
    threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True).start()
    yield Raw(server.server_port), config
    server.shutdown()
    server.server_close()
    app.shutdown()


def sign_in(raw: Raw) -> str:
    status, headers, _ = raw.call("GET", f"/?token={TOKEN}")
    assert status == 302
    return headers["set-cookie"].split(";")[0]


def test_api_requires_login(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    for path in ("/api/investigations", "/api/investigations/aaaaaaaaaaaa"):
        status, _, body = raw.call("GET", path)
        assert status == 401 and json.loads(body)["error"] == "login required"
    assert raw.call("POST", "/api/investigations", headers={"X-Rehub": "1"})[0] == 401


def test_health_and_static_assets_are_public(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    assert raw.call("GET", "/api/health")[0] == 200
    assert raw.call("GET", "/ui/css/app.css")[0] == 200
    assert raw.call("GET", "/ui/js/main.js")[0] == 200


def test_root_shows_login_not_the_app(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    for path in ("/", "/ui/index.html"):
        status, headers, body = raw.call("GET", path)
        assert status == 200 and b"Sign in to ReHub" in body
        assert b"/ui/js/main.js" not in body and TOKEN.encode() not in body
        assert "form-action 'self'" in headers["content-security-policy"]


def test_token_in_url_becomes_cookie_and_redirect(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    status, headers, _ = raw.call("GET", f"/?token={TOKEN}")
    assert status == 302 and headers["location"] == "/"
    cookie = headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
    assert TOKEN not in cookie and TOKEN not in headers["location"]
    assert headers["referrer-policy"] == "no-referrer"
    status, _, body = raw.call("GET", "/", headers={"Cookie": cookie.split(";")[0]})
    assert status == 200 and b"/ui/js/main.js" in body
    assert (
        raw.call("GET", "/api/investigations", headers={"Cookie": cookie.split(";")[0]})[0] == 200
    )


def test_wrong_token_rejected(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    status, headers, body = raw.call("GET", "/?token=nope")
    assert status == 401 and b"That token is not right." in body and "set-cookie" not in headers


def test_login_form(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    status, headers, _ = raw.call("POST", "/login", urlencode({"token": TOKEN}).encode(), form)
    assert (
        status == 303 and headers["location"] == "/" and "rehub_session=" in headers["set-cookie"]
    )
    status, _, body = raw.call("POST", "/login", urlencode({"token": "bad"}).encode(), form)
    assert status == 401 and b"not right" in body


def test_login_rejects_cross_origin_posts(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    form = {"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://evil.example"}
    assert raw.call("POST", "/login", urlencode({"token": TOKEN}).encode(), form)[0] == 403
    form = {"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "cross-site"}
    assert raw.call("POST", "/login", urlencode({"token": TOKEN}).encode(), form)[0] == 403


def test_repeated_failures_lock_out_even_the_right_token(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    for _ in range(MAX_FAILURES):
        assert raw.call("GET", "/?token=guess")[0] == 401
    status, _, body = raw.call("GET", f"/?token={TOKEN}")
    assert status == 429 and b"Too many attempts" in body


def test_forged_and_foreign_cookies_rejected(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    for cookie in (
        "rehub_session=1.abc",
        "rehub_session=",
        "rehub_session=9999999999.deadbeef",
        "other=1",
    ):
        assert raw.call("GET", "/api/investigations", headers={"Cookie": cookie})[0] == 401


def test_bearer_token_for_scripts(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    good = {"Authorization": f"Bearer {TOKEN}"}
    assert raw.call("GET", "/api/investigations", headers=good)[0] == 200
    assert raw.call("POST", "/api/investigations", headers=good)[0] == 201
    assert (
        raw.call("GET", "/api/investigations", headers={"Authorization": "Bearer wrong"})[0] == 401
    )
    assert raw.call("GET", "/api/investigations", headers={"Authorization": TOKEN})[0] == 401


def test_cookie_requests_still_need_csrf_header(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    cookie = {"Cookie": sign_in(raw)}
    assert raw.call("POST", "/api/investigations", headers=cookie)[0] == 403
    assert raw.call("POST", "/api/investigations", headers={**cookie, "X-Rehub": "1"})[0] == 201
    evil = {**cookie, "X-Rehub": "1", "Origin": "https://evil.example"}
    assert raw.call("POST", "/api/investigations", headers=evil)[0] == 403


def test_host_allowlist_applies_before_auth(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    headers = {"Cookie": sign_in(raw), "Host": "evil.example.com"}
    assert raw.call("GET", "/api/investigations", headers=headers)[0] == 403


def test_logout_clears_cookie(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    cookie = {"Cookie": sign_in(raw), "X-Rehub": "1"}
    status, headers, _ = raw.call("POST", "/api/logout", headers=cookie)
    assert status == 200 and "Max-Age=0" in headers["set-cookie"]


def test_auth_can_be_disabled_explicitly(tmp_path: Path) -> None:
    app = App(Config(data_dir=tmp_path / "d", port=0, token=""), FixtureExecutor())
    server = make_server(app)
    threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True).start()
    try:
        assert Raw(server.server_port).call("GET", "/api/investigations")[0] == 200
    finally:
        server.shutdown()
        server.server_close()
        app.shutdown()


def test_access_url_includes_token_and_translates_wildcard_host() -> None:
    config = Config(data_dir=Path("."), host="0.0.0.0", port=8080, token="abc")
    assert access_url(config) == "http://localhost:8080/?token=abc"
    config.public_url = "http://localhost:9000"
    assert access_url(config) == "http://localhost:9000/?token=abc"
    config.token = ""
    assert access_url(config) == "http://localhost:9000"


def test_sign_in_is_off_by_default_and_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("REHUB_TOKEN", "REHUB_AUTH", "REHUB_NO_AUTH"):
        monkeypatch.delenv(name, raising=False)
    assert Config.from_env(tmp_path).token == ""
    monkeypatch.setenv("REHUB_AUTH", "1")
    first = Config.from_env(tmp_path)
    assert first.token and Config.from_env(tmp_path).token == first.token
    monkeypatch.delenv("REHUB_AUTH")
    monkeypatch.setenv("REHUB_TOKEN", "explicit")
    assert Config.from_env(tmp_path).token == "explicit"


def test_token_never_logged_in_json_errors(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    _, _, body = raw.call("GET", "/api/investigations")
    assert TOKEN not in body.decode()


def test_doctor_endpoint_requires_login_and_reports(web: tuple[Raw, Config]) -> None:
    raw, _ = web
    assert raw.call("GET", "/api/doctor")[0] == 401
    status, _, body = raw.call("GET", "/api/doctor", headers={"Authorization": f"Bearer {TOKEN}"})
    data = json.loads(body)
    assert status == 200 and data["status"] in ("ok", "warn", "fail")
    assert {c["id"] for c in data["checks"]} >= {"data", "zeek", "suricata", "tshark", "auth"}
    assert raw.call("GET", "/api/health")[2] == b'{"ok": true, "auth": true}'
