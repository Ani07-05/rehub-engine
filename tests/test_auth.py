import os
import stat
from pathlib import Path

import pytest

from rehub.auth import (
    COOKIE_TTL,
    MAX_FAILURES,
    TOKEN_FILE,
    Auth,
    cookie_header,
    load_or_create_token,
    parse_cookie,
)


def test_token_created_once_with_private_permissions(tmp_path: Path) -> None:
    token = load_or_create_token(tmp_path)
    assert len(token) >= 40
    path = tmp_path / TOKEN_FILE
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_or_create_token(tmp_path) == token


def test_rotation_replaces_token(tmp_path: Path) -> None:
    first = load_or_create_token(tmp_path)
    second = load_or_create_token(tmp_path, rotate=True)
    assert first != second
    assert load_or_create_token(tmp_path) == second


def test_env_token_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REHUB_TOKEN", "from-env")
    assert load_or_create_token(tmp_path) == "from-env"
    assert not (tmp_path / TOKEN_FILE).exists()


def test_token_check_is_exact() -> None:
    auth = Auth("s3cret")
    assert auth.check_token("s3cret") and auth.check_token(" s3cret\n")
    assert (
        not auth.check_token("s3cre")
        and not auth.check_token("")
        and not auth.check_token("S3CRET")
    )


def test_cookie_round_trip_and_expiry() -> None:
    auth = Auth("tok")
    cookie = auth.make_cookie(now=1000)
    assert auth.valid_cookie(cookie, now=1000 + COOKIE_TTL - 1)
    assert not auth.valid_cookie(cookie, now=1000 + COOKIE_TTL + 1)


def test_cookie_forgery_and_other_tokens_rejected() -> None:
    auth = Auth("tok")
    cookie = auth.make_cookie(now=1000)
    expiry, _, mac = cookie.partition(".")
    assert not auth.valid_cookie(f"{int(expiry) + 99999}.{mac}", now=1000)
    assert not auth.valid_cookie(f"{expiry}.{'0' * len(mac)}", now=1000)
    assert not Auth("other").valid_cookie(cookie, now=1000)
    for junk in ("", "abc", ".", "1.", ".x", "x.y"):
        assert not auth.valid_cookie(junk, now=1000)


def test_disabled_auth_allows_everything() -> None:
    auth = Auth("")
    assert not auth.enabled and auth.check_token("x") and auth.valid_cookie("")


def test_lockout_after_repeated_failures_and_recovery() -> None:
    auth = Auth("tok")
    for i in range(MAX_FAILURES):
        assert not auth.locked_out(now=100 + i)
        auth.record_failure(now=100 + i)
    assert auth.locked_out(now=110)
    assert not auth.locked_out(now=100 + 61 + MAX_FAILURES)


def test_cookie_header_flags() -> None:
    header = cookie_header("v")
    assert "HttpOnly" in header and "SameSite=Strict" in header and "Path=/" in header
    assert "Domain" not in header
    assert parse_cookie("a=1; rehub_session=v; b=2") == "v"
    assert parse_cookie(None) == "" and parse_cookie("a=1") == ""


def test_secret_not_in_env_of_tests() -> None:
    assert "REHUB_TOKEN" not in os.environ
