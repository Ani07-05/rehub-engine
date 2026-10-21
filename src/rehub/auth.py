import hashlib
import hmac
import os
import secrets
import threading
import time
from pathlib import Path

COOKIE_NAME = "rehub_session"
COOKIE_TTL = 12 * 3600
TOKEN_FILE = ".token"
MAX_FAILURES = 5
FAILURE_WINDOW = 60.0


def load_or_create_token(data_dir: Path, rotate: bool = False) -> str:
    env = os.environ.get("REHUB_TOKEN", "").strip()
    if env:
        return env
    path = data_dir / TOKEN_FILE
    if path.is_file() and not rotate:
        existing = path.read_text().strip()
        if existing:
            return existing
    data_dir.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token + "\n")
    tmp.replace(path)
    path.chmod(0o600)
    return token


class Auth:
    def __init__(self, token: str) -> None:
        self.enabled = bool(token)
        self._token = token.encode()
        self._key = hashlib.sha256(b"rehub-session-v1|" + self._token).digest()
        self._failures: list[float] = []
        self._lock = threading.Lock()

    def check_token(self, candidate: str) -> bool:
        if not self.enabled:
            return True
        return hmac.compare_digest(candidate.strip().encode(), self._token)

    def _sign(self, expiry: int) -> str:
        return hmac.new(self._key, str(expiry).encode(), hashlib.sha256).hexdigest()

    def make_cookie(self, now: float | None = None) -> str:
        expiry = int((now if now is not None else time.time()) + COOKIE_TTL)
        return f"{expiry}.{self._sign(expiry)}"

    def valid_cookie(self, value: str, now: float | None = None) -> bool:
        if not self.enabled:
            return True
        expiry_text, _, mac = value.partition(".")
        if not expiry_text.isdigit() or not mac:
            return False
        if int(expiry_text) < (now if now is not None else time.time()):
            return False
        return hmac.compare_digest(mac, self._sign(int(expiry_text)))

    def locked_out(self, now: float | None = None) -> bool:
        current = now if now is not None else time.time()
        with self._lock:
            self._failures = [t for t in self._failures if current - t < FAILURE_WINDOW]
            return len(self._failures) >= MAX_FAILURES

    def record_failure(self, now: float | None = None) -> None:
        with self._lock:
            self._failures.append(now if now is not None else time.time())


def cookie_header(value: str, max_age: int = COOKIE_TTL) -> str:
    return f"{COOKIE_NAME}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}"


def parse_cookie(header: str | None, name: str = COOKIE_NAME) -> str:
    for part in (header or "").split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value
    return ""
