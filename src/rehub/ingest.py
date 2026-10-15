import gzip
import hashlib
import os
import tarfile
import tempfile
import zipfile
import zlib
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Protocol

from rehub.schema import Evidence
from rehub.sniff import PCAP_MAGICS, PCAPNG_MAGIC, is_gzip, read_head, sha256_file, sniff

CHUNK = 1 << 20
ZIP_SYMLINK = 0o120000
ZIP_TYPE_MASK = 0o170000


class IngestError(Exception):
    pass


class _Readable(Protocol):
    def read(self, size: int = ..., /) -> bytes: ...


@dataclass(frozen=True, slots=True)
class Limits:
    max_files: int = 5000
    max_total_bytes: int = 16 << 30


class _Budget:
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.files = 0
        self.total = 0

    def add_file(self) -> None:
        self.files += 1
        if self.files > self.limits.max_files:
            raise IngestError(f"archive exceeds {self.limits.max_files} files")

    def add_bytes(self, n: int) -> None:
        self.total += n
        if self.total > self.limits.max_total_bytes:
            raise IngestError(f"upload exceeds {self.limits.max_total_bytes} bytes expanded")


def blob_path(store: Path, sha256: str) -> Path:
    return store / sha256[:2] / sha256


def ingest(path: Path, store: Path, limits: Limits | None = None) -> list[Evidence]:
    budget = _Budget(limits or Limits())
    try:
        origin_sha = sha256_file(path)
        return [replace(ev, origin_sha256=origin_sha) for ev in _ingest(path, store, budget)]
    except (
        zipfile.BadZipFile,
        tarfile.TarError,
        gzip.BadGzipFile,
        EOFError,
        zlib.error,
        NotImplementedError,
        RuntimeError,
    ) as exc:
        raise IngestError(f"corrupt upload {path.name}: {exc}") from exc


def _is_tar(path: Path) -> bool:
    return read_head(path)[257:262] == b"ustar"


def _ingest_zip(path: Path, store: Path, budget: _Budget) -> list[Evidence]:
    out: list[Evidence] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir() or (info.external_attr >> 16) & ZIP_TYPE_MASK == ZIP_SYMLINK:
                continue
            with zf.open(info) as src:
                out.append(_store(src, info.filename, path.name, store, budget, False))
    return out


def _ingest_tar(path: Path, store: Path, budget: _Budget) -> list[Evidence]:
    out: list[Evidence] = []
    with tarfile.open(path) as tf:
        for member in tf:
            if not member.isfile():
                continue
            src = tf.extractfile(member)
            if src is None:
                continue
            with src:
                out.append(_store(src, member.name, path.name, store, budget, False))
    return out


def _starts_with_pcap_magic(path: Path) -> bool:
    with path.open("rb") as fh:
        magic = fh.read(4)
    return magic in PCAP_MAGICS or magic == PCAPNG_MAGIC


def _ingest(path: Path, store: Path, budget: _Budget) -> list[Evidence]:
    if _starts_with_pcap_magic(path):
        with path.open("rb") as src:
            return [_store(src, path.name, path.name, store, budget, False)]
    if zipfile.is_zipfile(path):
        return _ingest_zip(path, store, budget)
    if _is_tar(path):
        return _ingest_tar(path, store, budget)
    if is_gzip(path):
        name = path.name.removesuffix(".gz").removesuffix(".GZ")
        with gzip.open(path, "rb") as gz:
            return [_store(gz, name, path.name, store, budget, True)]
    with path.open("rb") as src:
        return [_store(src, path.name, path.name, store, budget, False)]


def _clean_name(name: str) -> str:
    parts = [p for p in PurePosixPath(name).parts if p not in ("/", "..", ".")]
    return "/".join(parts) or "unnamed"


def _store(
    src: _Readable, name: str, origin: str, store: Path, budget: _Budget, compressed: bool
) -> Evidence:
    budget.add_file()
    store.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    fd, tmp = tempfile.mkstemp(dir=store, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as out:
            while chunk := src.read(CHUNK):
                budget.add_bytes(len(chunk))
                digest.update(chunk)
                out.write(chunk)
                size += len(chunk)
        sha = digest.hexdigest()
        dest = blob_path(store, sha)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            Path(tmp).unlink()
        else:
            os.replace(tmp, dest)
            dest.chmod(0o444)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    clean = _clean_name(name)
    return Evidence(sha, clean, size, sniff(dest, clean), compressed, origin)
