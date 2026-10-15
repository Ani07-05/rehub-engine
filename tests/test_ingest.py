import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from rehub.ingest import IngestError, Limits, blob_path, ingest
from rehub.schema import EvidenceKind
from rehub.sniff import sha256_file

PCAP = bytes.fromhex("d4c3b2a1") + b"\x00" * 32
ZEEK = b"#separator \\x09\n#fields\tts\tuid\n"


def test_plain_file(tmp_path: Path) -> None:
    src = tmp_path / "cap.pcap"
    src.write_bytes(PCAP)
    store = tmp_path / "store"
    [ev] = ingest(src, store)
    assert ev.kind == EvidenceKind.PCAP
    assert ev.size == len(PCAP)
    assert blob_path(store, ev.sha256).read_bytes() == PCAP
    assert not blob_path(store, ev.sha256).stat().st_mode & 0o222


def test_gzip_unwrapped(tmp_path: Path) -> None:
    src = tmp_path / "cap.pcap.gz"
    src.write_bytes(gzip.compress(PCAP))
    [ev] = ingest(src, tmp_path / "store")
    assert ev.kind == EvidenceKind.PCAP
    assert ev.compressed
    assert ev.name == "cap.pcap"
    assert ev.origin == "cap.pcap.gz"


def test_zip_bundle(tmp_path: Path) -> None:
    src = tmp_path / "bundle.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("net/cap.pcap", PCAP)
        zf.writestr("logs/conn.log", ZEEK)
        zf.writestr("empty/", b"")
    evs = ingest(src, tmp_path / "store")
    assert {(e.name, e.kind) for e in evs} == {
        ("net/cap.pcap", EvidenceKind.PCAP),
        ("logs/conn.log", EvidenceKind.ZEEK_LOG),
    }
    assert all(e.origin == "bundle.zip" for e in evs)


def test_tar_gz_skips_symlinks(tmp_path: Path) -> None:
    src = tmp_path / "bundle.tar.gz"
    with tarfile.open(src, "w:gz") as tf:
        info = tarfile.TarInfo("cap.pcap")
        info.size = len(PCAP)
        tf.addfile(info, io.BytesIO(PCAP))
        link = tarfile.TarInfo("evil")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    evs = ingest(src, tmp_path / "store")
    assert [e.name for e in evs] == ["cap.pcap"]


def test_traversal_names_neutralised(tmp_path: Path) -> None:
    src = tmp_path / "bundle.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("../../etc/x.pcap", PCAP)
    store = tmp_path / "store"
    [ev] = ingest(src, store)
    assert ev.name == "etc/x.pcap"
    assert not (tmp_path.parent / "etc").exists()
    assert blob_path(store, ev.sha256).is_relative_to(store)


def test_dedupe_same_content(tmp_path: Path) -> None:
    a = tmp_path / "a.pcap"
    b = tmp_path / "b.pcap"
    a.write_bytes(PCAP)
    b.write_bytes(PCAP)
    store = tmp_path / "store"
    [ea] = ingest(a, store)
    [eb] = ingest(b, store)
    assert ea.sha256 == eb.sha256
    assert len(list(store.rglob("*"))) == 2


def test_file_limit(tmp_path: Path) -> None:
    src = tmp_path / "bundle.zip"
    with zipfile.ZipFile(src, "w") as zf:
        for i in range(3):
            zf.writestr(f"f{i}.txt", b"x")
    with pytest.raises(IngestError, match="files"):
        ingest(src, tmp_path / "store", Limits(max_files=2))


def test_expansion_limit_stops_bomb(tmp_path: Path) -> None:
    src = tmp_path / "bomb.gz"
    src.write_bytes(gzip.compress(b"\x00" * 1_000_000))
    store = tmp_path / "store"
    with pytest.raises(IngestError, match="expanded"):
        ingest(src, store, Limits(max_total_bytes=1000))
    assert not list(store.rglob(".tmp-*"))


def test_corrupt_gzip(tmp_path: Path) -> None:
    src = tmp_path / "bad.gz"
    src.write_bytes(gzip.compress(PCAP)[:-8])
    with pytest.raises(IngestError, match="corrupt"):
        ingest(src, tmp_path / "store")


def test_nested_archive_not_recursed(tmp_path: Path) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("cap.pcap", PCAP)
    src = tmp_path / "outer.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())
    [ev] = ingest(src, tmp_path / "store")
    assert ev.kind == EvidenceKind.UNKNOWN


def test_origin_hash_is_upload_hash(tmp_path: Path) -> None:
    src = tmp_path / "bundle.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("a.pcap", PCAP)
        zf.writestr("b.log", ZEEK)
    evs = ingest(src, tmp_path / "store")
    assert {e.origin_sha256 for e in evs} == {sha256_file(src)}
    assert len({e.sha256 for e in evs}) == 2


def test_pcap_with_trailing_zip_stays_pcap(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("x", b"y")
    src = tmp_path / "poly.pcap"
    src.write_bytes(PCAP + buf.getvalue())
    [ev] = ingest(src, tmp_path / "store")
    assert ev.kind == EvidenceKind.PCAP
    assert ev.name == "poly.pcap"


def test_encrypted_zip_raises_ingest_error(tmp_path: Path) -> None:
    src = tmp_path / "enc.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("a.pcap", PCAP)
    raw = bytearray(src.read_bytes())
    flag = raw.find(b"PK\x01\x02") + 8
    raw[flag] |= 0x01
    flag_local = raw.find(b"PK\x03\x04") + 6
    raw[flag_local] |= 0x01
    src.write_bytes(bytes(raw))
    with pytest.raises(IngestError):
        ingest(src, tmp_path / "store")
