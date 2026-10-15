import codecs
import gzip
import hashlib
import json
import re
from pathlib import Path

from rehub.schema import EvidenceKind

PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"),
}
PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")
GZIP_MAGIC = bytes.fromhex("1f8b")
JSON_KEY = re.compile(r'"([^"\\]+)"\s*:')
HEAD_BYTES = 8192
SYSLOG_LINE = re.compile(r"^(<\d{1,3}>|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s)")
XML_START = re.compile(r"<[?!A-Za-z]")
ZEEK_JSON_KEYS = {"uid", "id.orig_h", "ts_delta", "peer", "_path"}
IP_HEADERS = {"ip", "ip_address", "ipaddress", "ip address"}
ASSET_HEADERS = {"mac", "mac_address", "macaddress", "hostname", "host", "vendor", "role", "device"}
TIME_HEADERS = {"timestamp", "time", "datetime", "ts", "date"}
HISTORIAN_HEADERS = {
    "tag",
    "tagname",
    "tag_name",
    "point",
    "pointname",
    "value",
    "alarm",
    "message",
    "description",
}
ST_KEYWORDS = re.compile(r"\b(PROGRAM|FUNCTION_BLOCK|FUNCTION)\b", re.IGNORECASE)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def read_head(path: Path) -> bytes:
    with path.open("rb") as fh:
        head = fh.read(HEAD_BYTES)
    if head[:2] != GZIP_MAGIC:
        return head
    with gzip.open(path, "rb") as gz:
        return gz.read(HEAD_BYTES)


def is_gzip(path: Path) -> bool:
    with path.open("rb") as fh:
        return fh.read(2) == GZIP_MAGIC


def sniff(path: Path, name: str | None = None) -> EvidenceKind:
    try:
        head = read_head(path)
    except (OSError, EOFError):
        return EvidenceKind.UNKNOWN
    if head[:4] in PCAP_MAGICS or head[:4] == PCAPNG_MAGIC:
        return EvidenceKind.PCAP
    text = _decode(head)
    if text is None:
        return EvidenceKind.UNKNOWN
    return _sniff_text(text, _inner_suffix(Path(name) if name else path))


def _decode(head: bytes) -> str | None:
    if head[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        return head.decode("utf-16", errors="ignore")
    if b"\x00" in head:
        return None
    return head.decode("utf-8-sig", errors="ignore")


def _inner_suffix(path: Path) -> str:
    suffixes = [s.lower() for s in path.suffixes]
    if suffixes and suffixes[-1] == ".gz":
        suffixes = suffixes[:-1]
    return suffixes[-1] if suffixes else ""


def _sniff_text(text: str, suffix: str) -> EvidenceKind:
    stripped = text.lstrip()
    if XML_START.match(stripped):
        return _sniff_xml(stripped)
    first = stripped.splitlines()[0] if stripped else ""
    if first.startswith("#separator"):
        return EvidenceKind.ZEEK_LOG
    if first.startswith(("{", "[")):
        return _sniff_json(first, stripped)
    if suffix == ".st" and ST_KEYWORDS.search(text):
        return EvidenceKind.PLC_ST
    if SYSLOG_LINE.match(first):
        return EvidenceKind.SYSLOG
    return _sniff_delimited(first, suffix)


def _sniff_delimited(first: str, suffix: str) -> EvidenceKind:
    delim = next((d for d in (",", ";", "\t") if first.count(d) >= 1), None)
    if delim is None:
        return EvidenceKind.CSV if suffix == ".csv" else EvidenceKind.UNKNOWN
    headers = {h.strip().strip('"').lower() for h in first.split(delim)}
    if headers & IP_HEADERS and headers & ASSET_HEADERS:
        return EvidenceKind.CSV_ASSETS
    if headers & TIME_HEADERS and headers & HISTORIAN_HEADERS:
        return EvidenceKind.CSV_HISTORIAN
    return EvidenceKind.CSV if suffix == ".csv" else EvidenceKind.UNKNOWN


def _sniff_xml(text: str) -> EvidenceKind:
    head = text[:2048]
    if "<RSLogix5000Content" in head:
        return EvidenceKind.PLC_L5X
    if "plcopen.org" in head and "<project" in head:
        return EvidenceKind.PLC_PLCOPEN
    return EvidenceKind.UNKNOWN


def _json_keys(first_line: str) -> set[str]:
    try:
        obj = json.loads(first_line)
    except json.JSONDecodeError:
        return set(JSON_KEY.findall(first_line))
    return set(obj) if isinstance(obj, dict) else set()


def _sniff_json(first_line: str, text: str) -> EvidenceKind:
    keys = _json_keys(first_line)
    if "event_type" in keys and "timestamp" in keys:
        return EvidenceKind.SURICATA_EVE
    if "ts" in keys and keys & ZEEK_JSON_KEYS:
        return EvidenceKind.ZEEK_LOG
    if "index" in keys and "_index" in first_line:
        return EvidenceKind.TSHARK_JSON
    if "timestamp" in keys and "layers" in keys:
        return EvidenceKind.TSHARK_JSON
    if text.startswith("[") and '"_source"' in text[:4096] and '"layers"' in text[:4096]:
        return EvidenceKind.TSHARK_JSON
    return EvidenceKind.UNKNOWN
