from itertools import islice
from pathlib import Path
from typing import Any

from rehub.adapters.tshark import iter_packets
from rehub.ingest import blob_path
from rehub.pipeline import Record, investigation_dir
from rehub.schema import Evidence, EvidenceKind

MAX_LINE_CHARS = 4000
MAX_LINES = 200
TEXT_PROBE = 8192


def find_evidence(record: Record, sha256: str) -> Evidence | None:
    return next((e for e in record.evidence if e.sha256 == sha256), None)


def evidence_path(data_dir: Path, record: Record, sha256: str) -> Path | None:
    ev = find_evidence(record, sha256)
    if ev is None:
        return None
    stored = blob_path(data_dir / "store", sha256)
    if stored.is_file():
        return stored
    derived = investigation_dir(data_dir, record.id) / "runs" / ev.origin_sha256[:12] / ev.name
    root = (investigation_dir(data_dir, record.id) / "runs").resolve()
    resolved = derived.resolve()
    if resolved.is_file() and resolved.is_relative_to(root):
        return resolved
    return None


def flow_packets(
    data_dir: Path, record: Record, flow_key: str, limit: int
) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    for ev in record.evidence:
        if ev.kind != EvidenceKind.TSHARK_TSV:
            continue
        path = evidence_path(data_dir, record, ev.sha256)
        if path is None:
            continue
        for pkt in iter_packets(path):
            if pkt.key != flow_key:
                continue
            if len(rows) >= limit:
                return rows, True
            rows.append(
                {
                    "frame": pkt.frame,
                    "ts": pkt.ts,
                    "src": pkt.src,
                    "dst": pkt.dst,
                    "sport": pkt.sport,
                    "dport": pkt.dport,
                    "protocol": pkt.protocol,
                    "info": pkt.info,
                    "evidence": ev.sha256,
                }
            )
    return rows, False


def is_text(path: Path) -> bool:
    with path.open("rb") as fh:
        return b"\x00" not in fh.read(TEXT_PROBE)


def read_lines(path: Path, start: int, count: int) -> dict[str, Any]:
    count = max(1, min(count, MAX_LINES))
    start = max(1, start)
    with path.open(encoding="utf-8", errors="replace") as fh:
        window = list(islice(fh, start - 1, start - 1 + count))
    return {
        "start": start,
        "lines": [ln.rstrip("\n")[:MAX_LINE_CHARS] for ln in window],
    }
