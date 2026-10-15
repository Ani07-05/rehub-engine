import hashlib
import json
from collections.abc import Iterable, Iterator
from typing import Any

from rehub.adapters.base import SourceFile
from rehub.communityid import community_id
from rehub.schema import Event, EventKind

SKIPPED_LOGS = frozenset({"packet_filter", "loaded_scripts", "stats", "reporter", "broker"})
NOTICE_SEVERITY = {"notice": "medium", "weird": "low"}
INT_TYPES = {"count", "int", "port"}
FLOAT_TYPES = {"time", "interval", "double"}
Row = dict[str, Any]


def _convert(value: str, typ: str, set_sep: str, unset: str, empty: str) -> Any:
    if value == unset:
        return None
    if typ.startswith(("vector[", "set[")):
        if value == empty:
            return []
        inner = typ[typ.index("[") + 1 : -1]
        return [_convert(v, inner, set_sep, unset, empty) for v in value.split(set_sep)]
    if value == empty:
        return ""
    try:
        if typ in INT_TYPES:
            return int(value)
        if typ in FLOAT_TYPES:
            return float(value)
    except ValueError:
        return value
    if typ == "bool":
        return value == "T"
    return value


def _tsv_rows(lines: Iterable[str]) -> Iterator[tuple[int, str, Row]]:
    sep, set_sep, unset, empty = "\t", ",", "-", "(empty)"
    path = ""
    fields: list[str] = []
    types: list[str] = []
    for lineno, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line:
            continue
        if line.startswith("#"):
            key, _, rest = line[1:].partition(sep if line.startswith("#fields") else "\t")
            if line.startswith("#separator"):
                sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
            elif key == "set_separator":
                set_sep = rest
            elif key == "empty_field":
                empty = rest
            elif key == "unset_field":
                unset = rest
            elif key == "path":
                path = rest
            elif key == "fields":
                fields = rest.split(sep)
            elif key == "types":
                types = rest.split(sep)
            continue
        cells = line.split(sep)
        row = {
            f: _convert(c, t, set_sep, unset, empty)
            for f, c, t in zip(fields, cells, types, strict=False)
        }
        yield lineno, path, row


def _json_rows(lines: Iterable[str], default_path: str) -> Iterator[tuple[int, str, Row]]:
    for lineno, line in enumerate(lines, 1):
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        yield lineno, str(row.get("_path", default_path)), row


def read_rows(source: SourceFile) -> Iterator[tuple[int, str, Row]]:
    with source.path.open(encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        if first.startswith("#separator"):
            yield from _tsv_rows(fh)
        else:
            yield from _json_rows(fh, source.stem)


def _flow_key(row: Row, proto_by_uid: dict[str, str]) -> tuple[str | None, bool]:
    if cid := row.get("community_id"):
        return str(cid), False
    uid = row.get("uid")
    known = proto_by_uid.get(str(uid)) if uid else None
    proto = known or row.get("proto") or "tcp"
    key = _compute(row, str(proto))
    return key, known is None and not row.get("proto")


def _compute(row: Row, proto: str) -> str | None:
    try:
        return community_id(
            str(row["id.orig_h"]),
            str(row["id.resp_h"]),
            int(row["id.orig_p"]),
            int(row["id.resp_p"]),
            proto,
        )
    except (KeyError, TypeError, ValueError):
        return None


def _summary(log: str, row: Row) -> str:
    if log == "conn":
        svc = row.get("service") or row.get("proto") or "conn"
        sent, recv = row.get("orig_bytes") or 0, row.get("resp_bytes") or 0
        return f"{svc} {sent}/{recv}B {row.get('conn_state')}"
    if log == "modbus":
        return f"{row.get('pdu_type')} {row.get('func')}"
    if log == "modbus_detailed":
        return f"{row.get('func')} addr={row.get('address')} qty={row.get('quantity')}"
    if log == "s7comm":
        return f"{row.get('rosctr_name')} {row.get('function_name')}"
    if log == "cotp":
        return str(row.get("pdu_name"))
    if log in NOTICE_SEVERITY:
        return str(row.get("msg") or row.get("name") or log)
    return log


def _attrs(row: Row) -> dict[str, str]:
    skip = {"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "community_id"}
    return {
        k: json.dumps(v) if not isinstance(v, str) else v
        for k, v in row.items()
        if k not in skip and v is not None
    }


def _severity(log: str, row: Row) -> str | None:
    if log == "capture_loss" and (row.get("percent_lost") or 0) > 0:
        return "medium"
    return NOTICE_SEVERITY.get(log)


def _kind(log: str) -> EventKind:
    if log == "conn":
        return EventKind.FLOW
    if log in NOTICE_SEVERITY:
        return EventKind.ALERT
    if log == "capture_loss":
        return EventKind.HEALTH
    return EventKind.PROTOCOL_ACTION


def _is_conn(source: SourceFile) -> bool:
    if source.stem == "conn":
        return True
    with source.path.open(encoding="utf-8", errors="replace") as fh:
        head = "".join(fh.readline() for _ in range(30))
    return "#path\tconn" in head or '"_path":"conn"' in head


def _conn_protos(sources: list[SourceFile]) -> dict[str, str]:
    protos: dict[str, str] = {}
    for source in sources:
        if not _is_conn(source):
            continue
        for _, log, row in read_rows(source):
            if log == "conn" and row.get("uid") and row.get("proto"):
                protos[str(row["uid"])] = str(row["proto"])
    return protos


def _digest(row: Row) -> bytes:
    raw = json.dumps(row, sort_keys=True).encode()
    return hashlib.blake2b(raw, digest_size=16).digest()


def parse_zeek(sources: Iterable[SourceFile]) -> Iterator[Event]:
    files = list(sources)
    proto_by_uid = _conn_protos(files)
    seen: set[bytes] = set()
    for source in files:
        for lineno, log, row in read_rows(source):
            if log in SKIPPED_LOGS:
                continue
            if log == "modbus_detailed":
                digest = _digest(row)
                if digest in seen:
                    continue
                seen.add(digest)
            key, assumed = _flow_key(row, proto_by_uid) if "id.orig_h" in row else (None, False)
            attrs = _attrs(row)
            if assumed:
                attrs["flow_key_assumed_tcp"] = "1"
            sport, dport = row.get("id.orig_p"), row.get("id.resp_p")
            yield Event(
                ts=float(row["ts"]) if row.get("ts") is not None else None,
                tool="zeek",
                kind=_kind(log),
                evidence_id=source.evidence_id,
                src=row.get("id.orig_h"),
                dst=row.get("id.resp_h"),
                sport=sport if isinstance(sport, int) else None,
                dport=dport if isinstance(dport, int) else None,
                proto=str(row["proto"]) if log == "conn" else log,
                flow_key=key,
                severity=_severity(log, row),
                summary=_summary(log, row),
                ref=f"{source.name}:L{lineno}",
                attrs=attrs,
            )
