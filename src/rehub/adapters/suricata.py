import json
from collections.abc import Iterable, Iterator
from typing import Any

from rehub.adapters.base import SourceFile, iso_to_epoch
from rehub.communityid import community_id
from rehub.schema import Event, EventKind

SEVERITY = {1: "high", 2: "medium", 3: "low"}
HEALTH_KEYS = ("capture.kernel_drops", "decoder.invalid", "flow.memcap")


def _flat(prefix: str, value: Any, out: dict[str, str]) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _flat(f"{prefix}.{k}" if prefix else k, v, out)
    elif value is not None:
        out[prefix] = str(value)


def _flow_key(obj: dict[str, Any]) -> str | None:
    if obj.get("community_id"):
        return str(obj["community_id"])
    try:
        return community_id(
            str(obj["src_ip"]),
            str(obj["dest_ip"]),
            int(obj["src_port"]),
            int(obj["dest_port"]),
            str(obj["proto"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _event(source: SourceFile, lineno: int, obj: dict[str, Any]) -> Event | None:
    kind = obj.get("event_type")
    ts = iso_to_epoch(obj["timestamp"]) if "timestamp" in obj else None
    common: dict[str, Any] = {
        "ts": ts,
        "tool": "suricata",
        "evidence_id": source.evidence_id,
        "ref": f"{source.name}:L{lineno}",
    }
    if kind == "stats":
        stats: dict[str, str] = {}
        _flat("", obj.get("stats", {}), stats)
        health = {k: stats[k] for k in HEALTH_KEYS if k in stats}
        drops = sum(int(v) for v in health.values() if v.isdigit())
        return Event(
            kind=EventKind.HEALTH,
            summary=f"suricata drops={drops}",
            severity="medium" if drops else None,
            attrs=health,
            **common,
        )
    if kind not in ("alert", "flow", "anomaly"):
        return None
    attrs: dict[str, str] = {}
    if kind == "alert":
        a = obj["alert"]
        attrs.update(
            sid=str(a.get("signature_id")),
            category=str(a.get("category", "")),
            signature=str(a.get("signature", "")),
            app_proto=str(obj.get("app_proto", "")),
        )
        for proto in ("modbus", "enip", "dnp3"):
            if proto in obj:
                _flat(proto, obj[proto], attrs)
        summary = str(a.get("signature", "alert"))
        severity = SEVERITY.get(a.get("severity", 3), "low")
        ev_kind = EventKind.ALERT
    elif kind == "anomaly":
        _flat("anomaly", obj.get("anomaly", {}), attrs)
        summary = f"anomaly {obj.get('anomaly', {}).get('event', '')}".strip()
        severity, ev_kind = "low", EventKind.ALERT
    else:
        f = obj.get("flow", {})
        attrs.update(
            pkts_toserver=str(f.get("pkts_toserver", "")),
            pkts_toclient=str(f.get("pkts_toclient", "")),
            state=str(f.get("state", "")),
            app_proto=str(obj.get("app_proto", "")),
        )
        summary = f"{obj.get('app_proto', obj.get('proto', 'flow'))} {f.get('state', '')}".strip()
        severity, ev_kind = None, EventKind.FLOW
    return Event(
        kind=ev_kind,
        src=obj.get("src_ip"),
        dst=obj.get("dest_ip"),
        sport=obj.get("src_port"),
        dport=obj.get("dest_port"),
        proto=str(obj.get("proto", "")).lower() or None,
        flow_key=_flow_key(obj),
        severity=severity,
        summary=summary,
        attrs=attrs,
        **common,
    )


def parse_suricata(sources: Iterable[SourceFile]) -> Iterator[Event]:
    for source in sources:
        with source.path.open(encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event = _event(source, lineno, obj)
                if event is not None:
                    yield event
