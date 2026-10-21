from dataclasses import fields, is_dataclass
from typing import Any

from rehub.model import (
    Asset,
    Detection,
    EvidenceRef,
    Flow,
    Investigation,
    ModbusWrite,
    PlcImpact,
    Source,
)
from rehub.schema import Evidence, EvidenceKind

COMPUTED = {
    "Detection": ("tools", "rules", "corroborated"),
    "Asset": ("kind",),
    "ModbusWrite": ("count",),
}


def to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        out = {f.name: to_jsonable(getattr(obj, f.name)) for f in fields(obj)}
        for name in COMPUTED.get(type(obj).__name__, ()):
            out[name] = to_jsonable(getattr(obj, name))
        return out
    if isinstance(obj, (set, frozenset)):
        return sorted(to_jsonable(v) for v in obj)
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, EvidenceKind):
        return obj.value
    return obj


def _refs(items: list[dict[str, Any]]) -> list[EvidenceRef]:
    return [EvidenceRef(**i) for i in items]


def asset_from_dict(d: dict[str, Any]) -> Asset:
    return Asset(
        id=d["id"],
        ips=set(d["ips"]),
        macs=dict(d["macs"]),
        vendor=d["vendor"],
        locally_administered_mac=d["locally_administered_mac"],
        roles=set(d["roles"]),
        first_ts=d["first_ts"],
        last_ts=d["last_ts"],
        tools=set(d["tools"]),
        plc_projects=set(d["plc_projects"]),
    )


def flow_from_dict(d: dict[str, Any]) -> Flow:
    return Flow(**{**d, "tools": set(d["tools"]), "refs": _refs(d["refs"])})


def detection_from_dict(d: dict[str, Any]) -> Detection:
    base = {k: v for k, v in d.items() if k not in COMPUTED["Detection"]}
    return Detection(
        **{
            **base,
            "sources": [Source(**s) for s in d["sources"]],
            "plc": [PlcImpact(**i) for i in d["plc"]],
            "writes": [
                ModbusWrite(**{k: v for k, v in w.items() if k not in COMPUTED["ModbusWrite"]})
                for w in d.get("writes", [])
            ],
            "refs": _refs(d["refs"]),
        }
    )


def investigation_from_dict(d: dict[str, Any]) -> Investigation:
    return Investigation(
        assets={k: asset_from_dict(v) for k, v in d["assets"].items()},
        flows={k: flow_from_dict(v) for k, v in d["flows"].items()},
        detections=[detection_from_dict(x) for x in d["detections"]],
        caveats=list(d["caveats"]),
        event_count=d["event_count"],
    )


def evidence_from_dict(d: dict[str, Any]) -> Evidence:
    return Evidence(**{**d, "kind": EvidenceKind(d["kind"])})
