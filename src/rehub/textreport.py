from datetime import UTC, datetime

from rehub.correlate import ATTACK_NOTE
from rehub.model import Detection
from rehub.pipeline import Record


def _ts(value: float | None) -> str:
    if value is None:
        return "-"
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M:%S")


def _detection(d: Detection) -> list[str]:
    tools = "+".join(sorted(d.tools))
    flag = " corroborated" if d.corroborated else ""
    lines = [f"  [{d.severity or 'info'}] {d.title}  ({tools}{flag})"]
    if d.src or d.dst:
        lines.append(f"      {d.src or '?'} -> {d.dst or '?'}  x{d.count}  first {_ts(d.first_ts)}")
    if d.attack:
        lines.append(f"      ATT&CK candidates: {', '.join(d.attack)}")
    for impact in d.plc:
        values = f" = {impact.new_values}" if impact.new_values else ""
        where = f"{impact.variable} ({impact.address}, {impact.dtype})"
        lines.append(f"      PLC {impact.project}: {where}{values}")
        if impact.drives:
            lines.append(f"        drives: {', '.join(impact.drives)}")
        for reader in impact.readers[:3]:
            lines.append(f"        read at {reader}")
        lines.append(f"        note: {impact.assumption}")
    return lines


def render_text(record: Record) -> str:
    inv = record.investigation
    out = [f"Investigation {record.id}  created {record.created}", ""]
    out.append(f"Evidence ({len(record.evidence)})")
    for e in record.evidence:
        derived = f"  <- {e.origin}" if e.origin and e.origin != e.name else ""
        out.append(f"  {e.sha256[:12]}  {e.kind.value:14} {e.size:>9}  {e.name}{derived}")
    if record.tool_runs:
        out += ["", "Tool runs"]
        for r in record.tool_runs:
            status = "ok" if r.ok else f"FAILED: {r.error}"
            out.append(f"  {r.tool:9} {status}  ({r.seconds:.1f}s)")
    out += ["", f"Assets ({len(inv.assets)})"]
    for a in inv.assets.values():
        vendor = a.vendor or (
            "locally administered MAC" if a.locally_administered_mac else "unknown vendor"
        )
        plc = f"  PLC project: {', '.join(sorted(a.plc_projects))}" if a.plc_projects else ""
        out.append(f"  {a.id:16} {a.kind:10} {vendor}{plc}")
    out += ["", f"Flows ({len(inv.flows)})"]
    for f in inv.flows.values():
        out.append(
            f"  {f.src}:{f.sport} -> {f.dst}:{f.dport}  {f.proto}  {f.service or '-'}  "
            f"{f.packets} pkts  [{', '.join(sorted(f.tools))}]"
        )
    out += ["", f"Detections ({len(inv.detections)})"]
    for d in inv.detections:
        out += _detection(d)
    if any(d.attack for d in inv.detections):
        out += ["", f"Note: {ATTACK_NOTE}"]
    notes = [*inv.caveats, *record.warnings]
    if notes:
        out += ["", "Caveats and warnings"]
        out += [f"  - {n}" for n in notes]
    return "\n".join(out) + "\n"
