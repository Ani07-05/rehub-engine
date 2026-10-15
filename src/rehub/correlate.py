import hashlib
from collections import defaultdict
from collections.abc import Iterable, Sequence

from rehub.model import (
    MAC_ARP,
    MAC_INFERRED,
    MAC_L2,
    SEVERITY_RANK,
    Asset,
    Detection,
    EvidenceRef,
    Flow,
    Investigation,
    Source,
)
from rehub.oui import OuiTable, is_locally_administered
from rehub.plc.link import modbus_impacts
from rehub.plc.model import PlcProject
from rehub.schema import Event, EventKind

OT_PORTS = {
    502: "modbus",
    102: "s7comm",
    44818: "enip",
    2222: "enip",
    20000: "dnp3",
    4840: "opcua",
    47808: "bacnet",
    2404: "iec104",
}
OT_PROTOCOLS = frozenset(OT_PORTS.values())
MODBUS_WRITE = ("WRITE_", "MASK_WRITE", "READ_WRITE_")
MODBUS_REGISTER_WRITE = ("REGISTER", "REGISTERS")
S7_CONTROL = {"stop": "high", "download": "high", "plc control": "high", "upload": "medium"}
REDUNDANCY_MAC_PREFIXES = ("00:00:5e:00:01", "00:00:5e:00:02", "00:00:0c:07:ac", "00:00:0c:9f:f")
MERGE_WINDOW = 1.0
REF_CAP = 25
MODBUS_REGISTER_FUNCS = frozenset({"6", "16", "22", "23"})
EXPECTED_TOOLS = ("zeek", "suricata", "tshark")
FLOW_PRIORITY = {"zeek": 0, "suricata": 1, "tshark": 2}

ATTACK_NOTE = (
    "ATT&CK for ICS techniques are candidates inferred from observed behavior. "
    "Whether a command was unauthorized depends on context a capture cannot show."
)
T_UNAUTH_COMMAND = "T0855 Unauthorized Command Message"
T_MODIFY_PARAMETER = "T0836 Modify Parameter"
T_CHANGE_MODE = "T0858 Change Operating Mode"


def _ref(ev: Event) -> EvidenceRef:
    return EvidenceRef(ev.evidence_id, ev.ref, ev.tool)


def _widen(obj: Flow | Detection | Asset, ts: float | None) -> None:
    if ts is None:
        return
    obj.first_ts = ts if obj.first_ts is None else min(obj.first_ts, ts)
    obj.last_ts = ts if obj.last_ts is None else max(obj.last_ts, ts)


def _asset(inv: Investigation, ident: str) -> Asset:
    asset = inv.assets.get(ident)
    if asset is None:
        asset = inv.assets[ident] = Asset(id=ident)
    return asset


def _build_flows(inv: Investigation, events: list[Event]) -> None:
    keyed = [e for e in events if e.flow_key]
    for ev in keyed:
        assert ev.flow_key
        flow = inv.flows.setdefault(ev.flow_key, Flow(key=ev.flow_key))
        flow.tools.add(ev.tool)
        _widen(flow, ev.ts)
        if len(flow.refs) < REF_CAP:
            flow.refs.append(_ref(ev))
        if ev.tool == "tshark":
            flow.packets += int(ev.attrs.get("packets", 0))
            first, last = ev.attrs.get("first_frame"), ev.attrs.get("last_frame")
            if first and last:
                lo, hi = int(first), int(last)
                flow.first_frame = lo if flow.first_frame is None else min(flow.first_frame, lo)
                flow.last_frame = hi if flow.last_frame is None else max(flow.last_frame, hi)
    shape = [e for e in keyed if e.kind in (EventKind.FLOW, EventKind.PACKET)]
    for ev in sorted(shape, key=lambda e: FLOW_PRIORITY.get(e.tool, 9)):
        assert ev.flow_key
        flow = inv.flows[ev.flow_key]
        if flow.src is None:
            flow.src, flow.dst = ev.src, ev.dst
            flow.sport, flow.dport = ev.sport, ev.dport
            flow.proto = ev.proto
    for ev in sorted(keyed, key=lambda e: FLOW_PRIORITY.get(e.tool, 9)):
        assert ev.flow_key
        flow = inv.flows[ev.flow_key]
        service = ev.attrs.get("service") or ev.attrs.get("app_proto")
        if service and not flow.service and ev.tool in ("zeek", "suricata"):
            flow.service = service


def _flow_protocol(flow: Flow) -> str | None:
    for token in (flow.service or "").replace(",", " ").split():
        if token in OT_PROTOCOLS:
            return token
    return OT_PORTS.get(flow.dport) if flow.dport is not None else None


def _pairs(events: list[Event], attr: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for ev in events:
        for pair in ev.attrs.get(attr, "").split(";"):
            ip, _, mac = pair.partition("=")
            if ip and mac:
                found.add((ip, mac.lower()))
    return found


def _attribute_macs(inv: Investigation, events: list[Event]) -> None:
    arp = _pairs(events, "arp_ip_mac")
    inferred = _pairs(events, "ip_mac") - arp
    arp_ips = {ip for ip, _ in arp}
    ips_by_mac: dict[str, set[str]] = defaultdict(set)
    for ip, mac in arp | inferred:
        ips_by_mac[mac].add(ip)
    gateways = {
        mac
        for mac, ips in ips_by_mac.items()
        if len(ips) > 1 and any((ip, mac) in inferred for ip in ips)
    }
    for ip, mac in sorted(arp):
        asset = _asset(inv, ip)
        asset.ips.add(ip)
        asset.macs[mac] = MAC_ARP
    for ip, mac in sorted(inferred):
        if mac in gateways or ip in arp_ips:
            continue
        asset = _asset(inv, ip)
        asset.ips.add(ip)
        asset.macs.setdefault(mac, MAC_INFERRED)
    for mac in sorted(gateways):
        ips = sorted(ips_by_mac[mac])
        inv.caveats.append(
            f"MAC {mac} is shared by {len(ips)} IPs ({', '.join(ips)}): treated as a gateway, "
            "no vendor attributed to those hosts from it."
        )


def _is_unicast(mac: str) -> bool:
    try:
        return not int(mac.split(":")[0], 16) & 1
    except ValueError:
        return False


def _add_l2_assets(inv: Investigation, events: list[Event]) -> None:
    known = {m for a in inv.assets.values() for m in a.macs}
    for ev in events:
        mac = (ev.src or "").lower()
        if ev.proto != "l2" or mac in known or not _is_unicast(mac):
            continue
        asset = _asset(inv, mac)
        asset.macs[mac] = MAC_L2
        asset.tools.add(ev.tool)
        _widen(asset, ev.ts)
        known.add(mac)


def _build_assets(inv: Investigation, events: list[Event], oui: OuiTable) -> None:
    for flow in inv.flows.values():
        proto = _flow_protocol(flow)
        for ip, role in ((flow.src, "client"), (flow.dst, "server")):
            if not ip:
                continue
            asset = _asset(inv, ip)
            asset.ips.add(ip)
            _widen(asset, flow.first_ts)
            _widen(asset, flow.last_ts)
            asset.tools |= flow.tools
            if proto:
                asset.roles.add(f"{proto}_{role}")
    _attribute_macs(inv, events)
    _add_l2_assets(inv, events)
    for asset in inv.assets.values():
        asset.ips.add(
            asset.id
        ) if "." in asset.id or ":" in asset.id and "-" not in asset.id else None
        for mac in sorted(asset.macs):
            vendor = oui.vendor(mac)
            if vendor:
                asset.vendor = vendor
                break
        asset.locally_administered_mac = asset.vendor is None and any(
            is_locally_administered(m) for m in asset.macs
        )


def _modbus_tid(ev: Event) -> str | None:
    if ev.tool == "zeek":
        return ev.attrs.get("tid")
    return ev.attrs.get("modbus.request.transaction_id")


def _control(ev: Event) -> tuple[str, str, str, list[str]] | None:
    if ev.tool != "zeek":
        return None
    if ev.proto == "modbus" and ev.attrs.get("pdu_type") == "REQ":
        func = ev.attrs.get("func", "")
        if func.startswith(MODBUS_WRITE):
            attack = [T_UNAUTH_COMMAND]
            if func.endswith(MODBUS_REGISTER_WRITE):
                attack.append(T_MODIFY_PARAMETER)
            return "control:modbus", f"Modbus {func}", "medium", attack
    if ev.proto == "s7comm":
        name = ev.attrs.get("function_name", "")
        for needle, severity in S7_CONTROL.items():
            if needle in name.lower():
                attack = [T_CHANGE_MODE] if needle in ("stop", "plc control") else []
                return "control:s7comm", f"S7comm {name}", severity, attack
    return None


def _detail_index(events: list[Event]) -> dict[tuple[str | None, str, str], Event]:
    return {
        (e.flow_key, e.attrs.get("tid", ""), e.attrs.get("func", "")): e
        for e in events
        if e.proto == "modbus_detailed"
    }


def _detection_id(*parts: object) -> str:
    raw = "|".join(str(p) for p in parts).encode()
    return hashlib.sha1(raw, usedforsecurity=False).hexdigest()[:12]


def _absorb(
    det: Detection, ev: Event, source: Source, severity: str | None, attack: list[str]
) -> None:
    det.count += 1
    if source not in det.sources:
        det.sources.append(source)
    _widen(det, ev.ts)
    if len(det.refs) < REF_CAP:
        det.refs.append(_ref(ev))
    if SEVERITY_RANK.get(severity or "", 0) > SEVERITY_RANK.get(det.severity or "", 0):
        det.severity = severity
    for technique in attack:
        if technique not in det.attack:
            det.attack.append(technique)


def _group_key(ev: Event, rule: str, title: str) -> tuple[object, ...]:
    tid = _modbus_tid(ev)
    if (
        tid is not None
        and ev.flow_key
        and (rule == "control:modbus" or ev.attrs.get("app_proto") == "modbus")
    ):
        return ("modbus", ev.flow_key, tid)
    return ("rule", rule, ev.flow_key, title)


def _merge_by_time(found: dict[tuple[object, ...], Detection]) -> None:
    controls = [
        d
        for k, d in found.items()
        if k[0] == "rule" and any(s.rule.startswith("control:") for s in d.sources)
    ]
    alerts = [
        (k, d)
        for k, d in found.items()
        if k[0] == "rule" and all(s.tool == "suricata" for s in d.sources)
    ]
    for key, alert in alerts:
        near = [
            c
            for c in controls
            if c.flow_key == alert.flow_key
            and alert.first_ts is not None
            and c.first_ts is not None
            and c.last_ts is not None
            and c.first_ts - MERGE_WINDOW <= alert.first_ts <= c.last_ts + MERGE_WINDOW
        ]
        if not near:
            continue
        target = min(near, key=lambda c: abs((c.first_ts or 0.0) - (alert.first_ts or 0.0)))
        target.count += alert.count
        target.sources.extend(s for s in alert.sources if s not in target.sources)
        target.refs.extend(alert.refs[: max(0, REF_CAP - len(target.refs))])
        target.attrs.update({k: v for k, v in alert.attrs.items() if k not in target.attrs})
        if SEVERITY_RANK.get(alert.severity or "", 0) > SEVERITY_RANK.get(target.severity or "", 0):
            target.severity = alert.severity
        _widen(target, alert.first_ts)
        _widen(target, alert.last_ts)
        del found[key]


def _build_detections(inv: Investigation, events: list[Event]) -> None:
    detail = _detail_index(events)
    found: dict[tuple[object, ...], Detection] = {}
    for ev in events:
        attack: list[str] = []
        extra: dict[str, str]
        if ev.kind == EventKind.LOGIC:
            rule = f"plc:{ev.attrs.get('rule', 'logic')}"
            title, severity = f"PLC logic: {ev.summary}", ev.severity
            extra = {k: ev.attrs[k] for k in ("project", "detail", "variable") if k in ev.attrs}
        elif ev.kind == EventKind.ALERT:
            sid = ev.attrs.get("sid")
            rule = f"suricata:{sid}" if ev.tool == "suricata" and sid else f"{ev.tool}:{ev.proto}"
            title, severity = ev.summary, ev.severity
            extra = {
                k: v
                for k, v in ev.attrs.items()
                if ev.tool == "suricata"
                and (
                    k.startswith("modbus.request.write")
                    or k in ("category", "modbus.request.function_raw")
                )
            }
        else:
            control = _control(ev)
            if control is None:
                continue
            rule, title, severity, attack = control
            extra = {"func": ev.attrs["func"]} if "func" in ev.attrs else {}
            d = detail.get((ev.flow_key, ev.attrs.get("tid", ""), ev.attrs.get("func", "")))
            if d:
                extra.update(
                    {
                        k: d.attrs[k]
                        for k in ("address", "quantity", "request_values")
                        if k in d.attrs
                    }
                )
        key = _group_key(ev, rule, title)
        det = found.get(key)
        if det is None:
            det = found[key] = Detection(
                id=_detection_id(*key),
                title=title,
                severity=severity,
                flow_key=ev.flow_key,
                src=ev.src,
                dst=ev.dst,
            )
        elif rule.startswith("control:") and not any(
            s.rule.startswith("control:") for s in det.sources
        ):
            det.title = title
        _absorb(det, ev, Source(ev.tool, rule, title), severity, attack)
        det.attrs.update({k: v for k, v in extra.items() if k not in det.attrs})
    _merge_by_time(found)
    inv.detections = sorted(
        found.values(),
        key=lambda d: (-SEVERITY_RANK.get(d.severity or "", 0), d.first_ts or 0.0, d.id),
    )


def _write_target(det: Detection) -> tuple[int, int, str] | None:
    func = det.attrs.get("func", "")
    raw = det.attrs.get("modbus.request.function_raw", "")
    is_register = "REGISTER" in func or raw in MODBUS_REGISTER_FUNCS
    address = det.attrs.get("address") or det.attrs.get("modbus.request.write.address", "")
    if not is_register or not address.isdigit():
        return None
    quantity = det.attrs.get("quantity") or det.attrs.get("modbus.request.write.quantity") or "1"
    values = det.attrs.get("request_values") or det.attrs.get("modbus.request.write.data", "")
    return int(address), int(quantity) if quantity.isdigit() else 1, values


def _link_plc(inv: Investigation, projects: Sequence[PlcProject]) -> None:
    for project in projects:
        if not project.controller_ips:
            inv.caveats.append(
                f"PLC project {project.name} has no controller IP, so it was not linked to any "
                "network asset. Provide the controller IP."
            )
            continue
        for ip in sorted(project.controller_ips):
            if ip in inv.assets:
                inv.assets[ip].plc_projects.add(project.name)
            else:
                inv.caveats.append(
                    f"PLC project {project.name} is assigned to {ip}, which is not seen in the "
                    "network evidence."
                )
        for det in inv.detections:
            target = _write_target(det)
            if target is None or det.dst not in project.controller_ips:
                continue
            address, quantity, values = target
            det.plc.extend(modbus_impacts(project, address, quantity, values))


def _build_arp_conflicts(inv: Investigation, events: list[Event]) -> None:
    macs_by_ip: dict[str, set[str]] = defaultdict(set)
    refs_by_ip: dict[str, list[EvidenceRef]] = defaultdict(list)
    firsts: dict[str, float | None] = {}
    for ev in events:
        for pair in ev.attrs.get("arp_ip_mac", "").split(";"):
            ip, _, mac = pair.partition("=")
            if not ip or not mac or mac.lower().startswith(REDUNDANCY_MAC_PREFIXES):
                continue
            macs_by_ip[ip].add(mac.lower())
            refs_by_ip[ip].append(_ref(ev))
            firsts[ip] = ev.ts if firsts.get(ip) is None else min(firsts[ip] or 0.0, ev.ts or 0.0)
    for ip, macs in sorted(macs_by_ip.items()):
        if len(macs) < 2:
            continue
        title = f"ARP: {ip} claimed by multiple MACs"
        det = Detection(
            id=_detection_id("arp_conflict", ip),
            title=title,
            severity="medium",
            flow_key=None,
            src=ip,
            dst=None,
            first_ts=firsts.get(ip),
            last_ts=firsts.get(ip),
            count=len(refs_by_ip[ip]),
            sources=[Source("tshark", "engine:arp_conflict", title)],
            attrs={"macs": ", ".join(sorted(macs))},
            refs=refs_by_ip[ip][:REF_CAP],
        )
        inv.detections.append(det)
    inv.detections.sort(
        key=lambda d: (-SEVERITY_RANK.get(d.severity or "", 0), d.first_ts or 0.0, d.id)
    )


def _build_caveats(inv: Investigation, events: list[Event]) -> None:
    seen = {e.tool for e in events}
    for tool in EXPECTED_TOOLS:
        if tool not in seen:
            inv.caveats.append(f"No {tool} evidence: correlation across tools is limited.")
    for ev in events:
        if ev.kind == EventKind.HEALTH and ev.severity:
            inv.caveats.append(
                f"Capture health ({ev.tool}): {ev.summary}. "
                "Absence of detections is not conclusive."
            )


def correlate(
    events: Iterable[Event],
    oui: OuiTable | None = None,
    plc: Sequence[PlcProject] = (),
) -> Investigation:
    items = list(events)
    inv = Investigation(event_count=len(items))
    _build_flows(inv, items)
    _build_assets(inv, items, oui or OuiTable.from_env())
    _build_detections(inv, items)
    _build_arp_conflicts(inv, items)
    _link_plc(inv, plc)
    _build_caveats(inv, items)
    inv.assets = dict(sorted(inv.assets.items()))
    inv.flows = dict(sorted(inv.flows.items(), key=lambda kv: (kv[1].first_ts or 0.0, kv[0])))
    return inv
