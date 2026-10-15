from pathlib import Path

import pytest

from rehub.adapters.base import SourceFile
from rehub.adapters.suricata import parse_suricata
from rehub.adapters.tshark import parse_tshark
from rehub.adapters.zeek import parse_zeek
from rehub.correlate import ATTACK_NOTE, correlate
from rehub.model import MAC_ARP, MAC_INFERRED, Investigation
from rehub.oui import OuiTable
from rehub.schema import Event, EventKind

DEMO = Path(__file__).resolve().parent.parent / "fixtures" / "ot-demo"
HMI, PLC, ROGUE, S7 = "10.0.0.10", "10.0.0.20", "10.0.0.66", "10.0.0.30"
REMOTE_A, REMOTE_B = "172.16.0.5", "172.16.0.6"
GATEWAY_MAC = "00:00:0c:07:ac:01"


def src(rel: str) -> SourceFile:
    return SourceFile(DEMO / rel, rel, "ev-" + rel)


def demo_events(tools: tuple[str, ...] = ("zeek", "suricata", "tshark")) -> list[Event]:
    events: list[Event] = []
    if "zeek" in tools:
        names = ["conn", "modbus", "modbus_detailed", "s7comm", "cotp"]
        events += parse_zeek([src(f"zeek/{n}.log") for n in names])
    if "suricata" in tools:
        events += parse_suricata([src("suricata/eve.json")])
    if "tshark" in tools:
        events += parse_tshark([src("tshark/packets.tsv")])
    return events


def packet(attrs: dict[str, str], ts: float | None = 1.0, proto: str = "tcp") -> Event:
    return Event(
        ts=ts, tool="tshark", kind=EventKind.PACKET, evidence_id="e", proto=proto, attrs=attrs
    )


@pytest.fixture(scope="module")
def inv() -> Investigation:
    return correlate(demo_events())


def test_six_flows_merged_across_tools(inv: Investigation) -> None:
    assert len(inv.flows) == 6
    assert all(f.tools == {"zeek", "suricata", "tshark"} for f in inv.flows.values())
    assert sum(f.packets for f in inv.flows.values()) == 104
    assert all(f.proto == "tcp" for f in inv.flows.values())


def test_flow_initiator_comes_from_zeek_not_first_packet(inv: Investigation) -> None:
    rogue = [f for f in inv.flows.values() if f.src == ROGUE]
    assert {f.dport for f in rogue} == {502, 102}
    assert all(f.sport and f.sport > 40000 for f in rogue)


def test_assets_and_roles(inv: Investigation) -> None:
    assert set(inv.assets) == {HMI, PLC, ROGUE, S7, REMOTE_A, REMOTE_B}
    assert inv.assets[PLC].kind == "controller"
    assert "modbus_server" in inv.assets[PLC].roles
    assert "s7comm_server" in inv.assets[S7].roles
    assert inv.assets[HMI].kind == "client"
    assert {"modbus_client", "s7comm_client"} <= inv.assets[ROGUE].roles


def test_vendors_from_arp_confirmed_macs(inv: Investigation) -> None:
    assert inv.assets[PLC].vendor == "Telemecanique Electrique (Schneider Electric)"
    assert inv.assets[S7].vendor == "Siemens AG"
    assert inv.assets[PLC].macs == {"00:80:f4:00:00:20": MAC_ARP}
    assert inv.assets[ROGUE].vendor is None
    assert inv.assets[ROGUE].locally_administered_mac


def test_gateway_mac_never_attributed_to_remote_hosts() -> None:
    oui = OuiTable({"00000C": "Cisco Systems"})
    inv = correlate(demo_events(), oui)
    for ip in (REMOTE_A, REMOTE_B):
        assert inv.assets[ip].vendor is None
        assert GATEWAY_MAC not in inv.assets[ip].macs
    assert any(GATEWAY_MAC in c and "gateway" in c for c in inv.caveats)


def test_inferred_mac_used_when_unambiguous_and_no_arp() -> None:
    inv = correlate([packet({"ip_mac": "10.0.0.5=00:1b:1b:aa:bb:cc"})])
    asset = inv.assets["10.0.0.5"]
    assert asset.macs == {"00:1b:1b:aa:bb:cc": MAC_INFERRED}
    assert asset.vendor == "Siemens AG"


def test_inferred_mac_ignored_when_arp_knows_better() -> None:
    events = [
        packet({"arp_ip_mac": "10.0.0.5=00:1b:1b:00:00:05"}),
        packet({"ip_mac": "10.0.0.5=00:00:0c:00:00:01"}),
    ]
    asset = correlate(events).assets["10.0.0.5"]
    assert asset.macs == {"00:1b:1b:00:00:05": MAC_ARP}


def test_modbus_writes_merged_across_tools(inv: Investigation) -> None:
    writes = [d for d in inv.detections if d.title.startswith("Modbus")]
    assert [d.title for d in writes] == [
        "Modbus WRITE_SINGLE_REGISTER",
        "Modbus WRITE_MULTIPLE_REGISTERS",
    ]
    for d in writes:
        assert d.tools == {"zeek", "suricata"}
        assert d.corroborated
        assert d.count == 2
        assert d.attack == ["T0855 Unauthorized Command Message", "T0836 Modify Parameter"]
    assert writes[0].attrs["address"] == "10"
    assert writes[0].severity == "medium"


def test_s7_stop_merged_by_time_window(inv: Investigation) -> None:
    [stop] = [d for d in inv.detections if d.title == "S7comm PLC Stop"]
    assert stop.severity == "high"
    assert stop.tools == {"zeek", "suricata"}
    assert stop.attack == ["T0858 Change Operating Mode"]
    assert stop.count == 3


def test_no_duplicate_findings(inv: Investigation) -> None:
    assert len(inv.detections) == 3
    assert [d.title for d in inv.detections][0] == "S7comm PLC Stop"
    assert all(d.src == ROGUE for d in inv.detections)


def test_benign_polling_and_routed_reads_raise_nothing(inv: Investigation) -> None:
    benign = {f.key for f in inv.flows.values() if f.src != ROGUE}
    assert len(benign) == 4
    assert not any(d.flow_key in benign for d in inv.detections)


def test_every_detection_has_evidence_refs(inv: Investigation) -> None:
    for d in inv.detections:
        assert d.refs
        assert all(r.evidence_id.startswith("ev-") and r.ref for r in d.refs)


def test_single_tool_not_corroborated_and_caveats() -> None:
    inv = correlate(demo_events(("suricata",)))
    assert inv.detections
    assert not any(d.corroborated for d in inv.detections)
    assert "No zeek evidence: correlation across tools is limited." in inv.caveats
    assert "No tshark evidence: correlation across tools is limited." in inv.caveats


def test_zeek_only_still_finds_control_actions() -> None:
    inv = correlate(demo_events(("zeek",)))
    assert {d.title for d in inv.detections} >= {"S7comm PLC Stop", "Modbus WRITE_SINGLE_REGISTER"}
    assert not any(d.corroborated for d in inv.detections)


def test_unrelated_alert_not_merged_into_control() -> None:
    events = demo_events()
    late = [
        Event(
            ts=1_760_000_050.0,
            tool="suricata",
            kind=EventKind.ALERT,
            evidence_id="e",
            src=ROGUE,
            dst=S7,
            flow_key=next(f.key for f in correlate(events).flows.values() if f.dport == 102),
            severity="low",
            summary="later unrelated alert",
            attrs={"sid": "1"},
        )
    ]
    inv = correlate(events + late)
    assert "later unrelated alert" in {d.title for d in inv.detections}
    assert len(inv.detections) == 4


def test_arp_conflict_detected() -> None:
    events = [
        packet({"arp_ip_mac": "10.0.0.5=aa:aa:aa:aa:aa:01"}, ts=1.0),
        packet({"arp_ip_mac": "10.0.0.5=aa:aa:aa:aa:aa:02"}, ts=2.0),
    ]
    [det] = correlate(events).detections
    assert det.title == "ARP: 10.0.0.5 claimed by multiple MACs"
    assert det.attrs["macs"] == "aa:aa:aa:aa:aa:01, aa:aa:aa:aa:aa:02"
    assert det.severity == "medium"


def test_arp_redundancy_virtual_macs_not_flagged() -> None:
    events = [
        packet({"arp_ip_mac": "10.0.0.1=00:00:5e:00:01:01"}),
        packet({"arp_ip_mac": "10.0.0.1=aa:aa:aa:aa:aa:01"}),
    ]
    assert correlate(events).detections == []


def test_capture_loss_adds_caveat() -> None:
    ev = Event(
        ts=1.0,
        tool="zeek",
        kind=EventKind.HEALTH,
        evidence_id="e",
        severity="medium",
        summary="capture_loss",
    )
    assert any("not conclusive" in c for c in correlate([ev]).caveats)


def test_output_independent_of_event_order() -> None:
    events = demo_events()
    a, b = correlate(events), correlate(list(reversed(events)))
    assert list(a.assets) == list(b.assets)
    assert list(a.flows) == list(b.flows)
    assert [(d.id, d.title, d.count) for d in a.detections] == [
        (d.id, d.title, d.count) for d in b.detections
    ]


def test_attack_note_present() -> None:
    assert "candidates" in ATTACK_NOTE


def test_unknown_mac_vendor_none() -> None:
    assert OuiTable().vendor("dc:ad:be:ef:00:01") is None
    assert OuiTable({"DEADBE": "x"}).vendor("de:ad:be:ef:00:01") is None
    assert OuiTable({"DCADBE": "Test Corp"}).vendor("DC:AD:BE:ef:00:01") == "Test Corp"


def test_empty_input() -> None:
    inv = correlate([])
    assert inv.flows == {} and inv.assets == {} and inv.detections == []
