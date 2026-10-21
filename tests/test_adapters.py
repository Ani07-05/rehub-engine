from pathlib import Path

from rehub.adapters.base import SourceFile
from rehub.adapters.suricata import parse_suricata
from rehub.adapters.tshark import parse_tshark
from rehub.adapters.zeek import parse_zeek, read_rows
from rehub.schema import Event, EventKind

DEMO = Path(__file__).resolve().parent.parent / "fixtures" / "ot-demo"
ROGUE = "10.0.0.66"


def src(rel: str) -> SourceFile:
    return SourceFile(DEMO / rel, rel, "ev-" + rel)


def zeek_events() -> list[Event]:
    names = ["conn", "modbus", "modbus_detailed", "s7comm", "cotp"]
    return list(parse_zeek([src(f"zeek/{n}.log") for n in names]))


def test_zeek_flows_carry_community_id() -> None:
    flows = [e for e in zeek_events() if e.kind == EventKind.FLOW]
    assert len(flows) == 6
    assert all(e.flow_key and e.flow_key.startswith("1:") for e in flows)
    assert {e.dport for e in flows} == {502, 102}


def test_zeek_protocol_logs_link_to_conn_flow() -> None:
    events = zeek_events()
    conn_keys = {e.flow_key for e in events if e.kind == EventKind.FLOW}
    actions = [e for e in events if e.kind == EventKind.PROTOCOL_ACTION]
    assert actions
    assert all(e.flow_key in conn_keys for e in actions)
    assert not any("flow_key_assumed_tcp" in e.attrs for e in actions)


def test_zeek_modbus_write_detail() -> None:
    writes = [e for e in zeek_events() if e.proto == "modbus_detailed" and e.src == ROGUE]
    assert {e.attrs["func"] for e in writes} == {
        "WRITE_SINGLE_REGISTER",
        "WRITE_MULTIPLE_REGISTERS",
    }


def test_zeek_modbus_detailed_deduplicated(tmp_path: Path) -> None:
    line = (DEMO / "zeek" / "modbus_detailed.log").read_text().splitlines()[0]
    dup = tmp_path / "modbus_detailed.log"
    dup.write_text("\n".join([line, line, line]) + "\n")
    events = list(parse_zeek([SourceFile(dup, "modbus_detailed.log", "e")]))
    assert len(events) == 1


def test_zeek_s7_stop_summary() -> None:
    s7 = [e for e in zeek_events() if e.proto == "s7comm"]
    assert [e.summary for e in s7] == ["Job-Request PLC Stop"]


def test_zeek_provenance_ref() -> None:
    first = next(e for e in zeek_events() if e.kind == EventKind.FLOW)
    assert first.ref.startswith("zeek/conn.log:L")
    assert first.evidence_id == "ev-zeek/conn.log"


def test_zeek_tsv_parsing(tmp_path: Path) -> None:
    tsv = tmp_path / "conn.log"
    tsv.write_text(
        "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
        "#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\ttunnel_parents\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tset[string]\n"
        "1760000000.5\tCabc\t10.0.0.1\t4000\t10.0.0.2\t502\ttcp\tmodbus\t(empty)\n"
        "#close\t2026-01-01\n"
    )
    [(_, path, row)] = list(read_rows(SourceFile(tsv, "conn.log", "e")))
    assert path == "conn"
    assert row["id.orig_p"] == 4000
    assert row["ts"] == 1760000000.5
    assert row["tunnel_parents"] == []
    [event] = list(parse_zeek([SourceFile(tsv, "conn.log", "e")]))
    assert event.kind == EventKind.FLOW
    assert event.flow_key and event.flow_key.startswith("1:")


def test_zeek_unlinked_protocol_log_flags_assumption(tmp_path: Path) -> None:
    line = (DEMO / "zeek" / "modbus.log").read_text().splitlines()[0]
    f = tmp_path / "modbus.log"
    f.write_text(line + "\n")
    [event] = list(parse_zeek([SourceFile(f, "modbus.log", "e")]))
    assert event.attrs["flow_key_assumed_tcp"] == "1"
    assert event.flow_key


def test_zeek_skips_noise_and_garbage(tmp_path: Path) -> None:
    f = tmp_path / "packet_filter.log"
    f.write_text('{"ts":1.0,"filter":"ip or not ip"}\nnot json\n')
    assert list(parse_zeek([SourceFile(f, "packet_filter.log", "e")])) == []


def test_suricata_alerts() -> None:
    events = list(parse_suricata([src("suricata/eve.json")]))
    alerts = [e for e in events if e.kind == EventKind.ALERT]
    assert {e.summary for e in alerts} == {
        "REHUB Modbus write single register",
        "REHUB Modbus write multiple registers",
        "REHUB S7comm PLC stop",
    }
    assert all(e.src == ROGUE and e.severity == "low" and e.flow_key for e in alerts)
    write = next(e for e in alerts if e.attrs["sid"] == "9000001")
    assert write.attrs["modbus.request.write.address"] == "10"
    assert write.attrs["modbus.request.write.data"] == "1000"


def test_suricata_flows_and_health() -> None:
    events = list(parse_suricata([src("suricata/eve.json")]))
    assert len([e for e in events if e.kind == EventKind.FLOW]) == 6
    [health] = [e for e in events if e.kind == EventKind.HEALTH]
    assert health.severity is None


def test_suricata_flow_keys_match_zeek() -> None:
    zeek = {e.flow_key for e in zeek_events() if e.kind == EventKind.FLOW}
    suri = {
        e.flow_key for e in parse_suricata([src("suricata/eve.json")]) if e.kind == EventKind.FLOW
    }
    assert zeek == suri


def test_suricata_drops_flag_health(tmp_path: Path) -> None:
    f = tmp_path / "eve.json"
    f.write_text(
        '{"timestamp":"2026-01-01T00:00:00.000000+0000","event_type":"stats",'
        '"stats":{"capture":{"kernel_drops":42}}}\n'
    )
    [event] = list(parse_suricata([SourceFile(f, "eve.json", "e")]))
    assert event.severity == "medium"
    assert event.attrs["capture.kernel_drops"] == "42"


def test_tshark_aggregates_per_flow_and_matches_zeek_keys() -> None:
    events = list(parse_tshark([src("tshark/packets.tsv")]))
    keys = {e.flow_key for e in events if e.flow_key}
    zeek = {e.flow_key for e in zeek_events() if e.kind == EventKind.FLOW}
    assert keys == zeek
    assert sum(int(e.attrs["packets"]) for e in events) == 108


def test_tshark_records_ip_mac_pairs() -> None:
    events = list(parse_tshark([src("tshark/packets.tsv")]))
    pairs = {p for e in events for p in e.attrs["ip_mac"].split(";") if p}
    assert "10.0.0.20=00:80:f4:00:00:20" in pairs
    assert "10.0.0.66=02:00:00:00:00:66" in pairs


def test_tshark_non_ip_traffic_kept_as_l2(tmp_path: Path) -> None:
    f = tmp_path / "packets.tsv"
    cells = [""] * 16
    cells[0], cells[1], cells[12] = "1", "1760000000.0", "ARP"
    cells[14], cells[15] = "aa:aa:aa:aa:aa:01", "ff:ff:ff:ff:ff:ff"
    f.write_text("\t".join(cells) + "\n")
    [event] = list(parse_tshark([SourceFile(f, "packets.tsv", "e")]))
    assert event.proto == "l2"
    assert event.src == "aa:aa:aa:aa:aa:01"
    assert event.flow_key is None


def test_tshark_arp_pairs_and_missing_time(tmp_path: Path) -> None:
    f = tmp_path / "packets.tsv"
    cells = [""] * 18
    cells[0], cells[12] = "1", "ARP"
    cells[14], cells[15] = "aa:aa:aa:aa:aa:01", "ff:ff:ff:ff:ff:ff"
    cells[16], cells[17] = "aa:aa:aa:aa:aa:01", "10.0.0.5"
    f.write_text("\t".join(cells) + "\n")
    [event] = list(parse_tshark([SourceFile(f, "packets.tsv", "e")]))
    assert event.attrs["arp_ip_mac"] == "10.0.0.5=aa:aa:aa:aa:aa:01"
    assert event.ts is None


def test_tshark_demo_has_arp_pairs() -> None:
    events = list(parse_tshark([src("tshark/packets.tsv")]))
    pairs = {p for e in events for p in e.attrs["arp_ip_mac"].split(";") if p}
    assert "10.0.0.20=00:80:f4:00:00:20" in pairs


def test_suricata_computes_flow_key_when_missing(tmp_path: Path) -> None:
    f = tmp_path / "eve.json"
    f.write_text(
        '{"timestamp":"2026-01-01T00:00:00.000000+0000","event_type":"alert",'
        '"src_ip":"10.0.0.66","src_port":40001,"dest_ip":"10.0.0.20","dest_port":502,'
        '"proto":"TCP","alert":{"signature_id":1,"signature":"x","severity":2}}\n'
    )
    [event] = list(parse_suricata([SourceFile(f, "eve.json", "e")]))
    zeek_key = next(
        e.flow_key for e in zeek_events() if e.kind == EventKind.FLOW and e.sport == 40001
    )
    assert event.flow_key == zeek_key
    assert event.proto == "tcp"


def test_zeek_weird_titles_read_like_sentences(tmp_path: Path) -> None:
    f = tmp_path / "weird.log"
    f.write_text(
        '{"ts":1.0,"name":"dnp3_header_lacks_magic","uid":"C1","id.orig_h":"10.0.0.8",'
        '"id.orig_p":1,"id.resp_h":"10.0.0.3","id.resp_p":20000}\n'
    )
    [event] = list(parse_zeek([SourceFile(f, "weird.log", "e")]))
    assert event.summary == "Protocol anomaly: dnp3 header lacks magic"
    assert event.kind == EventKind.ALERT and event.severity == "low"
