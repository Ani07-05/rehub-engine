import gzip
from pathlib import Path

import pytest

from rehub.schema import EvidenceKind
from rehub.sniff import sha256_file, sniff

L5X = '<?xml version="1.0"?>\n<RSLogix5000Content SchemaRevision="1.0"></RSLogix5000Content>'
PLCOPEN = '<?xml version="1.0"?>\n<project xmlns="http://www.plcopen.org/xml/tc6_0201"></project>'
EVE = '{"timestamp":"2026-01-01T00:00:00","event_type":"alert","src_ip":"10.0.0.1","flow_id":1}\n'
ZEEK_TSV = "#separator \\x09\n#fields\tts\tuid\n"
ZEEK_JSON = '{"ts":1.0,"uid":"CAbc","id.orig_h":"10.0.0.1"}\n'
TSHARK_EK = (
    '{"index":{"_index":"packets-2026-01-01","_type":"doc"}}\n{"timestamp":"1","layers":{}}\n'
)
ST = "PROGRAM main\nVAR x : BOOL; END_VAR\nEND_PROGRAM\n"
SYSLOG = "<34>Oct 11 22:14:15 plc1 sshd: failed login\n"
SYSLOG_BSD = "Oct 11 22:14:15 plc1 sshd: failed login\n"


@pytest.mark.parametrize(
    ("name", "content", "kind"),
    [
        ("a.xml", L5X, EvidenceKind.PLC_L5X),
        ("a.xml", PLCOPEN, EvidenceKind.PLC_PLCOPEN),
        ("eve.json", EVE, EvidenceKind.SURICATA_EVE),
        ("conn.log", ZEEK_TSV, EvidenceKind.ZEEK_LOG),
        ("conn.log", ZEEK_JSON, EvidenceKind.ZEEK_LOG),
        ("p.json", TSHARK_EK, EvidenceKind.TSHARK_JSON),
        ("main.st", ST, EvidenceKind.PLC_ST),
        ("messages", SYSLOG, EvidenceKind.SYSLOG),
        ("messages", SYSLOG_BSD, EvidenceKind.SYSLOG),
        ("assets.csv", "ip,mac\n10.0.0.1,aa:bb\n", EvidenceKind.CSV_ASSETS),
        ("hist.csv", "timestamp,tag,value\n1,T1,5\n", EvidenceKind.CSV_HISTORIAN),
        ("other.csv", "a,b\n1,2\n", EvidenceKind.CSV),
        ("other.txt", "a,b\n1,2\n", EvidenceKind.UNKNOWN),
        ("fake.log", "#fields\tts\n", EvidenceKind.UNKNOWN),
        ("notes.txt", "hello\n", EvidenceKind.UNKNOWN),
        ("blob.bin", "", EvidenceKind.UNKNOWN),
    ],
)
def test_text_kinds(tmp_path: Path, name: str, content: str, kind: EvidenceKind) -> None:
    path = tmp_path / name
    path.write_text(content)
    assert sniff(path) == kind


@pytest.mark.parametrize("magic", ["d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d", "0a0d0d0a"])
def test_pcap_magics(tmp_path: Path, magic: str) -> None:
    path = tmp_path / "x.dat"
    path.write_bytes(bytes.fromhex(magic) + b"\x00" * 32)
    assert sniff(path) == EvidenceKind.PCAP


def test_binary_unknown(tmp_path: Path) -> None:
    path = tmp_path / "project.ACD"
    path.write_bytes(b"\xff\xfe\x00\x01" * 16)
    assert sniff(path) == EvidenceKind.UNKNOWN


def test_extension_not_trusted(tmp_path: Path) -> None:
    path = tmp_path / "capture.txt"
    path.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 32)
    assert sniff(path) == EvidenceKind.PCAP


def test_sha256(tmp_path: Path) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"abc")
    assert sha256_file(path) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_multibyte_split_at_head_boundary(tmp_path: Path) -> None:
    path = tmp_path / "conn.log"
    body = "#separator \\x09\n#fields\tts\tuid\n" + "é" * 5000
    path.write_text(body, encoding="utf-8")
    assert sniff(path) == EvidenceKind.ZEEK_LOG


def test_eve_first_line_longer_than_head(tmp_path: Path) -> None:
    path = tmp_path / "eve.json"
    payload = "A" * 20000
    path.write_text(
        '{"timestamp":"2026-01-01T00:00:00","event_type":"alert",'
        f'"src_ip":"10.0.0.1","payload":"{payload}"}}\n'
    )
    assert sniff(path) == EvidenceKind.SURICATA_EVE


def test_eve_stats_line_without_flow(tmp_path: Path) -> None:
    path = tmp_path / "eve.json"
    path.write_text('{"timestamp":"2026-01-01T00:00:00","event_type":"stats","stats":{}}\n')
    assert sniff(path) == EvidenceKind.SURICATA_EVE


def test_zeek_json_capture_loss(tmp_path: Path) -> None:
    path = tmp_path / "capture_loss.log"
    path.write_text('{"ts":1.0,"ts_delta":60.0,"peer":"zeek","gaps":0}\n')
    assert sniff(path) == EvidenceKind.ZEEK_LOG


def test_gzip_pcap(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap.gz"
    path.write_bytes(gzip.compress(bytes.fromhex("d4c3b2a1") + b"\x00" * 32))
    assert sniff(path) == EvidenceKind.PCAP


def test_gzip_zeek_log(tmp_path: Path) -> None:
    path = tmp_path / "conn.log.gz"
    path.write_bytes(gzip.compress(ZEEK_TSV.encode()))
    assert sniff(path) == EvidenceKind.ZEEK_LOG


def test_nul_bytes_not_text(tmp_path: Path) -> None:
    path = tmp_path / "x.csv"
    path.write_bytes(b"ip,mac\n\x00\x00\x00")
    assert sniff(path) == EvidenceKind.UNKNOWN


FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "ot-demo"


@pytest.mark.parametrize(
    ("rel", "kind"),
    [
        ("zeek/conn.log", EvidenceKind.ZEEK_LOG),
        ("zeek/modbus.log", EvidenceKind.ZEEK_LOG),
        ("zeek/s7comm.log", EvidenceKind.ZEEK_LOG),
        ("suricata/eve.json", EvidenceKind.SURICATA_EVE),
    ],
)
def test_real_tool_output(rel: str, kind: EvidenceKind) -> None:
    assert sniff(FIXTURE_DIR / rel) == kind


def test_real_pcap() -> None:
    assert sniff(FIXTURE_DIR.parent / "ot-demo.pcap") == EvidenceKind.PCAP


def test_utf8_bom_xml_and_csv(tmp_path: Path) -> None:
    xml = tmp_path / "p.xml"
    xml.write_bytes(b"\xef\xbb\xbf" + L5X.encode())
    assert sniff(xml) == EvidenceKind.PLC_L5X
    csv_file = tmp_path / "hist.csv"
    csv_file.write_bytes(b"\xef\xbb\xbftimestamp,tag,value\n1,T1,5\n")
    assert sniff(csv_file) == EvidenceKind.CSV_HISTORIAN


def test_utf16_csv(tmp_path: Path) -> None:
    path = tmp_path / "hist.csv"
    path.write_bytes("timestamp,tag,value\r\n1,T1,5\r\n".encode("utf-16"))
    assert sniff(path) == EvidenceKind.CSV_HISTORIAN
