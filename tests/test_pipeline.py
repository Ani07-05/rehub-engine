import gzip
import json
import zipfile
from pathlib import Path

import pytest

from rehub import pipeline
from rehub.pipeline import Record, load_record, read_status, run_investigation
from rehub.schema import EvidenceKind
from rehub.serialize import to_jsonable
from tests.helpers import DEMO, FIXTURES, FixtureExecutor

PCAP = FIXTURES / "ot-demo.pcap"
PUMP = FIXTURES / "plc" / "pump.st"
PLC_IP = "10.0.0.20"


def run(
    tmp_path: Path, uploads: list[Path], fail: set[str] | None = None, **kw: object
) -> tuple[Record, FixtureExecutor]:
    ex = FixtureExecutor(fail)
    rec = run_investigation(uploads, tmp_path / "data", execute=ex, **kw)  # type: ignore[arg-type]
    return rec, ex


@pytest.fixture
def full(tmp_path: Path) -> Record:
    return run(tmp_path, [PCAP, PUMP], plc_ips={"pump.st": PLC_IP})[0]


def test_full_run_runs_three_tools_and_links_plc(full: Record) -> None:
    assert sorted(r.tool for r in full.tool_runs) == ["suricata", "tshark", "zeek"]
    assert all(r.ok for r in full.tool_runs)
    inv = full.investigation
    assert len(inv.flows) == 6
    single = next(d for d in inv.detections if d.title == "Modbus WRITE_SINGLE_REGISTER")
    assert single.tools == {"zeek", "suricata"}
    assert [i.variable for i in single.plc] == ["Setpoint"]
    assert any(d.title.startswith("PLC logic:") for d in inv.detections)
    assert inv.assets[PLC_IP].plc_projects == {"pump"}
    assert full.warnings == []


def test_evidence_chain_of_custody(full: Record) -> None:
    by_name = {e.name: e for e in full.evidence}
    pcap = by_name["ot-demo.pcap"]
    assert pcap.kind == EvidenceKind.PCAP
    conn = by_name["zeek/conn.log"]
    assert conn.kind == EvidenceKind.ZEEK_LOG
    assert conn.origin == "ot-demo.pcap"
    assert conn.origin_sha256 == pcap.sha256
    assert by_name["tshark/packets.tsv"].kind == EvidenceKind.TSHARK_TSV
    assert by_name["suricata/eve.json"].kind == EvidenceKind.SURICATA_EVE
    assert by_name["pump.st"].kind == EvidenceKind.PLC_ST
    for det in full.investigation.detections:
        shas = {e.sha256 for e in full.evidence}
        assert all(r.evidence_id in shas for r in det.refs)


def test_record_round_trips_through_json(tmp_path: Path, full: Record) -> None:
    data = tmp_path / "ignored"
    pipeline.save_record(data.parent / "data", full)
    loaded = load_record(tmp_path / "data", full.id)
    assert loaded is not None
    assert to_jsonable(loaded) == to_jsonable(full)
    assert (
        loaded.investigation.detections[0].corroborated
        == full.investigation.detections[0].corroborated
    )


def test_record_json_has_computed_fields(tmp_path: Path, full: Record) -> None:
    raw = json.loads((tmp_path / "data" / "investigations" / full.id / "record.json").read_text())
    det = next(d for d in raw["investigation"]["detections"] if d["title"].startswith("Modbus"))
    assert det["corroborated"] is True
    assert det["tools"] == ["suricata", "zeek"]
    assert raw["investigation"]["assets"][PLC_IP]["kind"] == "controller"


def test_status_progresses_to_done(tmp_path: Path) -> None:
    stages: list[str] = []
    rec, _ = run(tmp_path, [PCAP], on_progress=stages.append)
    assert stages[0] == "ingest" and stages[-1] == "done"
    assert read_status(tmp_path / "data", rec.id)["stage"] == "done"  # type: ignore[index]


def test_tool_failure_is_isolated(tmp_path: Path) -> None:
    rec, _ = run(tmp_path, [PCAP], fail={"suricata"})
    bad = next(r for r in rec.tool_runs if r.tool == "suricata")
    assert not bad.ok and "exploded" in bad.error
    assert any("suricata failed" in w for w in rec.warnings)
    assert "No suricata evidence: correlation across tools is limited." in rec.investigation.caveats
    assert len(rec.investigation.flows) == 6
    assert all(not d.corroborated for d in rec.investigation.detections)


def test_all_tools_failing_still_completes(tmp_path: Path) -> None:
    rec, _ = run(tmp_path, [PCAP], fail={"zeek", "suricata", "tshark"})
    assert rec.investigation.flows == {}
    assert len(rec.warnings) == 3
    assert read_status(tmp_path / "data", rec.id)["stage"] == "done"  # type: ignore[index]


def test_bundle_upload(tmp_path: Path) -> None:
    bundle = tmp_path / "case.zip"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.write(PCAP, "net/ot-demo.pcap")
        zf.write(PUMP, "plc/pump.st")
    rec, _ = run(tmp_path, [bundle], plc_ips={"plc/pump.st": PLC_IP})
    assert {e.name for e in rec.evidence} >= {"net/ot-demo.pcap", "plc/pump.st", "zeek/conn.log"}
    assert rec.investigation.assets[PLC_IP].plc_projects == {"pump"}


def test_log_only_upload_needs_no_tools(tmp_path: Path) -> None:
    ex = FixtureExecutor()
    uploads = [DEMO / "suricata" / "eve.json", *sorted((DEMO / "zeek").glob("*.log"))]
    rec = run_investigation(uploads, tmp_path / "data", execute=ex)
    assert ex.calls == []
    assert rec.tool_runs == []
    assert {d.title for d in rec.investigation.detections} >= {"Modbus WRITE_SINGLE_REGISTER"}
    assert "No tshark evidence: correlation across tools is limited." in rec.investigation.caveats


def test_unsupported_and_unknown_evidence_warned(tmp_path: Path) -> None:
    hist = tmp_path / "hist.csv"
    hist.write_text("timestamp,tag,value\n1,T1,5\n")
    junk = tmp_path / "notes.txt"
    junk.write_text("hello")
    rec, _ = run(tmp_path, [hist, junk])
    assert any("hist.csv" in w and "csv_historian" in w for w in rec.warnings)
    assert any("notes.txt" in w and "unknown" in w for w in rec.warnings)


def test_corrupt_upload_does_not_abort_the_rest(tmp_path: Path) -> None:
    bad = tmp_path / "bad.gz"
    bad.write_bytes(gzip.compress(b"x" * 100)[:-6])
    rec, _ = run(tmp_path, [bad, PCAP])
    assert any("bad.gz" in w and "corrupt" in w for w in rec.warnings)
    assert len(rec.investigation.flows) == 6


def test_plc_parse_error_is_a_warning(tmp_path: Path) -> None:
    evil = tmp_path / "x.xml"
    evil.write_text(
        '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y">]>'
        '<project xmlns="http://www.plcopen.org/xml/tc6_0201"></project>'
    )
    rec, _ = run(tmp_path, [evil])
    assert any("x.xml" in w and "DTD" in w for w in rec.warnings)


def test_duplicate_uploads_deduplicated(tmp_path: Path) -> None:
    copy = tmp_path / "copy.pcap"
    copy.write_bytes(PCAP.read_bytes())
    rec, ex = run(tmp_path, [PCAP, copy])
    assert len([e for e in rec.evidence if e.kind == EvidenceKind.PCAP]) == 1
    assert ex.calls.count("zeek") == 1


def test_same_input_gives_same_findings(tmp_path: Path) -> None:
    a, _ = run(tmp_path / "a", [PCAP, PUMP], plc_ips={"pump.st": PLC_IP})
    b, _ = run(tmp_path / "b", [PCAP, PUMP], plc_ips={"pump.st": PLC_IP})
    assert [(d.id, d.title, d.count) for d in a.investigation.detections] == [
        (d.id, d.title, d.count) for d in b.investigation.detections
    ]
    assert {e.sha256 for e in a.evidence} == {e.sha256 for e in b.evidence}


def test_failure_marks_status_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(pipeline, "correlate", boom)
    with pytest.raises(RuntimeError):
        run_investigation(
            [PCAP], tmp_path / "data", execute=FixtureExecutor(), investigation_id="abc"
        )
    status = read_status(tmp_path / "data", "abc")
    assert status is not None and status["stage"] == "failed" and "boom" in status["detail"]
    assert load_record(tmp_path / "data", "abc") is None


def test_investigation_id_collision_refused(tmp_path: Path) -> None:
    run_investigation([PCAP], tmp_path / "data", execute=FixtureExecutor(), investigation_id="same")
    with pytest.raises(FileExistsError):
        run_investigation(
            [PCAP], tmp_path / "data", execute=FixtureExecutor(), investigation_id="same"
        )
