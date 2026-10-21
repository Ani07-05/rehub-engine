import json
from pathlib import Path
from typing import Any

import pytest

from rehub.ingest import ingest
from rehub.pipeline import run_investigation
from rehub.schema import EvidenceKind
from rehub.sniff import sniff
from tests.helpers import FixtureExecutor

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
MANIFEST = json.loads((SAMPLES / "manifest.json").read_text())["samples"]
SINGLE = [e for e in MANIFEST if e["kind"] != "bundle"]
BUNDLES = [e for e in MANIFEST if e["kind"] == "bundle"]
ANALYZED = {
    EvidenceKind.PCAP, EvidenceKind.ZEEK_LOG, EvidenceKind.SURICATA_EVE,
    EvidenceKind.PLC_ST, EvidenceKind.PLC_PLCOPEN, EvidenceKind.PLC_L5X,
}  # fmt: skip


def test_manifest_covers_every_file_and_nothing_else() -> None:
    on_disk = {
        p.relative_to(SAMPLES).as_posix()
        for p in SAMPLES.rglob("*")
        if p.is_file() and p.name not in ("README.md", "manifest.json")
    }
    assert on_disk == {e["path"] for e in MANIFEST}


def test_every_evidence_kind_is_represented() -> None:
    kinds = {e["kind"] for e in SINGLE}
    assert kinds == {k.value for k in EvidenceKind} - {"tshark_tsv", "csv"}


@pytest.mark.parametrize("entry", SINGLE, ids=lambda e: e["path"])
def test_each_sample_is_recognized_as_declared(entry: dict[str, Any]) -> None:
    assert sniff(SAMPLES / entry["path"]).value == entry["kind"]
    assert entry["analyzed"] == (EvidenceKind(entry["kind"]) in ANALYZED)


@pytest.mark.parametrize("entry", BUNDLES, ids=lambda e: e["path"])
def test_bundles_unpack_to_the_declared_members(tmp_path: Path, entry: dict[str, Any]) -> None:
    found = ingest(SAMPLES / entry["path"], tmp_path / "store")
    assert sorted(f"{e.name}:{e.kind.value}" for e in found) == sorted(entry["members"])


def test_logs_only_upload_reproduces_the_story_from_real_zeek_tsv(tmp_path: Path) -> None:
    uploads = [p for p in sorted((SAMPLES / "zeek-tsv").glob("*.log"))]
    uploads += [SAMPLES / "suricata" / "eve.json", SAMPLES / "plc" / "pump.st"]
    record = run_investigation(
        uploads, tmp_path / "data", plc_ips={"pump.st": "10.0.0.20"}, execute=FixtureExecutor()
    )
    titles = {d.title for d in record.investigation.detections}
    assert {"S7comm PLC Stop", "Modbus WRITE_SINGLE_REGISTER"} <= titles
    single = next(
        d for d in record.investigation.detections if d.title == "Modbus WRITE_SINGLE_REGISTER"
    )
    assert single.corroborated and single.plc[0].variable == "Setpoint"
    assert record.tool_runs == []


def test_stored_only_samples_warn_instead_of_vanishing(tmp_path: Path) -> None:
    uploads = [SAMPLES / e["path"] for e in SINGLE if not e["analyzed"]]
    record = run_investigation(uploads, tmp_path / "data", execute=FixtureExecutor())
    assert len(record.warnings) == len(uploads)
    assert all("stored but not analyzed" in w for w in record.warnings)
    assert len(record.evidence) == len(uploads)


def test_samples_stay_small() -> None:
    assert sum(p.stat().st_size for p in SAMPLES.rglob("*") if p.is_file()) < 400_000
