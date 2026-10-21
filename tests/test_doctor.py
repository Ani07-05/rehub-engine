import shutil
from pathlib import Path

import pytest

from rehub import doctor
from rehub.doctor import FAIL, OK, WARN, run_doctor
from tests.helpers import ProbeExecutor


def by_id(report: doctor.Report) -> dict[str, doctor.Check]:
    return {c.id: c for c in report.checks}


def test_everything_ready(tmp_path: Path) -> None:
    report = run_doctor(tmp_path / "data", ProbeExecutor())
    checks = by_id(report)
    assert report.status == OK
    assert checks["zeek"].detail == "version 8.0.10"
    assert checks["suricata"].detail == "version 8.0.7"
    assert checks["tshark"].detail == "version 4.4.19"
    assert {"selftest-zeek", "selftest-suricata", "selftest-tshark"} <= set(checks)
    assert all(c.status == OK for c in report.checks)


def test_missing_tool_fails_with_fix_and_skips_selftest(tmp_path: Path) -> None:
    report = run_doctor(tmp_path, ProbeExecutor(missing={"suricata"}))
    checks = by_id(report)
    assert report.status == FAIL
    assert checks["suricata"].status == FAIL and "not installed" in checks["suricata"].detail
    assert "ReHub image" in checks["suricata"].fix
    assert not any(k.startswith("selftest") for k in checks)


def test_tool_that_starts_but_cannot_parse_is_caught_by_selftest(tmp_path: Path) -> None:
    report = run_doctor(tmp_path, ProbeExecutor(no_alerts=True))
    checks = by_id(report)
    assert report.status == FAIL
    assert checks["selftest-suricata"].status == FAIL
    assert checks["selftest-zeek"].status == OK


def test_tool_run_failure_reported_per_tool(tmp_path: Path) -> None:
    class Failing(ProbeExecutor):
        def __call__(self, argv, **kw):  # type: ignore[no-untyped-def]
            if argv[0] == "zeek" and "-r" in argv:
                import subprocess

                return subprocess.CompletedProcess(argv, 2, "", "zeek crashed")
            return super().__call__(argv, **kw)

    checks = by_id(run_doctor(tmp_path, Failing()))
    assert (
        checks["selftest-zeek"].status == FAIL and "zeek crashed" in checks["selftest-zeek"].detail
    )


def test_missing_ics_plugins_warn(tmp_path: Path) -> None:
    report = run_doctor(tmp_path, ProbeExecutor(probes={("zeek", "-N"): "nothing useful"}))
    assert by_id(report)["zeek-ics"].status == WARN
    assert report.status == WARN


def test_quick_skips_the_sample_capture(tmp_path: Path) -> None:
    report = run_doctor(tmp_path, ProbeExecutor(), quick=True)
    assert not any(c.id.startswith("selftest") for c in report.checks)


def test_sign_in_off_is_fine_for_a_local_tool(tmp_path: Path) -> None:
    report = run_doctor(tmp_path, ProbeExecutor(), auth_enabled=False)
    assert by_id(report)["auth"].status == OK and "local only" in by_id(report)["auth"].detail
    assert report.status == OK


def test_unwritable_data_folder_fails(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    report = run_doctor(blocker / "data", ProbeExecutor())
    assert by_id(report)["data"].status == FAIL


@pytest.mark.parametrize(("free_gb", "status"), [(0.1, FAIL), (2, WARN), (50, OK)])
def test_disk_space_thresholds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, free_gb: float, status: str
) -> None:
    class Usage:
        free = int(free_gb * (1 << 30))

    monkeypatch.setattr(shutil, "disk_usage", lambda _p: Usage())
    assert by_id(run_doctor(tmp_path, ProbeExecutor(), quick=True))["disk"].status == status


def test_selftest_pcap_is_a_real_modbus_capture() -> None:
    data = doctor.SELFTEST_PCAP.read_bytes()
    assert data[:4] == bytes.fromhex("d4c3b2a1") and len(data) < 4096
