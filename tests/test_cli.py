from pathlib import Path

import pytest

from rehub.cli import main
from tests.helpers import FIXTURES, FixtureExecutor

PCAP = str(FIXTURES / "ot-demo.pcap")
PUMP = str(FIXTURES / "plc" / "pump.st")


def test_analyze_prints_investigation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        ["--data", str(tmp_path), "analyze", PCAP, PUMP, "--plc-ip", "pump.st=10.0.0.20"],
        execute=FixtureExecutor(),
    )
    out = capsys.readouterr()
    assert code == 0
    assert "Assets (6)" in out.out
    assert "[high] S7comm PLC Stop  (suricata+zeek corroborated)" in out.out
    assert "PLC pump: Setpoint (%MW10, INT) = [1000]" in out.out
    assert "drives: ReliefValve" in out.out
    assert "T0858 Change Operating Mode" in out.out
    assert "candidates" in out.out
    assert "ingest" in out.err and "done" in out.err


def test_show_reloads_stored_investigation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["--data", str(tmp_path), "analyze", PCAP], execute=FixtureExecutor())
    capsys.readouterr()
    inv_id = next((tmp_path / "investigations").iterdir()).name
    assert main(["--data", str(tmp_path), "show", inv_id]) == 0
    assert "S7comm PLC Stop" in capsys.readouterr().out
    assert main(["--data", str(tmp_path), "show", "nope"]) == 1


def test_missing_file_and_bad_plc_ip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--data", str(tmp_path), "analyze", str(tmp_path / "x.pcap")]) == 2
    with pytest.raises(SystemExit):
        main(["--data", str(tmp_path), "analyze", PCAP, "--plc-ip", "nonsense"])


def test_serve_command_builds_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_serve(config: object, execute: object) -> None:
        seen["config"] = config

    monkeypatch.setattr("rehub.cli.serve", fake_serve)
    monkeypatch.setenv("REHUB_HOST", "0.0.0.0")
    assert main(["--data", str(tmp_path / "d"), "serve", "--port", "9999"]) == 0
    config = seen["config"]
    assert (config.host, config.port) == ("0.0.0.0", 9999)  # type: ignore[attr-defined]
    assert (tmp_path / "d").is_dir()
