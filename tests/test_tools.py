import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from rehub import tools


class FakeExec:
    def __init__(
        self, returncode: int = 0, stderr: str = "", creates: tuple[str, ...] = ()
    ) -> None:
        self.returncode = returncode
        self.stderr = stderr
        self.creates = creates
        self.calls: list[tuple[Sequence[str], Path, float, Path | None]] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout: float,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, cwd, timeout, stdout_path))
        for name in self.creates:
            (cwd / name).write_text("x")
        return subprocess.CompletedProcess(argv, self.returncode, "", self.stderr)


def test_zeek_collects_logs_sorted(tmp_path: Path) -> None:
    fake = FakeExec(creates=("conn.log", "modbus.log"))
    out = tools.run_zeek(tmp_path / "a.pcap", tmp_path / "out", fake)
    assert [p.name for p in out.files] == ["conn.log", "modbus.log"]
    argv, cwd, _, _ = fake.calls[0]
    assert argv[:3] == ["zeek", "-C", "-r"]
    assert argv[-1] == tools.ZEEK_SCRIPT
    assert cwd == tmp_path / "out"


def test_suricata_argv_enables_ot_parsers(tmp_path: Path) -> None:
    argv = tools.suricata_argv(tmp_path / "a.pcap")
    assert "app-layer.protocols.modbus.enabled=yes" in argv
    assert "app-layer.protocols.enip.enabled=yes" in argv
    assert "outputs.1.eve-log.community-id=true" in argv
    assert argv[argv.index("-k") + 1] == "none"
    assert argv[argv.index("-S") + 1] == tools.SURICATA_RULES


def test_suricata_returns_eve(tmp_path: Path) -> None:
    out = tools.run_suricata(tmp_path / "a.pcap", tmp_path / "o", FakeExec(creates=("eve.json",)))
    assert [p.name for p in out.files] == ["eve.json"]


def test_suricata_no_eve_is_empty(tmp_path: Path) -> None:
    out = tools.run_suricata(tmp_path / "a.pcap", tmp_path / "o", FakeExec())
    assert out.files == ()


def test_tshark_streams_to_file(tmp_path: Path) -> None:
    fake = FakeExec()
    out = tools.run_tshark(tmp_path / "a.pcap", tmp_path / "o", fake)
    argv, _, _, stdout_path = fake.calls[0]
    assert stdout_path == tmp_path / "o" / "packets.tsv"
    assert out.files == (stdout_path,)
    assert argv.count("-e") == len(tools.TSHARK_FIELDS)
    assert "frame.time_epoch" in argv


def test_nonzero_exit_raises_with_stderr(tmp_path: Path) -> None:
    with pytest.raises(tools.ToolError, match="zeek exited 2: boom"):
        tools.run_zeek(tmp_path / "a.pcap", tmp_path / "o", FakeExec(returncode=2, stderr="boom"))


def test_stderr_truncated(tmp_path: Path) -> None:
    fake = FakeExec(returncode=1, stderr="E" * 10_000)
    with pytest.raises(tools.ToolError) as exc:
        tools.run_zeek(tmp_path / "a.pcap", tmp_path / "o", fake)
    assert len(str(exc.value)) < tools.STDERR_TAIL + 50


def test_timeout_wrapped(tmp_path: Path) -> None:
    def boom(
        argv: Sequence[str], *, cwd: Path, timeout: float, stdout_path: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(argv, timeout)

    with pytest.raises(tools.ToolError, match="timed out"):
        tools.run_suricata(tmp_path / "a.pcap", tmp_path / "o", boom, timeout=5)


def test_missing_binary_wrapped(tmp_path: Path) -> None:
    with pytest.raises(tools.ToolError, match="not installed"):
        tools.run_tshark(tmp_path / "a.pcap", tmp_path / "o")


def test_refuses_dirty_output_dir(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "conn.log").write_text("stale")
    fake = FakeExec()
    with pytest.raises(tools.ToolError, match="not empty"):
        tools.run_zeek(tmp_path / "a.pcap", out, fake)
    assert fake.calls == []
