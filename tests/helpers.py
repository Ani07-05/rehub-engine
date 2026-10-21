import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
DEMO = FIXTURES / "ot-demo"


class FixtureExecutor:
    def __init__(self, fail: set[str] | None = None) -> None:
        self.fail = fail or set()
        self.calls: list[str] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout: float,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        tool = argv[0]
        self.calls.append(tool)
        if tool in self.fail:
            return subprocess.CompletedProcess(argv, 3, "", f"{tool} exploded")
        if tool == "zeek":
            for log in (DEMO / "zeek").glob("*.log"):
                shutil.copy(log, cwd / log.name)
        elif tool == "suricata":
            shutil.copy(DEMO / "suricata" / "eve.json", cwd / "eve.json")
        elif tool == "tshark" and stdout_path is not None:
            shutil.copy(DEMO / "tshark" / "packets.tsv", stdout_path)
        return subprocess.CompletedProcess(argv, 0, "", "")


PROBES = {
    ("zeek", "--version"): "zeek version 8.0.10",
    ("zeek", "-N"): "ICSNPP::ENIP - Ethernet/IP (dynamic)\nICSNPP::S7COMM - S7comm (dynamic)",
    ("suricata", "-V"): "This is Suricata version 8.0.7 RELEASE",
    ("tshark", "--version"): "TShark (Wireshark) 4.4.19.",
}


class ProbeExecutor(FixtureExecutor):
    def __init__(
        self,
        fail: set[str] | None = None,
        missing: set[str] | None = None,
        probes: dict[tuple[str, str], str] | None = None,
        no_alerts: bool = False,
    ) -> None:
        super().__init__(fail)
        self.missing = missing or set()
        self.probes = {**PROBES, **(probes or {})}
        self.no_alerts = no_alerts

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout: float,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if argv[0] in self.missing:
            raise FileNotFoundError(2, "No such file", argv[0])
        key = (argv[0], argv[1]) if len(argv) == 2 else None
        if key in self.probes:
            return subprocess.CompletedProcess(argv, 0, self.probes[key], "")
        proc = super().__call__(argv, cwd=cwd, timeout=timeout, stdout_path=stdout_path)
        if self.no_alerts and argv[0] == "suricata":
            (cwd / "eve.json").write_text("")
        return proc
