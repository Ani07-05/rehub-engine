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
