import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.helpers import FIXTURES

IMAGE = os.environ.get("REHUB_IMAGE", "rehub:dev")


def _ready() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=False)
    return probe.returncode == 0


pytestmark = pytest.mark.skipif(not _ready(), reason="needs docker and rehub:dev image")


def test_cli_end_to_end_in_locked_down_container(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    data.chmod(0o777)
    uid = f"{os.getuid()}:{os.getgid()}"
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", uid,
        "-v", f"{FIXTURES}:/in:ro", "-v", f"{data}:/data", IMAGE,
        "rehub", "--data", "/data", "analyze", "/in/ot-demo.pcap", "/in/plc/pump.st",
        "--plc-ip", "pump.st=10.0.0.20",
    ]  # fmt: skip
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "Assets (6)" in out
    assert "[high] S7comm PLC Stop  (suricata+zeek corroborated)" in out
    assert "PLC pump: Setpoint (%MW10, INT) = [1000]" in out
    assert "FAILED" not in out
