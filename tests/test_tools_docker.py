import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

IMAGE = os.environ.get("REHUB_IMAGE", "rehub:dev")
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=False)
    return probe.returncode == 0


pytestmark = pytest.mark.skipif(not _docker_ready(), reason="needs docker and rehub:dev image")

SCRIPT = """
from pathlib import Path
from rehub import tools
p = Path('/in/ot-demo.pcap')
for fn, d in (
    (tools.run_zeek, 'zeek'),
    (tools.run_suricata, 'suricata'),
    (tools.run_tshark, 'tshark'),
):
    fn(p, Path('/out') / d)
"""


@pytest.fixture(scope="module")
def outdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("run")
    out.chmod(0o777)
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
        "-v", f"{FIXTURES}:/in:ro", "-v", f"{out}:/out", IMAGE, "python3", "-c", SCRIPT,
    ]  # fmt: skip
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    return out


def test_zeek_sees_ot_protocols(outdir: Path) -> None:
    services = {
        json.loads(line).get("service")
        for line in (outdir / "zeek" / "conn.log").read_text().splitlines()
    }
    assert "modbus" in services
    assert "cotp,s7comm" in services


def test_suricata_fires_ot_rules(outdir: Path) -> None:
    sigs = {
        json.loads(line)["alert"]["signature"]
        for line in (outdir / "suricata" / "eve.json").read_text().splitlines()
        if '"event_type":"alert"' in line
    }
    assert "REHUB Modbus write single register" in sigs
    assert "REHUB S7comm PLC stop" in sigs


def test_tshark_lists_every_packet(outdir: Path) -> None:
    lines = (outdir / "tshark" / "packets.tsv").read_text().splitlines()
    assert len(lines) == 108
