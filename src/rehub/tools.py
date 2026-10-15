import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

ZEEK_SCRIPT = "/opt/rehub/zeek/rehub.zeek"
SURICATA_CONFIG = "/opt/suricata/etc/suricata/suricata.yaml"
SURICATA_RULES = "/opt/rehub/suricata/rehub.rules"
SURICATA_SETTINGS = {
    "app-layer.protocols.modbus.enabled": "yes",
    "app-layer.protocols.enip.enabled": "yes",
    "outputs.1.eve-log.community-id": "true",
}
TSHARK_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "ipv6.nxt",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "_ws.col.protocol",
    "_ws.col.info",
    "eth.src",
    "eth.dst",
    "arp.src.hw_mac",
    "arp.src.proto_ipv4",
)
DEFAULT_TIMEOUT = 1800.0
STDERR_TAIL = 2000


class ToolError(RuntimeError):
    pass


class Executor(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout: float,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


def subprocess_executor(
    argv: Sequence[str], *, cwd: Path, timeout: float, stdout_path: Path | None = None
) -> subprocess.CompletedProcess[str]:
    env = {"PATH": "/usr/local/zeek/bin:/opt/suricata/bin:/usr/bin:/bin", "LC_ALL": "C"}
    if stdout_path is None:
        return subprocess.run(
            argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=False
        )
    with stdout_path.open("wb") as out:
        proc = subprocess.run(
            argv, cwd=cwd, env=env, stdout=out, stderr=subprocess.PIPE, timeout=timeout, check=False
        )
    return subprocess.CompletedProcess(
        argv, proc.returncode, "", proc.stderr.decode(errors="replace")
    )


@dataclass(frozen=True, slots=True)
class ToolOutput:
    tool: str
    files: tuple[Path, ...]


def _run(
    tool: str,
    argv: Sequence[str],
    outdir: Path,
    execute: Executor,
    timeout: float,
    stdout_path: Path | None = None,
) -> None:
    if outdir.exists() and any(outdir.iterdir()):
        raise ToolError(f"{tool} output dir {outdir} is not empty")
    outdir.mkdir(parents=True, exist_ok=True)
    try:
        proc = execute(argv, cwd=outdir, timeout=timeout, stdout_path=stdout_path)
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"{tool} timed out after {timeout:.0f}s") from exc
    except FileNotFoundError as exc:
        raise ToolError(f"{tool} not installed: {exc.filename}") from exc
    if proc.returncode != 0:
        raise ToolError(f"{tool} exited {proc.returncode}: {proc.stderr.strip()[-STDERR_TAIL:]}")


def run_zeek(
    pcap: Path,
    outdir: Path,
    execute: Executor = subprocess_executor,
    timeout: float = DEFAULT_TIMEOUT,
) -> ToolOutput:
    _run("zeek", ["zeek", "-C", "-r", str(pcap.resolve()), ZEEK_SCRIPT], outdir, execute, timeout)
    return ToolOutput("zeek", tuple(sorted(outdir.glob("*.log"))))


def suricata_argv(pcap: Path) -> list[str]:
    argv = [
        "suricata", "-r", str(pcap.resolve()), "-S", SURICATA_RULES, "-c", SURICATA_CONFIG,
        "-l", ".", "-k", "none", "--runmode", "single",
    ]  # fmt: skip
    for key, value in SURICATA_SETTINGS.items():
        argv += ["--set", f"{key}={value}"]
    return argv


def run_suricata(
    pcap: Path,
    outdir: Path,
    execute: Executor = subprocess_executor,
    timeout: float = DEFAULT_TIMEOUT,
) -> ToolOutput:
    _run("suricata", suricata_argv(pcap), outdir, execute, timeout)
    eve = outdir / "eve.json"
    return ToolOutput("suricata", (eve,) if eve.exists() else ())


def tshark_argv(pcap: Path) -> list[str]:
    argv = ["tshark", "-r", str(pcap.resolve()), "-T", "fields", "-E", "separator=/t"]
    for field in TSHARK_FIELDS:
        argv += ["-e", field]
    return argv


def run_tshark(
    pcap: Path,
    outdir: Path,
    execute: Executor = subprocess_executor,
    timeout: float = DEFAULT_TIMEOUT,
) -> ToolOutput:
    out = outdir / "packets.tsv"
    _run("tshark", tshark_argv(pcap), outdir, execute, timeout, stdout_path=out)
    return ToolOutput("tshark", (out,))
