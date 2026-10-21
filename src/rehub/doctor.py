import json
import re
import shutil
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from rehub import tools
from rehub.tools import Executor, ToolError, subprocess_executor

SELFTEST_PCAP = Path(__file__).parent / "data" / "selftest.pcap"
MIN_FREE_WARN = 5 << 30
MIN_FREE_FAIL = 512 << 20
PROBE_TIMEOUT = 20.0
EXPECTED_PLUGINS = ("ICSNPP::S7COMM", "ICSNPP::ENIP")
OK, WARN, FAIL = "ok", "warn", "fail"


@dataclass(slots=True)
class Check:
    id: str
    label: str
    status: str
    detail: str = ""
    fix: str = ""


@dataclass(slots=True)
class Report:
    checks: list[Check] = field(default_factory=list)
    checked_at: float = 0.0

    @property
    def status(self) -> str:
        states = {c.status for c in self.checks}
        return FAIL if FAIL in states else WARN if WARN in states else OK


def _probe(execute: Executor, argv: list[str], cwd: Path) -> tuple[int, str]:
    try:
        proc = execute(argv, cwd=cwd, timeout=PROBE_TIMEOUT, stdout_path=None)
    except FileNotFoundError:
        return 127, f"{argv[0]} is not installed"
    except Exception as exc:
        return 1, f"{type(exc).__name__}: {exc}"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _first_version(text: str) -> str:
    match = re.search(r"\d+\.\d+(?:\.\d+)?", text)
    return match.group(0) if match else ""


def check_data_dir(data_dir: Path) -> list[Check]:
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=data_dir):
            pass
    except OSError as exc:
        return [
            Check(
                "data",
                "Data folder",
                FAIL,
                f"{data_dir} is not writable: {exc.strerror}",
                "Mount a writable folder at the data path.",
            )
        ]
    free = shutil.disk_usage(data_dir).free
    gib = free / (1 << 30)
    if free < MIN_FREE_FAIL:
        status, fix = FAIL, "Free disk space before analyzing evidence."
    elif free < MIN_FREE_WARN:
        status, fix = WARN, "Large captures need several GB of free space."
    else:
        status, fix = OK, ""
    return [
        Check("data", "Data folder", OK, f"{data_dir} is writable"),
        Check("disk", "Free disk space", status, f"{gib:.1f} GB free", fix),
    ]


def check_tools(execute: Executor, cwd: Path) -> list[Check]:
    out: list[Check] = []
    rc, text = _probe(execute, ["zeek", "--version"], cwd)
    if rc != 0:
        out.append(
            Check(
                "zeek",
                "Zeek",
                FAIL,
                text or "did not start",
                "Use the ReHub image, which bundles Zeek.",
            )
        )
    else:
        out.append(Check("zeek", "Zeek", OK, f"version {_first_version(text) or text}"))
        rc, plugins = _probe(execute, ["zeek", "-N"], cwd)
        missing = [p for p in EXPECTED_PLUGINS if p not in plugins]
        out.append(
            Check(
                "zeek-ics",
                "Zeek industrial protocol plugins",
                WARN,
                f"missing {', '.join(missing)}",
                "S7 and EtherNet/IP traffic will not be parsed.",
            )
            if rc == 0 and missing
            else Check(
                "zeek-ics",
                "Zeek industrial protocol plugins",
                OK,
                "S7comm and EtherNet/IP available",
            )
        )
    rc, text = _probe(execute, ["suricata", "-V"], cwd)
    out.append(
        Check("suricata", "Suricata", OK, f"version {_first_version(text) or text}")
        if rc == 0
        else Check(
            "suricata",
            "Suricata",
            FAIL,
            text or "did not start",
            "Use the ReHub image, which bundles Suricata.",
        )
    )
    rc, text = _probe(execute, ["tshark", "--version"], cwd)
    first = text.splitlines()[0] if text else ""
    out.append(
        Check("tshark", "tshark", OK, f"version {_first_version(first) or first}")
        if rc == 0
        else Check(
            "tshark",
            "tshark",
            FAIL,
            text or "did not start",
            "Use the ReHub image, which bundles tshark.",
        )
    )
    return out


def _evidence_checks(root: Path) -> list[Check]:
    out: list[Check] = []
    modbus = root / "zeek" / "modbus.log"
    zeek_ok = modbus.is_file() and "WRITE_SINGLE_REGISTER" in modbus.read_text(errors="replace")
    out.append(
        Check(
            "selftest-zeek",
            "Zeek reads a sample capture",
            OK if zeek_ok else FAIL,
            "found the Modbus write" if zeek_ok else "did not find the expected Modbus write",
            "" if zeek_ok else "Zeek ran but did not parse Modbus.",
        )
    )
    eve = root / "suricata" / "eve.json"
    alerted = False
    if eve.is_file():
        for line in eve.read_text(errors="replace").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert" and event.get("alert", {}).get(
                "signature_id"
            ) in (9000001, 9000002):
                alerted = True
    out.append(
        Check(
            "selftest-suricata",
            "Suricata raises an alert on a sample capture",
            OK if alerted else FAIL,
            "the Modbus write rule fired"
            if alerted
            else "no alert fired for the sample Modbus write",
            "" if alerted else "Suricata rules did not load or Modbus parsing is off.",
        )
    )
    packets = root / "tshark" / "packets.tsv"
    listed = packets.is_file() and any(
        "502" in ln for ln in packets.read_text(errors="replace").splitlines()
    )
    out.append(
        Check(
            "selftest-tshark",
            "tshark lists the sample packets",
            OK if listed else FAIL,
            "packet list contains the Modbus conversation"
            if listed
            else "no Modbus packets listed",
            "" if listed else "tshark did not read the sample capture.",
        )
    )
    return out


def check_selftest(execute: Executor) -> list[Check]:
    if not SELFTEST_PCAP.is_file():
        return [
            Check(
                "selftest",
                "Sample capture",
                FAIL,
                "built-in sample capture is missing",
                "Reinstall ReHub.",
            )
        ]
    with tempfile.TemporaryDirectory(prefix="rehub-selftest-") as tmp:
        root = Path(tmp)
        pcap = root / "selftest.pcap"
        shutil.copy(SELFTEST_PCAP, pcap)
        failures: list[Check] = []
        for name, runner in (
            ("zeek", tools.run_zeek),
            ("suricata", tools.run_suricata),
            ("tshark", tools.run_tshark),
        ):
            try:
                runner(pcap, root / name, execute, 60.0)
            except ToolError as exc:
                failures.append(
                    Check(
                        f"selftest-{name}",
                        f"{name} on a sample capture",
                        FAIL,
                        str(exc),
                        "Check the tool installation.",
                    )
                )
        if failures:
            return failures
        return _evidence_checks(root)


def check_auth(enabled: bool) -> Check:
    if enabled:
        return Check("auth", "Sign-in", OK, "an access token is required")
    return Check(
        "auth",
        "Sign-in",
        WARN,
        "authentication is off",
        "Anyone who can reach this port can use ReHub. Start without --no-auth.",
    )


def run_doctor(
    data_dir: Path,
    execute: Executor = subprocess_executor,
    auth_enabled: bool = True,
    quick: bool = False,
    clock: Callable[[], float] = time.time,
) -> Report:
    report = Report(checked_at=clock())
    report.checks += check_data_dir(data_dir)
    probe_dir = data_dir if data_dir.is_dir() else Path(tempfile.gettempdir())
    tool_checks = check_tools(execute, probe_dir)
    report.checks += tool_checks
    report.checks.append(check_auth(auth_enabled))
    if not quick and all(c.status != FAIL for c in tool_checks):
        report.checks += check_selftest(execute)
    return report
