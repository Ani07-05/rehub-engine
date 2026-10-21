import json
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

from rehub.adapters.base import SourceFile
from rehub.adapters.suricata import parse_suricata
from rehub.adapters.tshark import parse_tshark
from rehub.adapters.zeek import parse_zeek
from rehub.correlate import correlate
from rehub.ingest import IngestError, blob_path, ingest
from rehub.model import Investigation
from rehub.plc.analyze import project_events
from rehub.plc.formats import load_plc
from rehub.plc.model import PlcParseError, PlcProject
from rehub.schema import Event, Evidence, EvidenceKind
from rehub.serialize import (
    evidence_from_dict,
    investigation_from_dict,
    to_jsonable,
)
from rehub.sniff import sha256_file, sniff
from rehub.tools import (
    DEFAULT_TIMEOUT,
    Executor,
    ToolError,
    ToolOutput,
    run_suricata,
    run_tshark,
    run_zeek,
    subprocess_executor,
)

PLC_KINDS = frozenset({EvidenceKind.PLC_ST, EvidenceKind.PLC_PLCOPEN, EvidenceKind.PLC_L5X})
ZEEK_KINDS = frozenset({EvidenceKind.ZEEK_LOG})
TOOL_RUNNERS = {"zeek": run_zeek, "suricata": run_suricata, "tshark": run_tshark}
RECORD = "record.json"
STATUS = "status.json"
SUMMARY = "summary.json"

Progress = Callable[[str], None]


@dataclass(slots=True)
class ToolRun:
    tool: str
    pcap: str
    pcap_sha256: str
    ok: bool
    error: str = ""
    outputs: list[str] = field(default_factory=list)
    seconds: float = 0.0


@dataclass(slots=True)
class PlcSummary:
    name: str
    format: str
    source: str
    evidence_id: str
    controller_ips: list[str]
    model: str | None
    variables: int
    statements: int
    caveats: list[str]


def engine_version() -> str:
    try:
        return metadata.version("rehub")
    except metadata.PackageNotFoundError:
        return "unknown"


@dataclass(slots=True)
class Record:
    id: str
    created: str
    engine_version: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    tool_runs: list[ToolRun] = field(default_factory=list)
    plc: list[PlcSummary] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    investigation: Investigation = field(default_factory=Investigation)


def investigation_dir(data_dir: Path, inv_id: str) -> Path:
    return data_dir / "investigations" / inv_id


def _write_status(
    inv_dir: Path, stage: str, detail: str = "", tools: dict[str, str] | None = None
) -> None:
    payload: dict[str, Any] = {
        "stage": stage,
        "detail": detail,
        "tools": tools or {},
        "updated": datetime.now(UTC).isoformat(),
    }
    tmp = inv_dir / (STATUS + ".tmp")
    tmp.write_text(json.dumps(payload))
    tmp.replace(inv_dir / STATUS)


def read_status(data_dir: Path, inv_id: str) -> dict[str, Any] | None:
    path = investigation_dir(data_dir, inv_id) / STATUS
    return json.loads(path.read_text()) if path.is_file() else None


def save_record(data_dir: Path, record: Record) -> Path:
    inv_dir = investigation_dir(data_dir, record.id)
    path = inv_dir / RECORD
    tmp = inv_dir / (RECORD + ".tmp")
    tmp.write_text(json.dumps(to_jsonable(record), indent=1, sort_keys=True))
    tmp.replace(path)
    (inv_dir / SUMMARY).write_text(json.dumps(_summary_dict(record)))
    return path


def _summary_dict(record: Record) -> dict[str, Any]:
    inv = record.investigation
    return {
        "id": record.id,
        "created": record.created,
        "evidence": len(record.evidence),
        "assets": len(inv.assets),
        "flows": len(inv.flows),
        "detections": len(inv.detections),
        "high": sum(1 for d in inv.detections if d.severity == "high"),
        "warnings": len(record.warnings),
        "names": [e.name for e in record.evidence if not e.origin or e.origin == e.name][:5],
    }


def list_investigations(data_dir: Path) -> list[dict[str, Any]]:
    root = data_dir / "investigations"
    items: list[dict[str, Any]] = []
    for inv_dir in root.iterdir() if root.is_dir() else []:
        status = read_status(data_dir, inv_dir.name) or {"stage": "unknown", "updated": ""}
        summary_path = inv_dir / SUMMARY
        summary: dict[str, Any] = (
            json.loads(summary_path.read_text()) if summary_path.is_file() else {"id": inv_dir.name}
        )
        items.append({**summary, "stage": status["stage"], "updated": status.get("updated", "")})
    return sorted(items, key=lambda i: str(i.get("created") or i.get("updated")), reverse=True)


def load_record(data_dir: Path, inv_id: str) -> Record | None:
    path = investigation_dir(data_dir, inv_id) / RECORD
    if not path.is_file():
        return None
    d: dict[str, Any] = json.loads(path.read_text())
    return Record(
        id=d["id"],
        created=d["created"],
        engine_version=d.get("engine_version", ""),
        evidence=[evidence_from_dict(e) for e in d["evidence"]],
        tool_runs=[ToolRun(**t) for t in d["tool_runs"]],
        plc=[PlcSummary(**p) for p in d["plc"]],
        warnings=list(d["warnings"]),
        investigation=investigation_from_dict(d["investigation"]),
    )


def _derived(
    parent: Evidence, tool: str, output: ToolOutput, root: Path
) -> list[tuple[Evidence, Path]]:
    found: list[tuple[Evidence, Path]] = []
    for path in output.files:
        name = f"{tool}/{path.relative_to(root / tool).as_posix()}"
        if tool == "tshark":
            kind = EvidenceKind.TSHARK_TSV
        elif tool == "zeek":
            kind = EvidenceKind.ZEEK_LOG
        else:
            kind = sniff(path, name)
        found.append(
            (
                Evidence(
                    sha256=sha256_file(path),
                    name=name,
                    size=path.stat().st_size,
                    kind=kind,
                    origin=parent.name,
                    origin_sha256=parent.sha256,
                ),
                path,
            )
        )
    return found


def _run_tools(
    pcap: Evidence,
    store: Path,
    runs_root: Path,
    execute: Executor,
    timeout: float,
    notify: Callable[[str, str], None] | None = None,
) -> tuple[list[ToolRun], list[tuple[Evidence, Path]]]:
    src = blob_path(store, pcap.sha256)
    root = runs_root / pcap.sha256[:12]

    def one(tool: str) -> tuple[ToolRun, list[tuple[Evidence, Path]]]:
        started = time.monotonic()
        if notify:
            notify(tool, "running")
        try:
            output = TOOL_RUNNERS[tool](src, root / tool, execute, timeout)
        except ToolError as exc:
            if notify:
                notify(tool, "failed")
            run = ToolRun(
                tool, pcap.name, pcap.sha256, False, str(exc), [], time.monotonic() - started
            )
            return run, []
        derived = _derived(pcap, tool, output, root)
        if notify:
            notify(tool, "done")
        run = ToolRun(
            tool,
            pcap.name,
            pcap.sha256,
            True,
            "",
            [e.name for e, _ in derived],
            time.monotonic() - started,
        )
        return run, derived

    with ThreadPoolExecutor(max_workers=len(TOOL_RUNNERS)) as pool:
        results = list(pool.map(one, TOOL_RUNNERS))
    return [r for r, _ in results], [d for _, ds in results for d in ds]


def _summary(project: PlcProject) -> PlcSummary:
    return PlcSummary(
        name=project.name,
        format=project.format,
        source=project.source,
        evidence_id=project.evidence_id,
        controller_ips=sorted(project.controller_ips),
        model=project.model,
        variables=len(project.variables),
        statements=len(project.statements),
        caveats=list(project.caveats),
    )


def run_investigation(
    uploads: Sequence[Path],
    data_dir: Path,
    *,
    plc_ips: Mapping[str, str] | None = None,
    execute: Executor = subprocess_executor,
    timeout: float = DEFAULT_TIMEOUT,
    on_progress: Progress | None = None,
    investigation_id: str | None = None,
) -> Record:
    inv_id = investigation_id or uuid.uuid4().hex[:12]
    inv_dir = investigation_dir(data_dir, inv_id)
    inv_dir.mkdir(parents=True, exist_ok=False)
    store = data_dir / "store"
    record = Record(
        id=inv_id, created=datetime.now(UTC).isoformat(), engine_version=engine_version()
    )

    tool_states: dict[str, str] = {}
    state_lock = threading.Lock()
    current = {"stage": "ingest", "detail": ""}

    def progress(stage: str, detail: str = "") -> None:
        current.update(stage=stage, detail=detail)
        with state_lock:
            _write_status(inv_dir, stage, detail, dict(tool_states))
        if on_progress:
            on_progress(f"{stage}: {detail}" if detail else stage)

    try:
        progress("ingest")
        seen: set[str] = set()
        for upload in uploads:
            try:
                for ev in ingest(upload, store):
                    if ev.sha256 not in seen:
                        seen.add(ev.sha256)
                        record.evidence.append(ev)
            except IngestError as exc:
                record.warnings.append(f"{upload.name}: {exc}")

        zeek: list[SourceFile] = []
        suricata: list[SourceFile] = []
        tshark: list[SourceFile] = []
        projects: list[PlcProject] = []
        for ev in list(record.evidence):
            path = blob_path(store, ev.sha256)
            if ev.kind == EvidenceKind.PCAP:
                progress("analyze", f"running tools on {ev.name}")
                with state_lock:
                    tool_states.update({t: "queued" for t in TOOL_RUNNERS})

                def notify(tool: str, state: str) -> None:
                    with state_lock:
                        tool_states[tool] = state
                        _write_status(
                            inv_dir, current["stage"], current["detail"], dict(tool_states)
                        )

                runs, derived = _run_tools(ev, store, inv_dir / "runs", execute, timeout, notify)
                record.tool_runs += runs
                for run in runs:
                    if not run.ok:
                        record.warnings.append(f"{run.tool} failed on {ev.name}: {run.error}")
                for d_ev, d_path in derived:
                    record.evidence.append(d_ev)
                    src = SourceFile(d_path, d_ev.name, d_ev.sha256)
                    if d_ev.kind == EvidenceKind.TSHARK_TSV:
                        tshark.append(src)
                    elif d_ev.kind == EvidenceKind.ZEEK_LOG:
                        zeek.append(src)
                    elif d_ev.kind == EvidenceKind.SURICATA_EVE:
                        suricata.append(src)
            elif ev.kind in ZEEK_KINDS:
                zeek.append(SourceFile(path, ev.name, ev.sha256))
            elif ev.kind == EvidenceKind.SURICATA_EVE:
                suricata.append(SourceFile(path, ev.name, ev.sha256))
            elif ev.kind in PLC_KINDS:
                try:
                    projects.append(
                        load_plc(path, ev.name, ev.kind, ev.sha256, (plc_ips or {}).get(ev.name))
                    )
                except PlcParseError as exc:
                    record.warnings.append(f"{ev.name}: {exc}")
            else:
                record.warnings.append(
                    f"{ev.name}: {ev.kind.value} is stored but not analyzed yet."
                )

        progress("correlate")
        events: list[Event] = [
            *parse_zeek(zeek),
            *parse_suricata(suricata),
            *parse_tshark(tshark),
        ]
        for project in projects:
            events.extend(project_events(project))
        record.plc = [_summary(p) for p in projects]
        record.investigation = correlate(events, plc=projects)
        save_record(data_dir, record)
        progress("done")
    except BaseException as exc:
        _write_status(inv_dir, "failed", f"{type(exc).__name__}: {exc}")
        raise
    return record
