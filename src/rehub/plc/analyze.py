import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass

from rehub.plc.model import PlcProject, Statement
from rehub.schema import Event, EventKind

TIMING_TYPES = frozenset(
    {"TON", "TOF", "TP", "CTU", "CTD", "CTUD", "TIMER", "COUNTER", "TIME", "DATE", "DT", "TOD",
     "TIME_OF_DAY", "DATE_AND_TIME"}
)  # fmt: skip
LARGE_CONSTANT = 10_000
LATCH_OPS = re.compile(r"\b(OTL|OTU)\(")
MEMORY_ADDRESS = re.compile(r"^%M[WDF]\d+$", re.IGNORECASE)
REVIEW_NOTE = "Review hint from static analysis, not a verdict."


@dataclass(frozen=True, slots=True)
class PlcFinding:
    rule: str
    title: str
    severity: str
    variable: str | None
    where: str
    detail: str


def where(stmt: Statement) -> str:
    unit = f"{stmt.unit}/{stmt.routine}" if stmt.routine else stmt.unit
    return f"{unit}:{stmt.line}"


def canon(project: PlcProject, key: str) -> str:
    for _ in range(8):
        var = project.variables.get(key)
        if var is None or not var.alias_for:
            return key
        base = re.split(r"[\.\[]", var.alias_for, maxsplit=1)[0]
        nxt = project.resolve(var.unit, base)
        if nxt is None or nxt == key:
            return key
        key = nxt
    return key


def usage(
    project: PlcProject,
) -> tuple[dict[str, list[Statement]], dict[str, list[Statement]]]:
    writers: dict[str, list[Statement]] = defaultdict(list)
    readers: dict[str, list[Statement]] = defaultdict(list)
    for stmt in project.statements:
        if stmt.target:
            writers[canon(project, stmt.target)].append(stmt)
        for key in (*stmt.reads, *stmt.guard_reads):
            readers[canon(project, key)].append(stmt)
    return writers, readers


def _is_counter(project: PlcProject, key: str, writers: dict[str, list[Statement]]) -> bool:
    return any(key in s.reads or key in s.guard_reads for s in writers.get(key, []))


def _unused(
    project: PlcProject, writers: dict[str, list[Statement]], readers: dict[str, list[Statement]]
) -> Iterator[PlcFinding]:
    for key, var in project.variables.items():
        base = canon(project, key)
        if base != key or base in writers or base in readers:
            continue
        label = f"{var.unit}.{var.name}" if var.unit else var.name
        if var.address and MEMORY_ADDRESS.match(var.address):
            yield PlcFinding(
                "mapped_but_unreferenced",
                f"{var.name} ({var.address}) is exposed but not used by logic",
                "low",
                key,
                f"{label} line {var.line}" if var.line else label,
                "Memory word reachable over fieldbus but no program logic reads or writes it. "
                + REVIEW_NOTE,
            )
        elif not var.address and var.section not in ("input", "external"):
            yield PlcFinding(
                "unused_variable",
                f"Unused variable {var.name}",
                "low",
                key,
                f"{label} line {var.line}" if var.line else label,
                "Declared but never referenced.",
            )


def _slot(stmt: Statement) -> tuple[str, str, tuple[str, ...]]:
    guards = list(stmt.guards)
    if guards and guards[-1].startswith("NOT (") and guards[-1].endswith(")"):
        guards[-1] = guards[-1][5:-1]
    return stmt.unit, stmt.routine, tuple(guards)


def _multiple_writers(
    project: PlcProject, writers: dict[str, list[Statement]]
) -> Iterator[PlcFinding]:
    for key, stmts in writers.items():
        var = project.variables.get(key)
        if var is None or not (var.is_output or var.address):
            continue
        plain = [s for s in stmts if not LATCH_OPS.search(s.text)]
        if len({_slot(s) for s in plain}) < 2:
            continue
        sites = ", ".join(where(s) for s in plain[:5])
        yield PlcFinding(
            "multiple_writers",
            f"{var.name} is written from {len(plain)} places",
            "low",
            key,
            where(plain[0]),
            f"Writers: {sites}. Later writes override earlier ones within a scan. " + REVIEW_NOTE,
        )


def _gated_outputs(
    project: PlcProject, writers: dict[str, list[Statement]]
) -> Iterator[PlcFinding]:
    for stmt in project.statements:
        if not stmt.target:
            continue
        var = project.variables.get(canon(project, stmt.target))
        if var is None or not var.is_output or not stmt.guards:
            continue
        timing = [
            k
            for k in stmt.guard_reads
            if project.variables[k].dtype.upper() in TIMING_TYPES
            or _is_counter(project, canon(project, k), writers)
        ]
        big = [n for n in stmt.literals if n >= LARGE_CONSTANT]
        if not timing and not big:
            continue
        reason = (
            f"gated by counter/timer {', '.join(project.variables[k].name for k in timing)}"
            if timing
            else f"gated by large constant {big[0]}"
        )
        yield PlcFinding(
            "gated_output_write",
            f"Output {var.name} {reason}",
            "medium" if timing else "low",
            canon(project, stmt.target),
            where(stmt),
            f"`{stmt.text}` under {'; '.join(stmt.guards)}. Counter or time-gated output writes "
            f"can be dormant logic. {REVIEW_NOTE}",
        )


def findings(project: PlcProject) -> list[PlcFinding]:
    writers, readers = usage(project)
    out = [
        *_unused(project, writers, readers),
        *_multiple_writers(project, writers),
        *_gated_outputs(project, writers),
    ]
    return sorted(out, key=lambda f: (f.severity != "medium", f.where, f.rule))


def project_events(project: PlcProject) -> Iterator[Event]:
    ip = sorted(project.controller_ips)[0] if project.controller_ips else None
    for f in findings(project):
        yield Event(
            ts=None,
            tool="plc",
            kind=EventKind.LOGIC,
            evidence_id=project.evidence_id,
            dst=ip,
            proto=project.format,
            severity=f.severity,
            summary=f.title,
            ref=f"{project.source}:{f.where}",
            attrs={
                "rule": f.rule,
                "variable": f.variable or "",
                "detail": f.detail,
                "project": project.name,
            },
        )
