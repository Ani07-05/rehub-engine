import re

from rehub.model import PlcImpact
from rehub.plc.analyze import usage, where
from rehub.plc.model import PlcProject, Statement, Variable

WORD_SIZE = {
    "BOOL": 1, "BYTE": 1, "WORD": 1, "INT": 1, "UINT": 1, "SINT": 1, "USINT": 1,
    "DINT": 2, "UDINT": 2, "DWORD": 2, "REAL": 2, "TIME": 2,
    "LINT": 4, "ULINT": 4, "LWORD": 4, "LREAL": 4,
}  # fmt: skip
ADDRESS = re.compile(r"^%M([WDF])(\d+)$", re.IGNORECASE)
ARRAY = re.compile(r"^ARRAY\s*\[([^\]]+)\]\s*OF\s+(\w+)", re.IGNORECASE)
MODBUS_ASSUMPTION = (
    "Assumes Modbus wire address N maps to %MW N (Schneider M580 and CODESYS default). "
    "Verify against the device's Modbus configuration."
)
READER_CAP = 5


def _element_words(dtype: str) -> tuple[int, bool]:
    size = WORD_SIZE.get(dtype.strip().upper())
    return (size, True) if size else (1, False)


def register_span(var: Variable) -> tuple[int, int, bool] | None:
    m = ADDRESS.match(var.address or "")
    if not m:
        return None
    unit, n = m.group(1).upper(), int(m.group(2))
    start = n if unit == "W" else n * 2
    dtype = var.dtype.strip()
    count = 1
    arr = ARRAY.match(dtype)
    if arr:
        for dim in arr.group(1).split(","):
            lo, _, hi = dim.partition("..")
            if lo.strip().lstrip("-").isdigit() and hi.strip().lstrip("-").isdigit():
                count *= int(hi) - int(lo) + 1
        dtype = arr.group(2)
    words, known = _element_words(dtype)
    if unit != "W":
        words, known = max(words, 2), known or dtype.upper() in ("REAL", "")
    return start, words * count, known


def _reader_text(stmt: Statement) -> str:
    cond = f"when {' and '.join(stmt.guards)}: " if stmt.guards else ""
    return f"{where(stmt)}: {cond}{stmt.text[:140]}"


def modbus_impacts(
    project: PlcProject, address: int, quantity: int, values: str = ""
) -> list[PlcImpact]:
    writers, readers = usage(project)
    impacts: list[tuple[int, PlcImpact]] = []
    for key, var in project.variables.items():
        span = register_span(var)
        if span is None:
            continue
        start, size, known = span
        if not (start < address + quantity and address < start + size):
            continue
        stmts = readers.get(key, [])
        drives = [
            project.variables[s.target].name
            for s in stmts
            if s.target and s.target != key and s.target in project.variables
        ]
        impacts.append(
            (
                start,
                PlcImpact(
                    project=project.name,
                    variable=var.name,
                    address=var.address or "",
                    dtype=var.dtype,
                    comment=var.comment,
                    readers=[_reader_text(s) for s in stmts[:READER_CAP]],
                    drives=list(dict.fromkeys(drives)),
                    new_values=values,
                    assumption=MODBUS_ASSUMPTION,
                    size_known=known,
                ),
            )
        )
    return [i for _, i in sorted(impacts, key=lambda t: t[0])]
