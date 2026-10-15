import re
from dataclasses import dataclass

from rehub.plc.model import PlcProject, Statement, Variable

SECTIONS = {
    "VAR": "local",
    "VAR_TEMP": "local",
    "VAR_STAT": "local",
    "VAR_INPUT": "input",
    "VAR_OUTPUT": "output",
    "VAR_IN_OUT": "inout",
    "VAR_GLOBAL": "global",
    "VAR_EXTERNAL": "external",
}
POU_START = re.compile(
    r"^\s*(PROGRAM|FUNCTION_BLOCK|FUNCTION)\s+(\w+)", re.IGNORECASE | re.MULTILINE
)
VAR_BLOCK = re.compile(
    r"\b(VAR(?:_TEMP|_STAT|_INPUT|_OUTPUT|_IN_OUT|_GLOBAL|_EXTERNAL)?)\b(?:\s+(?:CONSTANT|RETAIN|PERSISTENT))*"
    r"(.*?)\bEND_VAR\b",
    re.IGNORECASE | re.DOTALL,
)
DECL = re.compile(
    r"([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?:AT\s+(%[A-Za-z]+[\d\.]+))?\s*:(?!=)\s*"
    r"([^:;]+?)\s*(?::=\s*([^;]+?))?\s*;",
    re.IGNORECASE,
)
DELIMS = re.compile(
    r"\b(IF|ELSIF|THEN|ELSE|END_IF|CASE|END_CASE|FOR|WHILE|DO|END_FOR|END_WHILE|"
    r"REPEAT|UNTIL|END_REPEAT|OF)\b|;",
    re.IGNORECASE,
)
IDENT = re.compile(r"[A-Za-z_]\w*(?:(?:\.[A-Za-z_]\w*)|(?:\[[^\]]*\]))*")
LITERAL_PREFIX = re.compile(r"\b[A-Za-z_]*#[\w\.:\-]+")
NUMBER = re.compile(r"(?<![\w\.])\d+(?![\w\.])")
KEYWORDS = frozenset(
    {
        "TRUE",
        "FALSE",
        "AND",
        "OR",
        "NOT",
        "XOR",
        "MOD",
        "THEN",
        "DO",
        "OF",
        "TO",
        "BY",
        "RETURN",
        "EXIT",
    }
)
CALL = re.compile(r"^[A-Za-z_][\w\.]*\s*\(")
ASSIGN = re.compile(r"^(.*?)(?<![<>:])\s*:=\s*(.*)$", re.DOTALL)
CASE_LABEL = re.compile(r"^\s*([\w\.,\s\-#]+?)\s*:(?!=)\s*(.*)$", re.DOTALL)


@dataclass(frozen=True, slots=True)
class Pou:
    name: str
    kind: str
    decl: str
    body: str
    body_line: int


def strip_comments(text: str) -> str:
    def blank(m: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))

    text = re.sub(r"\(\*.*?\*\)", blank, text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", blank, text)
    return re.sub(r"'(?:[^'\\\n]|\$.)*'", blank, text)


def split_pous(text: str) -> list[Pou]:
    code = strip_comments(text)
    starts = list(POU_START.finditer(code))
    pous: list[Pou] = []
    for i, m in enumerate(starts):
        end = starts[i + 1].start() if i + 1 < len(starts) else len(code)
        chunk = code[m.start() : end]
        last_end_var = max(
            (x.end() for x in VAR_BLOCK.finditer(chunk)), default=m.end() - m.start()
        )
        decl = chunk[:last_end_var]
        body = chunk[last_end_var:]
        body = re.sub(r"\bEND_(PROGRAM|FUNCTION_BLOCK|FUNCTION)\b.*$", "", body, flags=re.I | re.S)
        body_line = code.count("\n", 0, m.start() + last_end_var) + 1
        pous.append(Pou(m.group(2), m.group(1).upper(), decl, body, body_line))
    return pous


def global_decl_text(text: str) -> str:
    code = strip_comments(text)
    first = POU_START.search(code)
    return code[: first.start()] if first else code


def parse_declarations(text: str, unit: str, line_offset: int = 0) -> list[Variable]:
    found: list[Variable] = []
    for block in VAR_BLOCK.finditer(text):
        section = SECTIONS.get(block.group(1).upper(), "local")
        base_line = line_offset + text.count("\n", 0, block.start(2))
        for d in DECL.finditer(block.group(2)):
            line = base_line + block.group(2).count("\n", 0, d.start()) + 1
            for name in (n.strip() for n in d.group(1).split(",")):
                key = name if section == "global" else f"{unit}.{name}"
                found.append(
                    Variable(
                        key=key,
                        name=name,
                        unit="" if section == "global" else unit,
                        section=section,
                        dtype=" ".join(d.group(3).split()),
                        address=d.group(2),
                        initial=d.group(4).strip() if d.group(4) else None,
                        line=line,
                    )
                )
    return found


def _identifiers(expr: str, project: PlcProject, unit: str) -> list[str]:
    cleaned = LITERAL_PREFIX.sub(" ", expr)
    out: list[str] = []
    for m in IDENT.finditer(cleaned):
        base = re.split(r"[\.\[]", m.group(0), maxsplit=1)[0]
        if base.upper() in KEYWORDS:
            continue
        key = project.resolve(unit, base)
        if key and key not in out:
            out.append(key)
    return out


def _literals(expr: str) -> list[int]:
    return [int(n) for n in NUMBER.findall(LITERAL_PREFIX.sub(" ", expr)) if len(n) < 12]


def parse_body(body: str, unit: str, first_line: int, project: PlcProject) -> list[Statement]:
    stack: list[str] = []
    statements: list[Statement] = []
    pos = 0
    pending: tuple[str, int] | None = None
    case_subject: str | None = None

    def line_of(offset: int) -> int:
        return first_line + body.count("\n", 0, offset)

    for m in DELIMS.finditer(body):
        chunk = body[pos : m.start()]
        token = m.group(0).upper()
        chunk_line = line_of(pos + (len(chunk) - len(chunk.lstrip())))
        pos = m.end()
        if pending is not None:
            kind, _ = pending
            cond = " ".join(chunk.split())
            if token in ("THEN", "DO", "OF"):
                if kind == "ELSIF" and stack:
                    stack[-1] = cond
                else:
                    stack.append(cond if kind != "CASE" else f"CASE {cond}")
                if kind == "CASE":
                    case_subject = cond
                pending = None
                continue
        if token in ("IF", "ELSIF", "WHILE", "FOR", "CASE"):
            pending = (token, chunk_line)
            continue
        if token == "REPEAT":
            stack.append("REPEAT")
            continue
        if token == "ELSE":
            if stack:
                stack[-1] = f"NOT ({stack[-1]})"
            continue
        if token in ("END_IF", "END_WHILE", "END_FOR", "END_CASE", "END_REPEAT", "UNTIL"):
            if stack:
                stack.pop()
            if token == "END_CASE":
                case_subject = None
            continue
        if token != ";":
            continue
        text = " ".join(chunk.split())
        if not text:
            continue
        guards = list(stack)
        label = CASE_LABEL.match(text) if case_subject and ":=" not in text.split(":")[0] else None
        if label and case_subject:
            guards.append(f"{case_subject} = {label.group(1).strip()}")
            text = " ".join(label.group(2).split())
        assign = None if CALL.match(text) else ASSIGN.match(text)
        guard_reads = list(dict.fromkeys(k for g in guards for k in _identifiers(g, project, unit)))
        guard_literals = [n for g in guards for n in _literals(g)]
        if assign:
            target_name = re.split(r"[\.\[]", assign.group(1).strip(), maxsplit=1)[0]
            target = project.resolve(unit, target_name)
            statements.append(
                Statement(
                    unit=unit,
                    line=chunk_line,
                    text=text,
                    target=target,
                    reads=_identifiers(assign.group(2), project, unit),
                    guards=guards,
                    guard_reads=guard_reads,
                    literals=guard_literals + _literals(assign.group(2)),
                )
            )
        else:
            statements.append(
                Statement(
                    unit=unit,
                    line=chunk_line,
                    text=text,
                    target=None,
                    reads=_identifiers(text, project, unit),
                    guards=guards,
                    guard_reads=guard_reads,
                    literals=guard_literals,
                    kind="call",
                )
            )
    return statements
