import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from rehub.plc import st
from rehub.plc.model import PlcParseError, PlcProject, Statement, Variable
from rehub.schema import EvidenceKind

MAX_BYTES = 64 << 20
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PLCOPEN_SECTIONS = {
    "inputVars": "input",
    "outputVars": "output",
    "inOutVars": "inout",
    "localVars": "local",
    "tempVars": "local",
    "externalVars": "external",
    "globalVars": "global",
}
L5X_CONDITIONS = frozenset(
    {
        "XIC",
        "XIO",
        "EQU",
        "NEQ",
        "GRT",
        "GEQ",
        "LES",
        "LEQ",
        "LIM",
        "CMP",
        "MEQ",
        "ONS",
        "OSR",
        "OSF",
    }
)
L5X_DEST = {
    "OTE": (0,),
    "OTL": (0,),
    "OTU": (0,),
    "CLR": (0,),
    "CPT": (0,),
    "MOV": (1,),
    "COP": (1,),
    "CPS": (1,),
    "ADD": (2,),
    "SUB": (2,),
    "MUL": (2,),
    "DIV": (2,),
}
INSTRUCTION = re.compile(r"\b([A-Z][A-Z0-9_]*)\(")


def _stem(name: str) -> str:
    return PurePosixPath(name).stem


def _read(path: Path) -> bytes:
    if path.stat().st_size > MAX_BYTES:
        raise PlcParseError(f"{path.name}: larger than {MAX_BYTES} bytes")
    return path.read_bytes()


def _safe_xml(path: Path) -> ET.Element:
    raw = _read(path)
    head = raw.lower()
    if b"<!doctype" in head or b"<!entity" in head:
        raise PlcParseError(f"{path.name}: DTD and entity declarations are not accepted")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise PlcParseError(f"{path.name}: invalid XML: {exc}") from exc


def _ln(el: ET.Element) -> str:
    return el.tag.rsplit("}", 1)[-1]


def _children(el: ET.Element, name: str) -> Iterator[ET.Element]:
    return (c for c in el if _ln(c) == name)


def _descendants(el: ET.Element, name: str) -> Iterator[ET.Element]:
    return (c for c in el.iter() if _ln(c) == name)


def load_st(
    path: Path, name: str, evidence_id: str = "", asset_ip: str | None = None
) -> PlcProject:
    text = _read(path).decode("utf-8-sig", errors="replace")
    project = PlcProject(name=_stem(name), format="st", source=name, evidence_id=evidence_id)
    if asset_ip:
        project.controller_ips.add(asset_ip)
    pous = st.split_pous(text)
    if not pous:
        raise PlcParseError(f"{name}: no PROGRAM, FUNCTION_BLOCK or FUNCTION found")
    for v in st.parse_declarations(st.global_decl_text(text), "", 0):
        project.variables[v.key] = v
    for pou in pous:
        for v in st.parse_declarations(
            pou.decl, pou.name, pou.body_line - pou.decl.count("\n") - 1
        ):
            project.variables[v.key] = v
    for pou in pous:
        project.statements += st.parse_body(pou.body, pou.name, pou.body_line, project)
    return project


def _plcopen_type(el: ET.Element | None) -> str:
    if el is None:
        return ""
    kids = list(el)
    if not kids:
        return ""
    t = kids[0]
    tag = _ln(t)
    if tag == "derived":
        return t.get("name", "derived")
    if tag == "array":
        dims = [(d.get("lower", "0"), d.get("upper", "0")) for d in _children(t, "dimension")]
        base = next(_children(t, "baseType"), None)
        spans = ",".join(f"{lo}..{hi}" for lo, hi in dims)
        return f"ARRAY [{spans}] OF {_plcopen_type(base)}"
    if tag == "string":
        return "STRING"
    return tag.upper()


def _plcopen_vars(section: ET.Element, unit: str, kind: str) -> Iterator[Variable]:
    for var in _children(section, "variable"):
        name = var.get("name", "")
        doc = next(_descendants(var, "documentation"), None)
        init = next(_descendants(var, "simpleValue"), None)
        yield Variable(
            key=name if kind == "global" else f"{unit}.{name}",
            name=name,
            unit="" if kind == "global" else unit,
            section=kind,
            dtype=_plcopen_type(next(_children(var, "type"), None)),
            address=var.get("address"),
            comment=" ".join("".join(doc.itertext()).split()) if doc is not None else "",
            initial=init.get("value") if init is not None else None,
        )


def load_plcopen(
    path: Path, name: str, evidence_id: str = "", asset_ip: str | None = None
) -> PlcProject:
    root = _safe_xml(path)
    header = next(_descendants(root, "contentHeader"), None)
    project = PlcProject(
        name=(header.get("name") if header is not None else None) or _stem(name),
        format="plcopen",
        source=name,
        evidence_id=evidence_id,
    )
    if asset_ip:
        project.controller_ips.add(asset_ip)
    for section in _descendants(root, "globalVars"):
        for v in _plcopen_vars(section, "", "global"):
            project.variables[v.key] = v
    bodies: list[tuple[str, str]] = []
    for pou in _descendants(root, "pou"):
        pou_name = pou.get("name", "")
        interface = next(_children(pou, "interface"), None)
        if interface is not None:
            for section in interface:
                kind = PLCOPEN_SECTIONS.get(_ln(section))
                if kind:
                    for v in _plcopen_vars(section, pou_name, kind):
                        project.variables[v.key] = v
        body = next(_children(pou, "body"), None)
        lang = _ln(next(iter(body), body)) if body is not None and len(body) else ""
        if lang == "ST" and body is not None:
            bodies.append((pou_name, "".join(next(iter(body)).itertext())))
        elif lang:
            project.caveats.append(
                f"POU {pou_name} uses {lang} (graphical or non-ST): logic not analyzed."
            )
    for pou_name, text in bodies:
        code = st.strip_comments(text)
        project.statements += st.parse_body(code, pou_name, 1, project)
    return project


def _split_params(text: str) -> list[str]:
    params: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            params.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        params.append("".join(cur).strip())
    return params


def _instructions(rung: str) -> Iterator[tuple[str, list[str]]]:
    for m in INSTRUCTION.finditer(rung):
        depth = 1
        i = m.end()
        while i < len(rung) and depth:
            depth += {"(": 1, ")": -1}.get(rung[i], 0)
            i += 1
        yield m.group(1), _split_params(rung[m.end() : i - 1])


def _tag_base(param: str) -> str | None:
    base = re.split(r"[\.\[]", param.strip(), maxsplit=1)[0]
    return base if re.fullmatch(r"[A-Za-z_]\w*", base) else None


def _rung_statement(
    project: PlcProject, prog: str, routine: str, number: str, rung: str
) -> Statement:
    guards: list[str] = []
    guard_reads: list[str] = []
    reads: list[str] = []
    targets: list[str] = []
    literals: list[int] = []
    for op, params in _instructions(rung):
        bases = [_tag_base(p) for p in params]
        keys = [project.resolve(prog, b) if b else None for b in bases]
        if op in L5X_CONDITIONS:
            guards.append(f"{op}({', '.join(params)})")
            guard_reads += [k for k in keys if k]
            literals += [int(p) for p in params if re.fullmatch(r"\d{1,11}", p)]
            continue
        dest = L5X_DEST.get(op, ())
        for i, key in enumerate(keys):
            if key and i in dest:
                targets.append(key)
            elif key:
                reads.append(key)
        literals += [int(p) for p in params if re.fullmatch(r"\d{1,11}", p)]
    stmt = Statement(
        unit=prog,
        line=int(number) if number.isdigit() else 0,
        text=" ".join(rung.split()),
        target=targets[0] if targets else None,
        reads=list(dict.fromkeys(reads)),
        guards=guards,
        guard_reads=list(dict.fromkeys(guard_reads)),
        literals=literals,
        routine=routine,
    )
    return stmt


def load_l5x(
    path: Path, name: str, evidence_id: str = "", asset_ip: str | None = None
) -> PlcProject:
    root = _safe_xml(path)
    controller = next(_descendants(root, "Controller"), None)
    if controller is None:
        raise PlcParseError(f"{name}: no Controller element")
    project = PlcProject(
        name=controller.get("Name", _stem(name)),
        format="l5x",
        source=name,
        evidence_id=evidence_id,
        model=controller.get("ProcessorType"),
    )
    if asset_ip:
        project.controller_ips.add(asset_ip)
    for module in _descendants(controller, "Module"):
        bridge = module.get("ParentModule") == "Local" and bool(
            re.search(r"-EN\d?[A-Z]", module.get("CatalogNumber", ""))
        )
        local = module.get("Name") == "Local" or bridge
        for port in _descendants(module, "Port"):
            addr = port.get("Address", "")
            if port.get("Type") == "Ethernet" and IPV4.match(addr) and local:
                project.controller_ips.add(addr)
    if not project.controller_ips:
        project.caveats.append("No controller IP found in module configuration.")
    scopes: list[tuple[str, ET.Element]] = [("", controller)]
    scopes += [(p.get("Name", ""), p) for p in _descendants(controller, "Program")]
    for prog, scope in scopes:
        tags = next(_children(scope, "Tags"), None)
        if tags is None:
            continue
        for tag in _children(tags, "Tag"):
            tname = tag.get("Name", "")
            desc = next(_children(tag, "Description"), None)
            project.variables[f"{prog}.{tname}" if prog else tname] = Variable(
                key=f"{prog}.{tname}" if prog else tname,
                name=tname,
                unit=prog,
                section="tag",
                dtype=tag.get("DataType", ""),
                comment=" ".join("".join(desc.itertext()).split()) if desc is not None else "",
                alias_for=tag.get("AliasFor"),
            )
    for prog_el in _descendants(controller, "Program"):
        prog = prog_el.get("Name", "")
        for routine in _descendants(prog_el, "Routine"):
            rname = routine.get("Name", "")
            for rung in _descendants(routine, "Rung"):
                text_el = next(_children(rung, "Text"), None)
                if text_el is not None and text_el.text:
                    project.statements.append(
                        _rung_statement(project, prog, rname, rung.get("Number", "0"), text_el.text)
                    )
            lines = [(ln.text or "") for ln in _descendants(routine, "Line")]
            if lines:
                body = st.strip_comments("\n".join(lines))
                for stmt in st.parse_body(body, prog, 1, project):
                    stmt.routine = rname
                    project.statements.append(stmt)
            if routine.get("Type") in ("FBD", "SFC"):
                project.caveats.append(
                    f"Routine {prog}.{rname} is {routine.get('Type')}: not analyzed."
                )
    _mark_coil_targets(project)
    return project


def _mark_coil_targets(project: PlcProject) -> None:
    for stmt in project.statements:
        if not stmt.target or not re.search(r"\bOT[ELU]\(", stmt.text):
            continue
        var = project.variables.get(stmt.target)
        if var is not None and var.section == "tag":
            var.section = "output"


LOADERS = {
    EvidenceKind.PLC_ST: load_st,
    EvidenceKind.PLC_PLCOPEN: load_plcopen,
    EvidenceKind.PLC_L5X: load_l5x,
}


def load_plc(
    path: Path,
    name: str,
    kind: EvidenceKind,
    evidence_id: str = "",
    asset_ip: str | None = None,
) -> PlcProject:
    loader = LOADERS.get(kind)
    if loader is None:
        raise PlcParseError(f"{name}: {kind.value} is not a supported PLC format")
    return loader(path, name, evidence_id, asset_ip)
