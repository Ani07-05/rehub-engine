from pathlib import Path

import pytest

from rehub.plc.analyze import canon, findings, project_events, usage
from rehub.plc.formats import load_l5x, load_plc, load_plcopen, load_st
from rehub.plc.link import modbus_impacts, register_span
from rehub.plc.model import PlcParseError, PlcProject, Variable
from rehub.plc.st import parse_body, parse_declarations, split_pous, strip_comments
from rehub.schema import EventKind, EvidenceKind

PLC_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "plc"


@pytest.fixture(scope="module")
def st_project() -> PlcProject:
    return load_st(PLC_DIR / "pump.st", "pump.st", "ev-st", "10.0.0.20")


@pytest.fixture(scope="module")
def xml_project() -> PlcProject:
    return load_plcopen(PLC_DIR / "pump.xml", "pump.xml", "ev-xml", "10.0.0.20")


@pytest.fixture(scope="module")
def l5x_project() -> PlcProject:
    return load_l5x(PLC_DIR / "tank.L5X", "tank.L5X", "ev-l5x")


def titles(project: PlcProject) -> set[str]:
    return {f.title for f in findings(project)}


def test_st_declarations(st_project: PlcProject) -> None:
    v = st_project.variables
    assert v["Setpoint"].address == "%MW10"
    assert v["Setpoint"].initial == "300"
    assert v["PumpControl.Pressure"].address == "%IW0"
    assert v["ReliefValve"].is_output
    assert v["Runtime"].section == "global"
    assert v["PumpControl.Heartbeat"].dtype == "TON"


def test_st_statements_and_guards(st_project: PlcProject) -> None:
    by_text = {s.text: s for s in st_project.statements}
    relief = by_text["ReliefValve := TRUE"]
    assert relief.guards == ["Pressure > Setpoint"]
    assert "PumpControl.Pressure" in relief.guard_reads and "Setpoint" in relief.guard_reads
    assert by_text["ReliefValve := FALSE"].guards == ["NOT (Pressure > Setpoint)"]
    assert by_text["PumpRun := FALSE"].literals == [4000000]
    call = next(s for s in st_project.statements if s.kind == "call")
    assert call.reads == ["PumpControl.Heartbeat"]


def test_st_line_numbers_point_at_source(st_project: PlcProject) -> None:
    lines = (PLC_DIR / "pump.st").read_text().splitlines()
    for stmt in st_project.statements:
        assert stmt.text.split(":=")[0].split("(")[0].strip() in lines[stmt.line - 1]


def test_plcopen_matches_st_semantics(xml_project: PlcProject, st_project: PlcProject) -> None:
    assert xml_project.name == "PumpStation"
    assert xml_project.variables["Setpoint"].address == "%MW10"
    assert xml_project.variables["Setpoint"].comment == "pressure setpoint kPa"
    assert xml_project.variables["SpeedLimit"].initial == "1500"
    assert xml_project.variables["Recipe"].dtype == "ARRAY [0..3] OF REAL"
    assert any("Panel uses LD" in c for c in xml_project.caveats)
    assert {s.text for s in xml_project.statements} <= {s.text for s in st_project.statements}


def test_l5x_project(l5x_project: PlcProject) -> None:
    assert l5x_project.name == "TankCtl"
    assert l5x_project.model == "1769-L33ER"
    assert l5x_project.controller_ips == {"10.0.0.40"}
    assert l5x_project.variables["StartPB"].comment == "Start button"
    assert l5x_project.variables["Drain"].is_output
    assert canon(l5x_project, "PumpAlias") == "Pump"


def test_l5x_rungs_split_reads_writes_and_guards(l5x_project: PlcProject) -> None:
    rung = next(s for s in l5x_project.statements if "ADD(" in s.text)
    assert rung.target == "Counter"
    assert rung.guard_reads == ["Pump"]
    assert rung.routine == "MainRoutine"
    st_line = next(s for s in l5x_project.statements if s.routine == "StCode")
    assert st_line.target == "Pump"
    assert st_line.guards == ["Level > 100"]


def test_findings_st(st_project: PlcProject) -> None:
    t = titles(st_project)
    assert "Output PumpRun gated by counter/timer Runtime" in t
    assert "PumpRun is written from 2 places" in t
    assert "Unused variable UnusedDiag" in t
    assert "SpareWord (%MW20) is exposed but not used by logic" in t
    assert not any("PumpControl.Heartbeat" in x or "Heartbeat" in x for x in t)


def test_if_else_branches_are_not_multiple_writers(st_project: PlcProject) -> None:
    assert "ReliefValve is written from 2 places" not in titles(st_project)


def test_findings_l5x(l5x_project: PlcProject) -> None:
    t = titles(l5x_project)
    assert "Output Drain gated by counter/timer Counter" in t
    assert "Pump is written from 3 places" in t
    assert "Unused variable SpareTag" in t


def test_gated_finding_severity_and_review_wording(st_project: PlcProject) -> None:
    gated = next(f for f in findings(st_project) if f.rule == "gated_output_write")
    assert gated.severity == "medium"
    assert "not a verdict" in gated.detail
    assert gated.where == "PumpControl:27"


def test_large_constant_only_is_low() -> None:
    project = PlcProject(name="p", format="st", source="p.st")
    project.variables["Out"] = Variable("Out", "Out", "", "output", "BOOL")
    project.variables["In"] = Variable("In", "In", "", "global", "DINT")
    text = "IF In > 50000 THEN Out := TRUE; END_IF;"
    project.statements = parse_body(text, "", 1, project)
    gated = next(f for f in findings(project) if f.rule == "gated_output_write")
    assert gated.severity == "low"


def test_project_events(st_project: PlcProject) -> None:
    events = list(project_events(st_project))
    assert events
    assert all(e.tool == "plc" and e.kind == EventKind.LOGIC for e in events)
    assert all(e.dst == "10.0.0.20" and e.evidence_id == "ev-st" for e in events)
    gated = next(e for e in events if e.attrs["rule"] == "gated_output_write")
    assert gated.ref == "pump.st:PumpControl:27"
    assert gated.severity == "medium"


@pytest.mark.parametrize(
    ("address", "dtype", "expected"),
    [
        ("%MW10", "INT", (10, 1, True)),
        ("%MW200", "REAL", (200, 2, True)),
        ("%MW0", "LREAL", (0, 4, True)),
        ("%MW30", "ARRAY [0..3] OF REAL", (30, 8, True)),
        ("%MD5", "DINT", (10, 2, True)),
        ("%MW7", "MyStruct", (7, 1, False)),
    ],
)
def test_register_span(address: str, dtype: str, expected: tuple[int, int, bool]) -> None:
    var = Variable("v", "v", "", "global", dtype, address)
    assert register_span(var) == expected


def test_register_span_ignores_io_addresses() -> None:
    assert register_span(Variable("v", "v", "", "global", "INT", "%IW0")) is None
    assert register_span(Variable("v", "v", "", "global", "BOOL", None)) is None


def test_modbus_impact_single_register(st_project: PlcProject) -> None:
    [impact] = modbus_impacts(st_project, 10, 1, "[1000]")
    assert impact.variable == "Setpoint"
    assert impact.address == "%MW10"
    assert impact.drives == ["ReliefValve"]
    assert any("Pressure > Setpoint" in r or "ReliefValve := TRUE" in r for r in impact.readers)
    assert impact.new_values == "[1000]"
    assert "Verify" in impact.assumption


def test_modbus_impact_multi_register_range(st_project: PlcProject) -> None:
    impacts = modbus_impacts(st_project, 0, 2, "[10000, 10000]")
    assert [i.variable for i in impacts] == ["PumpSpeed", "SpeedLimit"]
    assert impacts[1].drives == ["PumpRun"]


def test_modbus_impact_partial_overlap_and_miss(xml_project: PlcProject) -> None:
    assert [i.variable for i in modbus_impacts(xml_project, 33, 4)] == ["Recipe"]
    assert modbus_impacts(xml_project, 500, 4) == []


def test_usage_follows_aliases(l5x_project: PlcProject) -> None:
    writers, _ = usage(l5x_project)
    assert len(writers["Pump"]) == 3


def test_comments_and_strings_do_not_confuse_parser() -> None:
    code = "A := 1; // B := 2;\n(* C := 3; *)\nD := 'E := 4;';"
    stripped = strip_comments(code)
    assert "B := 2" not in stripped and "C := 3" not in stripped and "E := 4" not in stripped
    assert stripped.count("\n") == code.count("\n")


def test_nested_if_and_case_guards() -> None:
    project = PlcProject(name="p", format="st", source="p")
    for n in ("A", "B", "Mode", "Out"):
        project.variables[n] = Variable(n, n, "", "global", "INT")
    body = (
        "IF A > 1 THEN IF B > 2 THEN Out := 1; END_IF; END_IF; CASE Mode OF 3: Out := 2; END_CASE;"
    )
    stmts = parse_body(body, "", 1, project)
    assert stmts[0].guards == ["A > 1", "B > 2"]
    assert stmts[1].guards == ["CASE Mode", "Mode = 3"]


def test_declaration_multi_name_and_arrays() -> None:
    text = "VAR\n  a, b : INT := 5;\n  buf AT %MW40 : ARRAY [0..9] OF INT;\nEND_VAR\n"
    vs = {v.name: v for v in parse_declarations(text, "P")}
    assert set(vs) == {"a", "b", "buf"}
    assert vs["a"].initial == "5"
    assert vs["buf"].dtype == "ARRAY [0..9] OF INT"


def test_split_pous_finds_all_units() -> None:
    text = (
        "PROGRAM A\nVAR x:INT; END_VAR\nx:=1;\nEND_PROGRAM\nFUNCTION_BLOCK B\nEND_FUNCTION_BLOCK\n"
    )
    assert [(p.name, p.kind) for p in split_pous(text)] == [
        ("A", "PROGRAM"),
        ("B", "FUNCTION_BLOCK"),
    ]


def test_xml_doctype_and_entities_rejected(tmp_path: Path) -> None:
    bomb = tmp_path / "x.xml"
    bomb.write_text('<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y">]><project/>')
    with pytest.raises(PlcParseError, match="DTD"):
        load_plcopen(bomb, "x.xml")
    l5x = tmp_path / "x.L5X"
    l5x.write_text('<?xml version="1.0"?><!DOCTYPE a><RSLogix5000Content/>')
    with pytest.raises(PlcParseError, match="DTD"):
        load_l5x(l5x, "x.L5X")


def test_invalid_inputs_raise_parse_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.xml"
    bad.write_text("<project>")
    with pytest.raises(PlcParseError, match="invalid XML"):
        load_plcopen(bad, "bad.xml")
    empty = tmp_path / "empty.st"
    empty.write_text("just text")
    with pytest.raises(PlcParseError, match="no PROGRAM"):
        load_st(empty, "empty.st")
    no_ctrl = tmp_path / "n.L5X"
    no_ctrl.write_text("<RSLogix5000Content/>")
    with pytest.raises(PlcParseError, match="no Controller"):
        load_l5x(no_ctrl, "n.L5X")


def test_load_plc_dispatch_and_unsupported(tmp_path: Path) -> None:
    project = load_plc(PLC_DIR / "pump.st", "pump.st", EvidenceKind.PLC_ST, "e", "10.0.0.20")
    assert project.controller_ips == {"10.0.0.20"}
    with pytest.raises(PlcParseError, match="not a supported"):
        load_plc(tmp_path / "x", "x", EvidenceKind.CSV)


def test_l5x_without_ip_adds_caveat(tmp_path: Path) -> None:
    f = tmp_path / "a.L5X"
    f.write_text('<RSLogix5000Content><Controller Name="C"/></RSLogix5000Content>')
    project = load_l5x(f, "a.L5X")
    assert any("No controller IP" in c for c in project.caveats)
