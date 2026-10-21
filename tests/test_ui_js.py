import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from rehub.pipeline import run_investigation
from rehub.serialize import to_jsonable
from tests.helpers import FIXTURES, FixtureExecutor

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "src" / "rehub" / "ui"


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node")
def test_narrate_logic_with_node(tmp_path: Path) -> None:
    record = run_investigation(
        [FIXTURES / "ot-demo.pcap", FIXTURES / "plc" / "pump.st"],
        tmp_path / "data",
        plc_ips={"pump.st": "10.0.0.20"},
        execute=FixtureExecutor(),
    )
    path = tmp_path / "record.json"
    path.write_text(json.dumps(to_jsonable(record)))
    proc = subprocess.run(
        [shutil.which("node") or "node", "--test", str(ROOT / "tests" / "ui")],
        capture_output=True,
        text=True,
        env={**os.environ, "REHUB_RECORD": str(path)},
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def js_files() -> list[Path]:
    return sorted((UI / "js").rglob("*.js"))


def test_ui_has_no_unsafe_dom_sinks() -> None:
    banned = re.compile(
        r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|srcdoc"
    )
    for path in js_files():
        assert not banned.search(path.read_text()), path.name


def test_ui_works_under_strict_csp() -> None:
    html = (UI / "index.html").read_text()
    assert "<style" not in html and " style=" not in html
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert "http://" not in html and "https://" not in html
    for path in js_files():
        text = path.read_text()
        assert 'setAttribute("style"' not in text and "cssText" not in text, path.name
        assert not re.search(r"""\{[^}]*\bstyle:\s*[^n}]""", text), (
            f"inline style attribute in {path.name}"
        )
    assert "url(http" not in (UI / "css" / "app.css").read_text()


def test_every_relative_import_resolves() -> None:
    for path in js_files():
        for target in re.findall(r"from\s+\"(\.{1,2}/[^\"]+)\"", path.read_text()):
            assert (path.parent / target).resolve().is_file(), f"{path.name} imports {target}"


def test_index_assets_exist() -> None:
    html = (UI / "index.html").read_text()
    for ref in re.findall(r"""(?:src|href)="/ui/([^"]+)""", html):
        assert (UI / ref).is_file(), ref
