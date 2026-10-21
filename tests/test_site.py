import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
INDEX = (SITE / "index.html").read_text()
RAW_URL = "https://raw.githubusercontent.com/Ani07-05/rehub-engine/main/scripts/install.sh"


class Refs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.refs: list[tuple[str, str, str]] = []
        self.ids: set[str] = set()
        self.imgs: list[dict[str, str | None]] = []
        self.inline_scripts = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if a.get("id"):
            self.ids.add(str(a["id"]))
        for key in ("src", "href"):
            if a.get(key):
                self.refs.append((tag, key, str(a[key])))
        if tag == "img":
            self.imgs.append(a)
        if tag == "script" and not a.get("src"):
            self.inline_scripts += 1
        if "style" in a:
            self.inline_scripts += 1


def parsed() -> Refs:
    p = Refs()
    p.feed(INDEX)
    return p


def test_page_has_no_inline_script_or_style_and_no_third_party_loads() -> None:
    p = parsed()
    assert p.inline_scripts == 0
    assert "<style" not in INDEX
    for tag, _key, ref in p.refs:
        if tag in ("script", "link", "img"):
            assert ref.startswith("/"), f"{tag} loads {ref}"
        elif ref.startswith("http"):
            assert ref.startswith("https://github.com/Ani07-05/"), ref


def test_every_local_reference_exists() -> None:
    for _tag, _key, ref in parsed().refs:
        if ref.startswith("/") and not ref.startswith("//"):
            assert (SITE / ref.lstrip("/")).is_file(), ref


def test_anchors_and_copy_targets_resolve() -> None:
    p = parsed()
    for _t, _k, ref in p.refs:
        if ref.startswith("#"):
            assert ref[1:] in p.ids, ref
    for target in re.findall(r'data-copy="([^"]+)"', INDEX):
        assert target in p.ids


def test_screenshots_have_alt_text_and_dimensions() -> None:
    imgs = parsed().imgs
    assert len(imgs) >= 5
    for img in imgs:
        assert img.get("alt"), img.get("src")
        assert img.get("width") and img.get("height")
    for src in {str(i["src"]) for i in imgs}:
        assert (SITE / src.lstrip("/")).stat().st_size < 150_000, src
    assert (SITE / "img" / "PROVENANCE.md").is_file()


def test_install_command_is_in_the_static_html_for_visitors_without_js() -> None:
    assert f"curl -fsSL {RAW_URL} | sh" in INDEX
    assert "./scripts/install.sh --local" in INDEX
    assert "Pre-release" not in INDEX and "Needs Docker" in INDEX


def test_page_states_its_limits_honestly() -> None:
    for phrase in (
        "does not capture live traffic",
        "does not give verdicts",
        "untested",
        "not analyzed",
    ):
        assert phrase in INDEX


def test_every_theme_image_has_a_counterpart() -> None:
    dark = set(re.findall(r'class="only-dark" src="/img/([a-z]+)-dark\.webp"', INDEX))
    light = set(re.findall(r'class="only-light" src="/img/([a-z]+)-light\.webp"', INDEX))
    assert dark == light and dark >= {"summary", "detail", "report"}


def test_vercel_config_serves_the_installer_as_plain_text_with_a_strict_csp() -> None:
    cfg = json.loads((ROOT / "vercel.json").read_text())
    assert cfg["outputDirectory"] == "site"
    assert "scripts/install.sh" in cfg["buildCommand"] and "site/install.sh" in cfg["buildCommand"]
    headers = {h["source"]: {x["key"]: x["value"] for x in h["headers"]} for h in cfg["headers"]}
    assert headers["/install.sh"]["Content-Type"].startswith("text/plain")
    csp = headers["/(.*)"]["Content-Security-Policy"]
    assert (
        "unsafe-inline" not in csp
        and "default-src 'none'" in csp
        and "frame-ancestors 'none'" in csp
    )


def test_built_installer_copy_is_not_committed() -> None:
    assert "site/install.sh" in (ROOT / ".gitignore").read_text()
    tracked = subprocess.run(
        ["git", "ls-files", "site/install.sh"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert tracked.stdout.strip() == ""


def test_page_stays_light() -> None:
    total = sum(p.stat().st_size for p in SITE.rglob("*") if p.is_file())
    assert total < 900_000


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node")
def test_site_script_is_valid_javascript() -> None:
    assert (
        subprocess.run(["node", "--check", str(SITE / "js" / "site.js")], check=False).returncode
        == 0
    )
    for banned in ("innerHTML", "eval(", "document.write"):
        assert banned not in (SITE / "js" / "site.js").read_text()
