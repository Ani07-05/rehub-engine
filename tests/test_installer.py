import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "install.sh"


def embedded_compose() -> str:
    text = SCRIPT.read_text()
    match = re.search(r"cat <<'COMPOSE_EOF'\n(.*?)COMPOSE_EOF\n", text, re.S)
    assert match
    return match.group(1)


def test_embedded_compose_matches_compose_yml() -> None:
    assert embedded_compose() == (ROOT / "compose.yml").read_text()


def test_installer_is_self_contained_posix_sh() -> None:
    assert SCRIPT.read_text().startswith("#!/bin/sh\n")
    assert subprocess.run(["sh", "-n", str(SCRIPT)], check=False).returncode == 0
    body = SCRIPT.read_text()
    assert "curl" not in body.replace("curl | sh", "")
    assert "sudo" not in body


def test_installer_never_asks_for_more_than_docker() -> None:
    body = SCRIPT.read_text()
    assert "rm -rf" not in body
    assert "--privileged" not in body


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(
            ["docker", "image", "inspect", "rehub:dev"], capture_output=True, check=False
        ).returncode
        == 0
    )


@pytest.mark.skipif(not _docker_ready(), reason="needs docker and the rehub:dev image")
def test_install_and_uninstall_end_to_end(tmp_path: Path) -> None:
    env = {
        **os.environ,
        "REHUB_HOME": str(tmp_path),
        "REHUB_IMAGE": "rehub:dev",
        "REHUB_PROJECT": "rehubtest",
    }
    try:
        done = subprocess.run(
            [str(SCRIPT), "--no-open", "--port", "18097"],
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        assert done.returncode == 0, done.stdout + done.stderr
        assert "ReHub is ready." in done.stdout and "Startup check: ok" in done.stdout
        assert (tmp_path / "compose.yml").read_text() == (ROOT / "compose.yml").read_text()
        assert oct((tmp_path / ".env").stat().st_mode & 0o777) == "0o600"
    finally:
        subprocess.run(
            [str(SCRIPT), "--uninstall", "--purge"],
            env=env,
            capture_output=True,
            timeout=120,
            check=False,
        )


def test_missing_image_gives_a_clear_message(tmp_path: Path) -> None:
    if (
        shutil.which("docker") is None
        or subprocess.run(["docker", "info"], capture_output=True, check=False).returncode
    ):
        pytest.skip("needs a running docker")
    env = {
        **os.environ,
        "REHUB_HOME": str(tmp_path),
        "REHUB_IMAGE": "registry.invalid/none/rehub:nope",
        "REHUB_PROJECT": "rehubmiss",
    }
    done = subprocess.run(
        [str(SCRIPT), "--no-open", "--port", "18098"],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode != 0
    assert "not available" in done.stderr and "--local" in done.stderr
