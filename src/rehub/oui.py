import csv
import os
from pathlib import Path

EMBEDDED = {
    "001B1B": "Siemens AG",
    "0080F4": "Telemecanique Electrique (Schneider Electric)",
    "0000BC": "Allen-Bradley (Rockwell Automation)",
    "000C29": "VMware",
    "005056": "VMware",
    "080027": "VirtualBox",
    "525400": "QEMU/KVM",
}


def _prefix(mac: str) -> str:
    return "".join(c for c in mac.upper() if c.isalnum())[:6]


def is_locally_administered(mac: str) -> bool:
    try:
        return bool(int(mac.replace("-", ":").split(":")[0], 16) & 0b10)
    except ValueError:
        return False


class OuiTable:
    def __init__(self, extra: dict[str, str] | None = None) -> None:
        self.table = dict(EMBEDDED)
        if extra:
            self.table.update(extra)

    @classmethod
    def from_env(cls) -> "OuiTable":
        path = os.environ.get("REHUB_OUI")
        return cls(load_ieee_csv(Path(path))) if path and Path(path).is_file() else cls()

    def vendor(self, mac: str) -> str | None:
        if is_locally_administered(mac):
            return None
        return self.table.get(_prefix(mac))


def load_ieee_csv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            assignment = (row.get("Assignment") or "").strip().upper()
            name = (row.get("Organization Name") or "").strip()
            if len(assignment) == 6 and name:
                out[assignment] = name
    return out
