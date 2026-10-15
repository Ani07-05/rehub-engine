from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath


@dataclass(frozen=True, slots=True)
class SourceFile:
    path: Path
    name: str
    evidence_id: str

    @property
    def stem(self) -> str:
        base = PurePosixPath(self.name).name
        return base.removesuffix(".gz").removesuffix(".log")


def iso_to_epoch(value: str) -> float | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt).timestamp()
        except ValueError:
            continue
    return None
