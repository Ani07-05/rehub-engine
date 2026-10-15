from dataclasses import dataclass, field


class PlcParseError(ValueError):
    pass


@dataclass(slots=True)
class Variable:
    key: str
    name: str
    unit: str
    section: str
    dtype: str
    address: str | None = None
    comment: str = ""
    initial: str | None = None
    alias_for: str | None = None
    line: int | None = None

    @property
    def is_output(self) -> bool:
        return self.section == "output" or (self.address or "").upper().startswith("%Q")


@dataclass(slots=True)
class Statement:
    unit: str
    line: int
    text: str
    target: str | None
    reads: list[str] = field(default_factory=list)
    guards: list[str] = field(default_factory=list)
    guard_reads: list[str] = field(default_factory=list)
    literals: list[int] = field(default_factory=list)
    kind: str = "assign"
    routine: str = ""


@dataclass(slots=True)
class PlcProject:
    name: str
    format: str
    source: str
    evidence_id: str = ""
    controller_ips: set[str] = field(default_factory=set)
    model: str | None = None
    variables: dict[str, Variable] = field(default_factory=dict)
    statements: list[Statement] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    def resolve(self, unit: str, ident: str) -> str | None:
        local = f"{unit}.{ident}"
        if local in self.variables:
            return local
        return ident if ident in self.variables else None
