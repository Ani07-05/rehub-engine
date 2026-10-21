from dataclasses import dataclass, field

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}
MAC_ARP = "arp"
MAC_INFERRED = "inferred"
MAC_L2 = "l2"


@dataclass(slots=True)
class EvidenceRef:
    evidence_id: str
    ref: str
    tool: str


@dataclass(frozen=True, slots=True)
class Source:
    tool: str
    rule: str
    title: str


@dataclass(slots=True)
class PlcImpact:
    project: str
    variable: str
    address: str
    dtype: str
    comment: str
    readers: list[str]
    drives: list[str]
    new_values: str
    assumption: str
    size_known: bool = True


@dataclass(slots=True)
class ModbusWrite:
    code: int
    kind: str
    address: int
    quantity: int
    values: list[str]
    op: str
    seen: dict[str, int]

    @property
    def count(self) -> int:
        return max(self.seen.values(), default=0)


@dataclass(slots=True)
class Asset:
    id: str
    ips: set[str] = field(default_factory=set)
    macs: dict[str, str] = field(default_factory=dict)
    vendor: str | None = None
    locally_administered_mac: bool = False
    roles: set[str] = field(default_factory=set)
    first_ts: float | None = None
    last_ts: float | None = None
    tools: set[str] = field(default_factory=set)
    plc_projects: set[str] = field(default_factory=set)

    @property
    def kind(self) -> str:
        if any(r.endswith("_server") for r in self.roles):
            return "controller"
        if self.roles:
            return "client"
        return "unknown"


@dataclass(slots=True)
class Flow:
    key: str
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    proto: str | None = None
    service: str | None = None
    first_ts: float | None = None
    last_ts: float | None = None
    tools: set[str] = field(default_factory=set)
    packets: int = 0
    first_frame: int | None = None
    last_frame: int | None = None
    refs: list[EvidenceRef] = field(default_factory=list)


@dataclass(slots=True)
class Detection:
    id: str
    title: str
    severity: str | None
    flow_key: str | None
    src: str | None
    dst: str | None
    first_ts: float | None = None
    last_ts: float | None = None
    count: int = 0
    sources: list[Source] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    plc: list[PlcImpact] = field(default_factory=list)
    writes: list[ModbusWrite] = field(default_factory=list)
    attrs: dict[str, str] = field(default_factory=dict)
    refs: list[EvidenceRef] = field(default_factory=list)

    @property
    def tools(self) -> set[str]:
        return {s.tool for s in self.sources}

    @property
    def rules(self) -> set[str]:
        return {s.rule for s in self.sources}

    @property
    def corroborated(self) -> bool:
        return len(self.tools) >= 2


@dataclass(slots=True)
class Investigation:
    assets: dict[str, Asset] = field(default_factory=dict)
    flows: dict[str, Flow] = field(default_factory=dict)
    detections: list[Detection] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    event_count: int = 0
