from dataclasses import dataclass, field
from enum import StrEnum


class EvidenceKind(StrEnum):
    PCAP = "pcap"
    SURICATA_EVE = "suricata_eve"
    ZEEK_LOG = "zeek_log"
    TSHARK_JSON = "tshark_json"
    TSHARK_TSV = "tshark_tsv"
    PLC_L5X = "plc_l5x"
    PLC_PLCOPEN = "plc_plcopen"
    PLC_ST = "plc_st"
    SYSLOG = "syslog"
    CSV = "csv"
    CSV_ASSETS = "csv_assets"
    CSV_HISTORIAN = "csv_historian"
    UNKNOWN = "unknown"


class EventKind(StrEnum):
    FLOW = "flow"
    PROTOCOL_ACTION = "protocol_action"
    ALERT = "alert"
    PACKET = "packet"
    LOGIC = "logic"
    HEALTH = "health"


@dataclass(frozen=True, slots=True)
class Event:
    ts: float | None
    tool: str
    kind: EventKind
    evidence_id: str
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    proto: str | None = None
    flow_key: str | None = None
    severity: str | None = None
    summary: str = ""
    ref: str = ""
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Evidence:
    sha256: str
    name: str
    size: int
    kind: EvidenceKind
    compressed: bool = False
    origin: str = ""
    origin_sha256: str = ""
