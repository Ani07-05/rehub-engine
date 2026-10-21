from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from rehub.adapters.base import SourceFile
from rehub.communityid import community_id
from rehub.schema import Event, EventKind
from rehub.tools import TSHARK_FIELDS

IDX = {name: i for i, name in enumerate(TSHARK_FIELDS)}
IP_PROTO = {"6": "tcp", "17": "udp", "132": "sctp"}


@dataclass(slots=True)
class _Agg:
    first_ts: float | None
    first_frame: int
    last_frame: int
    packets: int = 0
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    proto: str = ""
    key: str | None = None
    macs: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    arp: set[str] = field(default_factory=set)


def _cell(cells: list[str], name: str) -> str:
    i = IDX[name]
    return cells[i] if i < len(cells) else ""


def _first(value: str) -> str:
    return value.split(",")[0]


def _port(cells: list[str], proto: str, which: str) -> int | None:
    name = f"{proto}.{which}port"
    if name not in IDX:
        return None
    raw = _first(_cell(cells, name))
    return int(raw) if raw.isdigit() else None


@dataclass(frozen=True, slots=True)
class Packet:
    frame: int
    ts: float | None
    src: str
    dst: str
    sport: int | None
    dport: int | None
    proto: str
    protocol: str
    info: str
    key: str | None
    l3: bool
    eth_src: str
    eth_dst: str
    arp: str


def iter_packets(path: Path) -> Iterator[Packet]:
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            cells = line.rstrip("\n").split("\t")
            frame = _first(_cell(cells, "frame.number"))
            if not frame.isdigit():
                continue
            ts_raw = _first(_cell(cells, "frame.time_epoch"))
            src = _first(_cell(cells, "ip.src") or _cell(cells, "ipv6.src"))
            dst = _first(_cell(cells, "ip.dst") or _cell(cells, "ipv6.dst"))
            eth_src, eth_dst = _cell(cells, "eth.src"), _cell(cells, "eth.dst")
            l3 = bool(src and dst)
            sport = dport = key = None
            if l3:
                num = _first(_cell(cells, "ip.proto") or _cell(cells, "ipv6.nxt"))
                proto = IP_PROTO.get(num, num)
                sport, dport = _port(cells, proto, "src"), _port(cells, proto, "dst")
                if sport is not None and dport is not None:
                    key = community_id(src, dst, sport, dport, proto)
            else:
                src, dst, proto = eth_src, eth_dst, "l2"
            arp_mac, arp_ip = _cell(cells, "arp.src.hw_mac"), _cell(cells, "arp.src.proto_ipv4")
            yield Packet(
                frame=int(frame),
                ts=float(ts_raw) if ts_raw else None,
                src=src,
                dst=dst,
                sport=sport,
                dport=dport,
                proto=proto,
                protocol=_cell(cells, "_ws.col.protocol"),
                info=_cell(cells, "_ws.col.info"),
                key=key,
                l3=l3,
                eth_src=eth_src,
                eth_dst=eth_dst,
                arp=f"{arp_ip}={arp_mac}" if arp_mac and arp_ip else "",
            )


def parse_tshark(sources: Iterable[SourceFile]) -> Iterator[Event]:
    for source in sources:
        aggs: dict[str, _Agg] = {}
        for pkt in iter_packets(source.path):
            bucket = pkt.key or f"{pkt.src}>{pkt.dst}:{pkt.proto}:{pkt.protocol}"
            agg = aggs.get(bucket)
            if agg is None:
                agg = _Agg(
                    pkt.ts, pkt.frame, pkt.frame, 0, pkt.src, pkt.dst, pkt.sport, pkt.dport,
                    pkt.proto, pkt.key,
                )  # fmt: skip
                aggs[bucket] = agg
            agg.packets += 1
            agg.last_frame = pkt.frame
            agg.protocols.add(pkt.protocol)
            if pkt.arp:
                agg.arp.add(pkt.arp)
            if pkt.l3 and pkt.eth_src:
                agg.macs.add(f"{pkt.src}={pkt.eth_src}")
            if pkt.l3 and pkt.eth_dst:
                agg.macs.add(f"{pkt.dst}={pkt.eth_dst}")
        for agg in aggs.values():
            yield Event(
                ts=agg.first_ts,
                tool="tshark",
                kind=EventKind.PACKET,
                evidence_id=source.evidence_id,
                src=agg.src,
                dst=agg.dst,
                sport=agg.sport,
                dport=agg.dport,
                proto=agg.proto,
                flow_key=agg.key,
                summary=f"{agg.packets} packets ({', '.join(sorted(agg.protocols))})",
                ref=f"{source.name}:frames {agg.first_frame}-{agg.last_frame}",
                attrs={
                    "packets": str(agg.packets),
                    "first_frame": str(agg.first_frame),
                    "last_frame": str(agg.last_frame),
                    "ip_mac": ";".join(sorted(agg.macs)),
                    "arp_ip_mac": ";".join(sorted(agg.arp)),
                },
            )
