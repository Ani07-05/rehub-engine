import sys
from pathlib import Path

from scapy.all import ARP, IP, TCP, Ether, Packet, Raw, wrpcap

HMI = "10.0.0.10"
PLC = "10.0.0.20"
ROGUE = "10.0.0.66"
S7_PLC = "10.0.0.30"
MAC = {HMI: "00:1b:1b:00:00:10", PLC: "00:80:f4:00:00:20", ROGUE: "02:00:00:00:00:66"}
MAC[S7_PLC] = "00:1b:1b:00:00:30"
GATEWAY_MAC = "00:00:0c:07:ac:01"
REMOTE_A = "172.16.0.5"
REMOTE_B = "172.16.0.6"
MAC[REMOTE_A] = GATEWAY_MAC
MAC[REMOTE_B] = GATEWAY_MAC


class Session:
    def __init__(self, client: str, server: str, sport: int, dport: int, t0: float) -> None:
        self.client, self.server, self.sport, self.dport = client, server, sport, dport
        self.t = t0
        self.cseq, self.sseq = 1000, 5000
        self.packets: list[Packet] = []

    def _pkt(self, from_client: bool, flags: str, payload: bytes = b"") -> None:
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        sp, dp = (self.sport, self.dport) if from_client else (self.dport, self.sport)
        seq, ack = (self.cseq, self.sseq) if from_client else (self.sseq, self.cseq)
        pkt = (
            Ether(src=MAC[src], dst=MAC[dst])
            / IP(src=src, dst=dst, id=len(self.packets) + 1)
            / TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack)
        )
        if payload:
            pkt = pkt / Raw(payload)
        self.t += 0.01
        pkt.time = self.t
        self.packets.append(pkt)
        if from_client:
            self.cseq += len(payload) + (1 if "S" in flags or "F" in flags else 0)
        else:
            self.sseq += len(payload) + (1 if "S" in flags or "F" in flags else 0)

    def open(self) -> None:
        self._pkt(True, "S")
        self._pkt(False, "SA")
        self._pkt(True, "A")

    def request(self, payload: bytes, reply: bytes) -> None:
        self._pkt(True, "PA", payload)
        self._pkt(False, "A")
        self._pkt(False, "PA", reply)
        self._pkt(True, "A")

    def close(self) -> None:
        self._pkt(True, "FA")
        self._pkt(False, "FA")
        self._pkt(True, "A")


def mbap(tid: int, pdu: bytes) -> bytes:
    return tid.to_bytes(2, "big") + b"\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + b"\x01" + pdu


def modbus_poll(t0: float, client: str, sport: int, requests: int = 5) -> list[Packet]:
    s = Session(client, PLC, sport, 502, t0)
    s.open()
    for i in range(requests):
        req = mbap(i + 1, b"\x03\x00\x00\x00\x02")
        rep = mbap(i + 1, b"\x03\x04\x00\x64\x00\xc8")
        s.request(req, rep)
    s.close()
    return s.packets


def modbus_rogue_write(t0: float) -> list[Packet]:
    s = Session(ROGUE, PLC, 40001, 502, t0)
    s.open()
    s.request(mbap(1, b"\x06\x00\x0a\x03\xe8"), mbap(1, b"\x06\x00\x0a\x03\xe8"))
    s.request(
        mbap(2, b"\x10\x00\x00\x00\x02\x04\x27\x10\x27\x10"), mbap(2, b"\x10\x00\x00\x00\x02")
    )
    s.close()
    return s.packets


def s7_stop(t0: float) -> list[Packet]:
    s = Session(ROGUE, S7_PLC, 40002, 102, t0)
    s.open()
    tpkt_cotp = b"\x03\x00\x00\x21\x02\xf0\x80"
    header = b"\x32\x01\x00\x00\x00\x01\x00\x10\x00\x00"
    param = b"\x29\x00\x00\x00\x00\x00\x09P_PROGRAM"
    stop = tpkt_cotp + header + param
    s.request(stop, b"\x03\x00\x00\x07\x02\xf0\x80")
    s.close()
    return s.packets


def arp_announcements(t0: float) -> list[Packet]:
    packets: list[Packet] = []
    for i, ip in enumerate((HMI, PLC, S7_PLC, ROGUE)):
        pkt = Ether(src=MAC[ip], dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, hwsrc=MAC[ip], psrc=ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip
        )
        pkt.time = t0 + i * 0.01
        packets.append(pkt)
    return packets


def build() -> list[Packet]:
    t0 = 1_760_000_000.0
    packets: list[Packet] = []
    packets += modbus_poll(t0, HMI, 41000)
    packets += modbus_rogue_write(t0 + 2)
    packets += modbus_poll(t0 + 4, HMI, 41001)
    packets += s7_stop(t0 + 6)
    packets += arp_announcements(t0 - 1)
    packets += modbus_poll(t0 + 8, REMOTE_A, 42000, 2)
    packets += modbus_poll(t0 + 9, REMOTE_B, 42001, 2)
    return sorted(packets, key=lambda p: float(p.time))


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures/ot-demo.pcap")
    wrpcap(str(out), build())
