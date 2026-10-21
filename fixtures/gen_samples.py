"""Builds the non-tool sample files under samples/ and the manifest. See scripts/make-samples.sh."""

import gzip
import io
import json
import random
import shutil
import tarfile
import zipfile
from pathlib import Path

from scapy.all import PcapNgWriter, rdpcap

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures"
OUT = ROOT / "samples"

SYSLOG = """Oct  9 08:53:19 fw-ot01 kernel: ACCEPT IN=eth1 SRC=10.0.0.10 DST=10.0.0.20 PROTO=TCP DPT=502
Oct  9 08:53:22 fw-ot01 kernel: ACCEPT IN=eth1 SRC=10.0.0.66 DST=10.0.0.20 PROTO=TCP DPT=502
Oct  9 08:53:22 ews01 sshd[2211]: Accepted password for engineer from 10.0.0.66 port 40001 ssh2
Oct  9 08:53:26 fw-ot01 kernel: ACCEPT IN=eth1 SRC=10.0.0.66 DST=10.0.0.30 PROTO=TCP DPT=102
Oct  9 08:53:27 plc-s7-01 plc: CPU mode change RUN -> STOP
Oct  9 08:53:40 hmi01 alarmd[310]: ALARM PumpStation Setpoint out of range (1000 kPa)
"""

ASSETS = """ip,mac,hostname,vendor,role,location
10.0.0.10,00:1b:1b:00:00:10,HMI-01,Siemens,operator station,control room
10.0.0.20,00:80:f4:00:00:20,PUMP-PLC,Schneider Electric,controller,pump house
10.0.0.30,00:1b:1b:00:00:30,S7-1500-A,Siemens,controller,pump house
10.0.0.40,00:00:bc:00:00:40,TANK-PLC,Rockwell Automation,controller,tank farm
"""

HISTORIAN_ROWS = [
    ("08:53:15", "Setpoint", 300, "good"), ("08:53:15", "SpeedLimit", 1500, "good"),
    ("08:53:15", "PumpSpeed", 1180, "good"), ("08:53:15", "Pressure", 482, "good"),
    ("08:53:20", "Pressure", 486, "good"), ("08:53:22", "Setpoint", 1000, "good"),
    ("08:53:22", "SpeedLimit", 10000, "good"), ("08:53:23", "PumpSpeed", 1960, "good"),
    ("08:53:24", "Pressure", 561, "good"), ("08:53:26", "PumpRun", 0, "good"),
    ("08:53:28", "Pressure", 640, "good"), ("08:53:30", "ReliefValve", 0, "good"),
]  # fmt: skip


def historian() -> str:
    lines = ["timestamp,tag,value,quality"]
    lines += [f"2025-10-09T{t}Z,{tag},{value},{q}" for t, tag, value, q in HISTORIAN_ROWS]
    return "\n".join(lines) + "\n"


def write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def main() -> None:
    pcap = FIX / "ot-demo.pcap"
    shutil.copy(pcap, OUT / "capture" / "ot-demo.pcap")
    writer = PcapNgWriter(str(OUT / "capture" / "ot-demo.pcapng"))
    writer.write(rdpcap(str(pcap)))
    writer.close()
    write(OUT / "capture" / "ot-demo.pcap.gz", gzip.compress(pcap.read_bytes(), mtime=0))
    for name in ("conn", "cotp", "modbus", "modbus_detailed", "s7comm"):
        shutil.copy(FIX / "ot-demo" / "zeek" / f"{name}.log", OUT / "zeek-json" / f"{name}.log")
    shutil.copy(FIX / "ot-demo" / "suricata" / "eve.json", OUT / "suricata" / "eve.json")
    for name in ("pump.st", "pump.xml", "tank.L5X"):
        shutil.copy(FIX / "plc" / name, OUT / "plc" / name)
    write(OUT / "logs" / "firewall.syslog", SYSLOG)
    write(OUT / "tables" / "assets.csv", ASSETS)
    write(OUT / "tables" / "historian.csv", historian())
    rng = random.Random(7)
    write(
        OUT / "other" / "project.ACD",
        b"SYNTHETIC SAMPLE, NOT A REAL PROJECT\x00"
        + bytes(rng.randrange(256) for _ in range(1500)),
    )

    with zipfile.ZipFile(OUT / "bundles" / "case.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, src in (("capture/ot-demo.pcap", pcap), ("plc/pump.st", FIX / "plc" / "pump.st")):
            info = zipfile.ZipInfo(arc, date_time=(2025, 10, 9, 8, 53, 0))
            zf.writestr(info, src.read_bytes())
    buf = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w") as tf,
    ):
        for arc, src in (
            ("suricata/eve.json", FIX / "ot-demo" / "suricata" / "eve.json"),
            ("plc/tank.L5X", FIX / "plc" / "tank.L5X"),
            ("plc/pump.xml", FIX / "plc" / "pump.xml"),
        ):
            data = src.read_bytes()
            info = tarfile.TarInfo(arc)
            info.size = len(data)
            info.mtime = 1760000000
            tf.addfile(info, io.BytesIO(data))
    write(OUT / "bundles" / "case.tar.gz", buf.getvalue())

    manifest = [
        ("capture/ot-demo.pcap", "pcap", True, "Packet capture. Runs Zeek, Suricata and tshark."),
        ("capture/ot-demo.pcapng", "pcap", True, "Same capture in pcapng format."),
        ("capture/ot-demo.pcap.gz", "pcap", True, "Same capture, gzip compressed; unpacked on upload."),
        ("zeek-tsv/conn.log", "zeek_log", True, "Zeek log in Zeek's default tab-separated format."),
        ("zeek-tsv/cotp.log", "zeek_log", True, "Zeek COTP log (S7 transport)."),
        ("zeek-tsv/modbus.log", "zeek_log", True, "Zeek Modbus log."),
        ("zeek-tsv/modbus_detailed.log", "zeek_log", True, "Zeek Modbus detail log (addresses and values)."),
        ("zeek-tsv/s7comm.log", "zeek_log", True, "Zeek S7comm log (includes the PLC Stop)."),
        ("zeek-json/conn.log", "zeek_log", True, "Zeek log in JSON format."),
        ("zeek-json/cotp.log", "zeek_log", True, "Zeek COTP log, JSON."),
        ("zeek-json/modbus.log", "zeek_log", True, "Zeek Modbus log, JSON."),
        ("zeek-json/modbus_detailed.log", "zeek_log", True, "Zeek Modbus detail log, JSON."),
        ("zeek-json/s7comm.log", "zeek_log", True, "Zeek S7comm log, JSON."),
        ("suricata/eve.json", "suricata_eve", True, "Suricata alerts and flows (eve.json)."),
        ("plc/pump.st", "plc_st", True, "PLC program, Structured Text. Give it controller IP 10.0.0.20."),
        ("plc/pump.xml", "plc_plcopen", True, "The same program as PLCopen XML (also 10.0.0.20)."),
        ("plc/tank.L5X", "plc_l5x", True, "Rockwell L5X project; the controller IP (10.0.0.40) is read from the file."),
        ("tshark/packets.ek.json", "tshark_json", False, "tshark -T ek export of the first packets. Stored, not analyzed yet."),
        ("logs/firewall.syslog", "syslog", False, "Firewall and host syslog around the incident. Stored, not analyzed yet."),
        ("tables/assets.csv", "csv_assets", False, "Asset inventory. Stored, not analyzed yet."),
        ("tables/historian.csv", "csv_historian", False, "Historian tag values around the incident. Stored, not analyzed yet."),
        ("other/project.ACD", "unknown", False, "Synthetic binary standing in for a proprietary PLC project. Hashed and stored only."),
    ]  # fmt: skip
    bundles = [
        ("bundles/case.zip", ["capture/ot-demo.pcap:pcap", "plc/pump.st:plc_st"], "A zip with a capture and a PLC program."),
        ("bundles/case.tar.gz", ["suricata/eve.json:suricata_eve", "plc/tank.L5X:plc_l5x", "plc/pump.xml:plc_plcopen"], "A tar.gz with logs and two PLC projects."),
    ]  # fmt: skip
    entries = [{"path": p, "kind": k, "analyzed": a, "note": n} for p, k, a, n in manifest]
    entries += [
        {"path": p, "kind": "bundle", "analyzed": True, "members": m, "note": n}
        for p, m, n in bundles
    ]
    write(OUT / "manifest.json", json.dumps({"samples": entries}, indent=2) + "\n")


if __name__ == "__main__":
    main()
