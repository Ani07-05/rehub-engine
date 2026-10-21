# Sample evidence

One file of every kind ReHub understands, so you can try each upload path. Everything here is synthetic and built around one story: an HMI polls a pump controller (10.0.0.20) over Modbus, then a rogue device (10.0.0.66) writes two registers and sends a stop command to a Siemens controller (10.0.0.30). Rebuild with `scripts/make-samples.sh` (needs Docker, the `rehub:dev` image and uv). `manifest.json` lists every file and what ReHub does with it.

## What each file is

| File | Type | What ReHub does |
|---|---|---|
| `capture/ot-demo.pcap` | Packet capture | Runs Zeek, Suricata and tshark |
| `capture/ot-demo.pcapng` | Same, pcapng | Same |
| `capture/ot-demo.pcap.gz` | Same, gzip | Unpacked, then same |
| `zeek-tsv/*.log` | Zeek logs, default tab-separated format | Analyzed directly, no tool needed |
| `zeek-json/*.log` | Zeek logs, JSON format | Analyzed directly |
| `suricata/eve.json` | Suricata alerts and flows | Analyzed directly |
| `plc/pump.st` | PLC program, Structured Text | Static analysis; linked to the network when you give it controller IP `10.0.0.20` |
| `plc/pump.xml` | Same program, PLCopen XML | Same (give it `10.0.0.20` too) |
| `plc/tank.L5X` | Rockwell project | Static analysis; the controller IP (10.0.0.40) is read from the file |
| `bundles/case.zip` | Capture and PLC program in one zip | Unpacked, every member analyzed |
| `bundles/case.tar.gz` | Eve log and two PLC projects | Unpacked, every member analyzed |
| `tshark/packets.ek.json` | tshark JSON export | Stored and hashed, not analyzed yet |
| `logs/firewall.syslog` | Syslog around the incident | Stored and hashed, not analyzed yet |
| `tables/assets.csv` | Asset inventory | Stored and hashed, not analyzed yet |
| `tables/historian.csv` | Historian tag values around the incident | Stored and hashed, not analyzed yet |
| `other/project.ACD` | Synthetic stand-in for a proprietary PLC project | Hashed and stored only |

Files that are stored but not analyzed show up under "What we could not verify" instead of being silently ignored.

## Things to try

- **The full story:** upload `capture/ot-demo.pcap` and `plc/pump.st` (set the controller IP to `10.0.0.20`). Same as the built-in demo.
- **No capture, only logs:** upload all of `zeek-tsv/*.log`, `suricata/eve.json` and `plc/pump.st`. The tool boxes read "Not needed" and the report notes that no tshark evidence was provided.
- **Everything at once:** drop `capture/ot-demo.pcap` together with the PLC, table, syslog and `other/` files and read the warnings.
- **Bundles:** upload `bundles/case.zip` or `bundles/case.tar.gz` alone.
- **Do not** upload `zeek-tsv` and `zeek-json` together in one investigation; they describe the same traffic and would be counted twice.
