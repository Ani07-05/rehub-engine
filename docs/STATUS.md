# Status and decisions

Handoff notes so work can resume on any machine.

## Goal

Black Hat Arsenal tool: drop in OT evidence, get an investigation (assets, communication, detections, evidence, report), fully local. Reported Arsenal Asia call close: 2026-11-02 (third-party date, verify on the official CFP page). Arsenal needs open source, no sales pitch, 3+ pages of docs, a demo that works without real hardware.

## Why this is different

- Malcolm is a heavy SOC platform. Zui is a query explorer that already correlates Zeek and Suricata (uid, Community ID). Zeek plus Suricata correlation alone is not the pitch.
- ReHub's pitch: network evidence joined to PLC logic, an answer instead of a query, evidence integrity (hashes, tool attribution, deterministic output), light local install.

## Built

Evidence sniffer and safe ingest, tool runners and image, Zeek/Suricata/tshark adapters, Community ID, correlator, PLC adapter and register linker, investigation pipeline (`rehub analyze`, `rehub show`) with JSON persistence. Full test suite passes (`uv run pytest`), including an end to end run in a no-network, read-only, cap-dropped container.

## Decisions

- Python 3.13 and uv. Engine and tools share one image; tools run as subprocesses, no Docker socket.
- Own Community ID v1 implementation, verified against Zeek and Suricata output.
- Findings merge across tools by flow plus Modbus transaction id, or a 1 second window for S7.
- MACs: ARP is authoritative. MACs seen on routed traffic are never attributed to hosts (gateway heuristic).
- No IEEE OUI database committed (redistribution terms unclear). Small embedded ICS vendor table plus optional `REHUB_OUI` CSV.
- ATT&CK for ICS: only T0855, T0836, T0858 are mapped, reported as candidates. Authorization context is not visible in a capture.
- PLC: ST, PLCopen XML, L5X static analysis only. Binary project files (`.ACD`, `.zap16`) are hashed and stored. Modbus wire address N is assumed to be `%MW N`; this is shown as an assumption wherever used.
- Emerging Threats Open rules are not bundled yet. Sources disagree on license wording (BSD, MIT, old GPL sids). Check the current LICENSE file before bundling.

## Next, in order

1. API (upload, status, results, evidence download) over the existing pipeline. Results are `record.json` per investigation under `$REHUB_DATA/investigations/<id>/`.
2. (done) pipeline runner.
3. UI: assets, flow graph, detections, evidence drill-down, PLC impact panel. Plain HTML and JS.
4. Report export with hashes, caveats and ATT&CK note.
5. Hardened compose (internal network plus gateway so the engine has no egress, `cap_drop: ALL`, read-only root, memory and pid limits), `install.sh`, publish image to GHCR.
6. Emerging Threats rules bundle after the license check.
7. Test on real ICS pcaps. The only pcap so far is synthetic.
8. Docs, demo script.

## Known limits

- `correlate` holds all events in memory; very large captures will hurt.
- Assets are keyed by IP; DHCP churn and multi-IP devices are not merged.
- Nested archives are stored as unknown.
- The pinned Debian `tshark` version in the Dockerfile will eventually disappear from the mirror (affects image builds only).
- Graphical PLC bodies (LD, FBD) are not analyzed.

## Workflow notes

- Rebuild the image after changing `src/`, then run `./scripts/regen-fixtures.sh` if tool output changes. Stale images silently produce old fixtures.
- Conventional Commits, subject 50 chars or less, no em dashes.
