# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack
Delegated: plain static HTML, CSS and JS with no build step, served by the existing Python server under a strict CSP (no inline script or style, no external hosts). Chosen because the image has no Node, the tool must run offline, and Arsenal reviewers should be able to read every file.

## Users
People who receive OT evidence after something went wrong: a pcap and maybe PLC project files. The reader is half technical, half not: they need a plain answer fast and the ability to dig into raw evidence whenever they choose. They often work on a laptop, offline, inside a plant or on a response engagement, and must be able to explain and defend what they found to others (managers, vendors, plant staff, other analysts).

## Product Purpose
ReHub turns one upload of OT evidence into one investigation: which devices exist, who talked to whom, what looks wrong, the evidence behind each claim, and a report. It runs Zeek, Suricata and tshark locally, correlates them, and joins network writes to the PLC logic they hit. Success is a reader who can state what happened, which device and process were affected, and how sure the tool is, without needing to know Zeek or Suricata.

## Positioning
Not a SOC dashboard (Malcolm) and not a query explorer (Zui): it answers instead of asking the reader to query. The mechanism no neighbor copies: a network command is tied to the exact PLC variable, the logic that reads it and the output it drives, with every claim attributed to the tool that saw it and backed by hashed evidence.

## Operating Context
Local and offline: a Docker container on the analyst's machine, bound to loopback, no network egress, no telemetry. Inputs are pcaps, Zeek logs, Suricata eve.json, and PLC files (Structured Text, PLCopen XML, L5X). Output is an on-screen investigation and an exportable report. Presented live at Black Hat Arsenal, where the demo must work without real PLC hardware.

## Capabilities and Constraints
- Two reading modes are required: a condensed summary view, and a deeper investigator view reachable at any point from the summary.
- Each finding shows which tools saw it, whether two tools corroborated it, ATT&CK for ICS candidates, and PLC impact when a project file is linked.
- Caveats are first-class: missing tools, capture loss, and gateway-MAC handling must be shown, never hidden. Absence of a finding is not proof of safety.
- The Modbus-address-to-PLC-variable mapping is an assumption and must be stated wherever it is used.
- ATT&CK mappings are candidates only (T0855, T0836, T0858 so far); authorization cannot be known from a capture.
- Evidence can only be downloaded, never rendered inline. All file-derived text must be escaped.
- No authentication: loopback only. The UI must not suggest multi-user or cloud features.
- Terminology: investigation, evidence, asset, flow, detection, corroborated, caveat.

## Brand Commitments
The user posted a diagram of the product flow (PCAP / OT evidence -> Zeek, Suricata, tshark -> ReHub correlation engine -> unified investigation view: Asset -> Communication -> Detection -> Evidence -> Report) in a black ground with thin rounded outlines, white text and downward arrows. The user confirmed staying in that world is binding: dark, calm, thin-outline. The product name is ReHub.

## Evidence on Hand
Synthetic demo only: fixtures/ot-demo.pcap (HMI polling, routed hosts, rogue Modbus writes, S7 PLC stop), fixtures/plc/pump.st and pump.xml, tank.L5X. No real customer data, testimonials, benchmarks or logos exist; none may be invented.

## Product Principles
- Answer first, evidence on demand: the summary states what happened in plain words; every sentence expands to the proof.
- Never overclaim: confidence comes from tool agreement and evidence, and uncertainty is stated beside the claim.
- One reader, two depths: the same facts at summary and investigator level, no separate product.
- Local and inspectable: nothing leaves the machine, and every number can be traced to a file, a hash and a line.

## Accessibility & Inclusion
Readable by non-specialists: plain language first, jargon only in the investigator view with its meaning available. Keyboard operable, visible focus, sufficient contrast on the dark ground, motion respects reduced-motion. Severity is never conveyed by color alone.
