export const ATTACK_NOTE =
  "ATT&CK for ICS techniques are candidates inferred from observed behavior. " +
  "Whether a command was unauthorized depends on context a capture cannot show.";

const SEV_WORD = { high: "High", medium: "Medium", low: "Low" };

export function severityWord(sev) {
  return SEV_WORD[sev] || "Info";
}

export function isNetwork(d) {
  return !(d.tools.length === 1 && d.tools[0] === "plc");
}

function vendorShort(vendor) {
  return vendor ? vendor.split(" (")[0] : "";
}

export function deviceLabel(inv, ip) {
  const a = inv.assets[ip];
  if (!a) return "device";
  const vendor = vendorShort(a.vendor);
  let label;
  if (a.kind === "controller") label = vendor ? `${vendor} controller` : "controller";
  else if (a.kind === "client") label = vendor ? `${vendor} device` : a.locally_administered_mac ? "unidentified device" : "client";
  else label = vendor || "device";
  const projects = a.plc_projects || [];
  if (a.kind === "controller" && projects.length) label += `, ${projects[0]} program`;
  return label;
}

export function deviceText(inv, ip) {
  return ip ? `${ip} (${deviceLabel(inv, ip)})` : "an unknown device";
}

const NOUNS = [
  [/^Modbus (WRITE_SINGLE_COIL|WRITE_MULTIPLE_COILS)/i, ["coil write command", "coil write commands"]],
  [/^Modbus (WRITE_|MASK_WRITE|READ_WRITE)/i, ["register write command", "register write commands"]],
  [/^S7comm .*stop/i, ["PLC stop command", "PLC stop commands"]],
  [/^S7comm .*download/i, ["program download command", "program download commands"]],
  [/^S7comm/i, ["S7 control command", "S7 control commands"]],
  [/^ARP:/i, ["address conflict", "address conflicts"]],
];

export function actionNoun(d, count) {
  for (const [re, forms] of NOUNS) if (re.test(d.title)) return forms[count === 1 ? 0 : 1];
  return count === 1 ? "flagged event" : "flagged events";
}

function joinList(items) {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

export function networkFindings(record) {
  return record.investigation.detections.filter(isNetwork);
}

function actorSentences(record, findings) {
  const inv = record.investigation;
  const bySrc = new Map();
  for (const d of findings) {
    const key = d.src || "unknown";
    if (!bySrc.has(key)) bySrc.set(key, []);
    bySrc.get(key).push(d);
  }
  const sentences = [];
  for (const [src, list] of [...bySrc].slice(0, 2)) {
    const byTarget = new Map();
    for (const d of list) {
      const noun = actionNoun(d, 2).replace(/s$/, "");
      const key = `${d.dst || "unknown"}|${noun}`;
      byTarget.set(key, [...(byTarget.get(key) || []), d]);
    }
    const phrases = [...byTarget].map(([key, items]) => {
      const dst = key.split("|")[0];
      const target = dst === "unknown" ? "the network" : deviceText(inv, dst);
      return `${items.length === 1 ? "a" : items.length} ${actionNoun(items[0], items.length)} to ${target}`;
    });
    sentences.push(`${deviceText(inv, src)} sent ${joinList(phrases)}.`);
  }
  if (bySrc.size > 2) sentences.push(`${bySrc.size - 2} more device${bySrc.size - 2 === 1 ? "" : "s"} also sent flagged traffic.`);
  return sentences;
}

function confidenceSentence(findings) {
  const n = findings.length;
  const both = findings.filter((d) => d.corroborated).length;
  if (both === n) return n === 1 ? "Two independent tools agree on it." : "Two independent tools agree on all of them.";
  if (both === 0) return "Only one tool reported this, so treat it as unconfirmed.";
  return `Two independent tools agree on ${both} of ${n}.`;
}

function impactSentence(record, findings) {
  const impacts = findings.flatMap((d) => d.plc || []);
  if (!impacts.length) return "";
  const project = impacts[0].project;
  const vars = [...new Set(impacts.map((i) => i.variable))];
  const drives = [...new Set(impacts.flatMap((i) => i.drives))];
  const tail = drives.length ? `, which feed ${joinList(drives)}` : "";
  return `In the ${project} PLC program these writes change ${joinList(vars)}${tail}.`;
}

export function headline(record) {
  const findings = networkFindings(record).filter((d) => d.severity === "high" || d.severity === "medium");
  const caveats = caveatList(record);
  if (!findings.length) {
    const out = ["No risky commands were found in this capture."];
    if (caveats.length) out.push("That does not prove the network was clean. See what could not be verified below.");
    return out;
  }
  const out = [actorSentences(record, findings).join(" "), confidenceSentence(findings)];
  const impact = impactSentence(record, findings);
  if (impact) out.push(impact);
  return out;
}

export function impactLine(d) {
  const impacts = d.plc || [];
  if (!impacts.length) return "";
  const vars = [...new Set(impacts.map((i) => i.variable))];
  const drives = [...new Set(impacts.flatMap((i) => i.drives))];
  return `Changes ${joinList(vars)}${drives.length ? `, which controls ${joinList(drives)}` : ""}.`;
}

export function plainMeaning(d) {
  const rules = d.rules || [];
  if (rules.some((r) => r === "control:modbus"))
    return "A device told the controller to change a stored value. If the sender is not an authorized operator station, this is an unauthorized command.";
  if (rules.some((r) => r === "control:s7comm") && /stop/i.test(d.title))
    return "A command told the PLC to stop running its program. Outputs stop following the program until it is started again.";
  if (rules.some((r) => r === "control:s7comm"))
    return "A command changed the program or mode on a Siemens controller.";
  if (rules.some((r) => r === "engine:arp_conflict"))
    return "Two devices claimed the same IP address. That can mean address spoofing, or a misconfigured or redundant device.";
  if (d.tools.length === 1 && d.tools[0] === "plc")
    return "This is a review hint from reading the PLC program, not something seen on the network.";
  return "A detection rule matched this traffic. Open the evidence to see exactly what was sent.";
}

export function lanes(d, record) {
  const inv = record.investigation;
  const flow = d.flow_key ? inv.flows[d.flow_key] : null;
  const list = [
    { id: "zeek", name: "Zeek", caption: "Protocol actions", on: d.tools.includes("zeek") },
    { id: "suricata", name: "Suricata", caption: "Rule alerts", on: d.tools.includes("suricata") },
    { id: "tshark", name: "tshark", caption: "Packet details", on: !!(flow && flow.tools.includes("tshark")) },
  ];
  if (record.plc.length) list.push({ id: "plc", name: "PLC", caption: "Program logic", on: d.tools.includes("plc") || (d.plc || []).length > 0 });
  return list;
}

export function caveatList(record) {
  const out = [...record.investigation.caveats, ...record.warnings];
  for (const run of record.tool_runs) if (!run.ok) out.push(`${run.tool} failed on ${run.pcap}: ${run.error}`);
  return [...new Set(out)];
}

export function parseRef(ref, tool) {
  const frames = /^(.*):frames (\d+)-(\d+)$/.exec(ref);
  if (frames) return { kind: "frames", file: frames[1], from: Number(frames[2]), to: Number(frames[3]) };
  const line = /^(.*):L(\d+)$/.exec(ref);
  if (line) return { kind: "line", file: line[1], line: Number(line[2]) };
  if (tool === "plc") {
    const i = ref.indexOf(":");
    return { kind: "plc", file: ref.slice(0, i), where: ref.slice(i + 1) };
  }
  return { kind: "other", file: ref };
}

export function timeText(ts) {
  if (ts == null) return "time not available";
  return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function toolList(tools) {
  const names = { zeek: "Zeek", suricata: "Suricata", tshark: "tshark", plc: "PLC analysis" };
  return joinList([...tools].sort().map((t) => names[t] || t));
}

export function isDerived(record, ev) {
  return record.tool_runs.some((r) => r.pcap_sha256 === ev.origin_sha256 && r.outputs.includes(ev.name));
}

export function uploadedEvidence(record) {
  return record.evidence.filter((e) => !isDerived(record, e));
}

export const KIND_NAMES = {
  pcap: "Packet capture",
  zeek_log: "Zeek log",
  suricata_eve: "Suricata alerts",
  tshark_tsv: "Packet list",
  tshark_json: "tshark export",
  plc_st: "PLC program (Structured Text)",
  plc_plcopen: "PLC project (PLCopen XML)",
  plc_l5x: "PLC project (L5X)",
  syslog: "Syslog",
  csv: "CSV",
  csv_assets: "Asset list (CSV)",
  csv_historian: "Historian export (CSV)",
  unknown: "Unrecognized file",
};

export function reportFileName(record) {
  return `rehub-report-${record.id}.html`;
}

export function confidenceText(d) {
  if (d.tools.length === 1 && d.tools[0] === "plc") return "Review hint from reading the PLC file. It is not a network observation, so it is not confirmed or refuted by the capture.";
  return d.corroborated
    ? `Confirmed by two independent tools (${toolList(d.tools)}).`
    : `Reported by one tool only (${toolList(d.tools)}); treat as unconfirmed.`;
}

const CHAIN = [
  { id: "storage", label: "Storage", ids: ["data", "disk"] },
  { id: "zeek", label: "Zeek", ids: ["zeek", "zeek-ics", "selftest-zeek"] },
  { id: "suricata", label: "Suricata", ids: ["suricata", "selftest-suricata"] },
  { id: "tshark", label: "tshark", ids: ["tshark", "selftest-tshark"] },
];
const RANK_STATUS = { ok: 0, warn: 1, fail: 2 };

export function serviceChain(checks) {
  return CHAIN.map((group) => {
    const members = checks.filter((c) => group.ids.includes(c.id));
    if (!members.length) return { id: group.id, label: group.label, status: "fail", sub: "No result", problems: [{ label: group.label, detail: "The check did not run.", fix: "" }] };
    const status = members.reduce((worst, c) => (RANK_STATUS[c.status] > RANK_STATUS[worst] ? c.status : worst), "ok");
    const problems = members.filter((c) => c.status !== "ok").map((c) => ({ label: c.label, detail: c.detail, fix: c.fix }));
    const lead = members.find((c) => c.id === group.id) || members.find((c) => c.id === "disk") || members[0];
    const sub = status === "ok" ? lead.detail.replace(/^version /, "") : status === "warn" ? "Needs attention" : "Not working";
    return { id: group.id, label: group.label, status, sub, problems };
  });
}

export function chainStatus(chain) {
  return chain.reduce((worst, n) => (RANK_STATUS[n.status] > RANK_STATUS[worst] ? n.status : worst), "ok");
}
