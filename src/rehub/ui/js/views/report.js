import { h, fmtBytes, fmtTime, plural } from "../dom.js";
import {
  ATTACK_NOTE, KIND_NAMES, caveatList, confidenceText, deviceText, headline, isDerived, parseRef,
  plainMeaning, reportFileName, timeText, toolList, uploadedEvidence,
} from "../narrate.js";
import { evidenceBySha, laneMini, sevBadge } from "./shared.js";
import { plcImpact } from "./finding.js";

function table(headers, rows) {
  return h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, headers.map((c) => h("th", {}, c)))), h("tbody", {}, rows)));
}

function refText(record, ref) {
  const parsed = parseRef(ref.ref, ref.tool);
  const ev = evidenceBySha(record, ref.evidence_id);
  const where = parsed.kind === "line" ? `line ${parsed.line}` : parsed.kind === "frames" ? `frames ${parsed.from} to ${parsed.to}` : parsed.where || "";
  return h("li", {}, h("b", {}, ref.tool), " ", ev ? ev.name : parsed.file, where ? `, ${where}` : "", ev ? h("span", { class: "hash" }, ` (sha256 ${ev.sha256.slice(0, 12)})`) : null);
}

function findingBlock(record, d) {
  const inv = record.investigation;
  return h(
    "section",
    { class: "finding" },
    h("h3", {}, d.title, sevBadge(d.severity)),
    h(
      "dl",
      { class: "kv" },
      d.first_ts != null ? [h("dt", {}, "When"), h("dd", {}, timeText(d.first_ts))] : null,
      d.src ? [h("dt", {}, "From"), h("dd", {}, deviceText(inv, d.src))] : null,
      d.dst ? [h("dt", {}, "To"), h("dd", {}, deviceText(inv, d.dst))] : null,
      h("dt", {}, "Confidence"), h("dd", {}, confidenceText(d)),
      h("dt", {}, "Seen by"), h("dd", {}, laneMini(d, record)),
    ),
    h("p", {}, plainMeaning(d)),
    d.attack.length ? h("p", { class: "small" }, "ATT&CK for ICS candidates: ", d.attack.join("; ")) : null,
    d.plc.length ? h("div", {}, h("h4", { class: "small muted" }, "Effect on the PLC program"), d.plc.map(plcImpact), h("p", { class: "small muted" }, d.plc[0].assumption)) : null,
    h("div", {}, h("h4", { class: "small muted" }, "Evidence"), h("ul", { class: "bullets small" }, d.refs.map((r) => refText(record, r)))),
  );
}

export function renderReport(record) {
  const inv = record.investigation;
  const caveats = caveatList(record);
  const hasPlc = inv.detections.some((d) => d.plc.length);
  const hasAttack = inv.detections.some((d) => d.attack.length);
  const created = fmtTime(Date.parse(record.created) / 1000);
  const generated = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
  return h(
    "article",
    { class: "report" },
    h("header", { class: "stack" },
      h("h1", {}, "Investigation report"),
      h("dl", { class: "kv" },
        h("dt", {}, "Case"), h("dd", { class: "mono" }, record.id),
        h("dt", {}, "Analyzed"), h("dd", {}, created),
        record.engine_version ? [h("dt", {}, "Analyzed with"), h("dd", {}, `ReHub ${record.engine_version}`)] : null,
        h("dt", {}, "Evidence"), h("dd", {}, `${plural(uploadedEvidence(record).length, "uploaded file")}, ${plural(record.evidence.length, "file")} including tool output`),
        h("dt", {}, "Report created"), h("dd", {}, generated),
      ),
    ),
    h("section", { class: "stack" }, h("h2", {}, "Summary"), headline(record).map((p) => h("p", { class: "answer" }, p))),
    h("section", {}, h("h2", {}, `Findings (${inv.detections.length})`), inv.detections.length ? inv.detections.map((d) => findingBlock(record, d)) : h("p", { class: "muted" }, "No findings were raised. That is not proof the network was safe; see the limits below.")),
    h("section", { class: "stack" }, h("h2", {}, `Devices (${Object.keys(inv.assets).length})`),
      table(["Address", "Type", "Vendor", "Roles", "PLC program"], Object.values(inv.assets).map((a) => h("tr", {}, h("td", { class: "mono" }, a.id), h("td", {}, a.kind), h("td", {}, a.vendor || (a.locally_administered_mac ? "Unidentified (locally administered MAC)" : "Unknown")), h("td", {}, [...a.roles].sort().join(", ") || "none seen"), h("td", {}, a.plc_projects.join(", ") || "none linked"))))),
    h("section", { class: "stack" }, h("h2", {}, `Conversations (${Object.keys(inv.flows).length})`),
      table(["From", "To", "Protocol", "Packets", "Started"], Object.values(inv.flows).map((f) => h("tr", {}, h("td", { class: "mono" }, `${f.src}:${f.sport}`), h("td", { class: "mono" }, `${f.dst}:${f.dport}`), h("td", {}, f.service || f.proto || "unknown"), h("td", { class: "num" }, f.packets ? String(f.packets) : "n/a"), h("td", {}, timeText(f.first_ts)))))),
    h("section", { class: "stack" }, h("h2", {}, "What could not be verified"),
      caveats.length ? h("ul", { class: "bullets" }, caveats.map((c) => h("li", {}, c))) : h("p", { class: "muted" }, "No gaps were flagged. A finding that is not listed was still not proven safe.")),
    h("section", { class: "stack" }, h("h2", {}, "Evidence and chain of custody"),
      h("p", { class: "muted" }, "Each file is identified by its SHA-256 hash. Files produced by the tools name the capture they came from."),
      table(["File", "Type", "Size", "SHA-256"], record.evidence.map((e) => h("tr", {}, h("td", {}, e.name, isDerived(record, e) ? h("div", { class: "xs faint" }, `produced from ${e.origin} (sha256 ${e.origin_sha256.slice(0, 12)})`) : null), h("td", {}, KIND_NAMES[e.kind] || e.kind), h("td", { class: "num" }, fmtBytes(e.size)), h("td", { class: "hash" }, e.sha256)))),
      record.tool_runs.length ? table(["Tool", "Capture", "Result"], record.tool_runs.map((r) => h("tr", {}, h("td", {}, r.tool), h("td", {}, r.pcap), h("td", {}, r.ok ? "Completed" : `Failed: ${r.error}`)))) : null),
    h("section", { class: "stack" }, h("h2", {}, "Method and limits"),
      h("ul", { class: "bullets" },
        h("li", {}, "Findings come from Zeek (protocol actions), Suricata (rule alerts), tshark (packet details) and static reading of PLC files. A finding is marked confirmed only when two independent tools reported it."),
        hasAttack ? h("li", {}, ATTACK_NOTE) : null,
        hasPlc ? h("li", {}, record.investigation.detections.find((d) => d.plc.length).plc[0].assumption) : null,
        h("li", {}, "The absence of a finding is not proof of safety. Missing tools, capture loss and unparsed files are listed under what could not be verified."),
        h("li", {}, "All analysis ran on the computer that produced this report. No evidence was sent elsewhere."),
        h("li", {}, "The same evidence produces the same findings; the hashes above identify exactly what was analyzed."),
      ),
    ),
    h("footer", { class: "foot small muted" }, `ReHub ${record.engine_version || ""} investigation ${record.id}`),
  );
}

function escapeText(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function buildStandaloneHtml(record, stylesheet) {
  const body = new XMLSerializer().serializeToString(renderReport(record));
  return [
    "<!doctype html>",
    '<html lang="en" class="paper">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>${escapeText(`ReHub report ${record.id}`)}</title>`,
    `<style>\n${stylesheet}\n</style>`,
    "</head>",
    "<body>",
    body,
    "</body>",
    "</html>",
    "",
  ].join("\n");
}

async function download(record, note) {
  try {
    const [app, rep] = await Promise.all(["/ui/css/app.css", "/ui/css/report.css"].map((u) => fetch(u).then((r) => r.text())));
    const url = URL.createObjectURL(new Blob([buildStandaloneHtml(record, `${app}\n${rep}`)], { type: "text/html" }));
    const link = h("a", { href: url, download: reportFileName(record) });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    note.textContent = `Saved ${reportFileName(record)}. It has no scripts and opens offline.`;
  } catch (err) {
    note.textContent = `Could not create the file: ${err.message}`;
  }
}

export function reportTab(record) {
  const note = h("span", { class: "small muted", role: "status" });
  return h(
    "div",
    { class: "stack" },
    h("div", { class: "report-toolbar" },
      h("button", { class: "btn primary", type: "button", onclick: () => window.print() }, "Print or save as PDF"),
      h("button", { class: "btn", type: "button", onclick: () => download(record, note) }, "Download HTML report"),
      note,
    ),
    renderReport(record),
  );
}
