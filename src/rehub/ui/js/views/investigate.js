import { h, mount, fmtBytes, fmtTime, plural, shortHash } from "../dom.js";
import { chevron } from "../icons.js";
import { api } from "../api.js";
import { KIND_NAMES, deviceLabel, isDerived, lanes, severityWord, timeText } from "../narrate.js";
import { renderFinding } from "./finding.js";
import { flowMap } from "./flowmap.js";
import { laneMini, sevBadge, showLines, showPackets } from "./shared.js";
import { reportTab } from "./report.js";

const TABS = [
  ["devices", "Devices"],
  ["communication", "Communication"],
  ["findings", "Findings"],
  ["evidence", "Evidence"],
  ["report", "Report"],
];
const RANK = { high: 3, medium: 2, low: 1 };

export function flowNav(record, tab) {
  const items = [];
  TABS.forEach(([id, label], i) => {
    if (i) items.push(chevron());
    items.push(h("a", { href: `#/i/${record.id}/${id}`, "aria-current": tab === id ? "page" : null }, label));
  });
  return h("nav", { class: "flownav", "aria-label": "Investigation sections" }, items);
}

function deviceFindings(record, ip) {
  return record.investigation.detections.filter((d) => d.src === ip || d.dst === ip);
}

function devicesTab(record) {
  const inv = record.investigation;
  const rows = Object.values(inv.assets).map((a) => {
    const n = deviceFindings(record, a.id).length;
    const vendor = a.vendor || (a.locally_administered_mac ? "Unidentified (locally administered MAC)" : "Unknown");
    const macs = Object.entries(a.macs).map(([m, how]) => `${m} (${how})`).join(", ");
    return h(
      "tr",
      {},
      h("td", { class: "mono" }, a.id),
      h("td", {}, a.kind),
      h("td", {}, vendor),
      h("td", {}, [...a.roles].sort().join(", ") || "none seen"),
      h("td", {}, a.plc_projects.length ? a.plc_projects.join(", ") : "none linked"),
      h("td", { class: "mono" }, macs || "none"),
      h("td", { class: "num" }, timeText(a.first_ts)),
      h("td", {}, n ? h("a", { href: `#/i/${record.id}/findings?device=${encodeURIComponent(a.id)}` }, plural(n, "finding")) : "none"),
    );
  });
  return h(
    "section",
    { class: "stack" },
    h("h2", {}, `Devices (${rows.length})`),
    h("p", { class: "muted" }, "Everything that sent or received traffic. A vendor is only shown when the hardware address was confirmed, never guessed from a router."),
    h(
      "div",
      { class: "tablewrap" },
      h(
        "table",
        {},
        h("thead", {}, h("tr", {}, ["Address", "Type", "Vendor", "Roles", "PLC program", "Hardware address", "First seen", "Findings"].map((c) => h("th", {}, c)))),
        h("tbody", {}, rows),
      ),
    ),
  );
}

function communicationTab(record, ctx) {
  const inv = record.investigation;
  const worst = new Map();
  for (const d of inv.detections) {
    if (d.flow_key && (RANK[d.severity] || 0) > (RANK[worst.get(d.flow_key)] || 0)) worst.set(d.flow_key, d.severity);
  }
  const rows = [];
  for (const f of Object.values(inv.flows)) {
    const slot = h("div", { class: "stack" });
    const flagged = worst.get(f.key);
    const hasTshark = f.tools.includes("tshark");
    rows.push(
      h(
        "tr",
        {},
        h("td", { class: "mono" }, `${f.src}:${f.sport}`),
        h("td", { class: "mono" }, `${f.dst}:${f.dport}`),
        h("td", {}, f.service || f.proto || "unknown"),
        h("td", { class: "num" }, f.packets ? String(f.packets) : "n/a"),
        h("td", {}, flagged ? sevBadge(flagged) : h("span", { class: "faint" }, "none")),
        h("td", { class: "num" }, timeText(f.first_ts)),
        h(
          "td",
          {},
          hasTshark ? h("button", { class: "btn small", type: "button", onclick: () => showPackets(slot, ctx, f.key) }, "Show packets") : h("span", { class: "faint" }, "no packets"),
          slot,
        ),
      ),
    );
  }
  const onSelect = (ip) => {
    location.hash = `#/i/${record.id}/findings?device=${encodeURIComponent(ip)}`;
  };
  return h(
    "section",
    { class: "stack-lg" },
    h("section", { class: "stack" }, h("h2", {}, "Who talks to whom"), flowMap(record, onSelect)),
    h(
      "section",
      { class: "stack" },
      h("h2", {}, `Conversations (${rows.length})`),
      h(
        "div",
        { class: "tablewrap" },
        h("table", {}, h("thead", {}, h("tr", {}, ["From", "To", "Protocol", "Packets", "Finding", "Started", "Detail"].map((c) => h("th", {}, c)))), h("tbody", {}, rows)),
      ),
    ),
  );
}

function findingsTab(record, ctx, selectedId, query) {
  const inv = record.investigation;
  const device = query.get("device");
  const sev = query.get("severity") || "all";
  const only2 = query.get("corroborated") === "1";
  let list = inv.detections.filter((d) => (sev === "all" ? true : d.severity === sev) && (!only2 || d.corroborated) && (!device || d.src === device || d.dst === device));
  const base = `#/i/${record.id}/findings`;
  const href = (extra, id) => {
    const q = new URLSearchParams(query);
    for (const [k, v] of Object.entries(extra)) v == null || v === "" ? q.delete(k) : q.set(k, v);
    const qs = q.toString();
    return `${base}${id ? "/" + id : ""}${qs ? "?" + qs : ""}`;
  };
  const selected = list.find((d) => d.id === selectedId) || inv.detections.find((d) => d.id === selectedId) || list[0] || null;
  const filters = h(
    "div",
    { class: "filters", role: "group", "aria-label": "Filter findings" },
    ...["all", "high", "medium", "low"].map((v) =>
      h("a", { class: "btn small ghost", href: href({ severity: v === "all" ? null : v }, null), "aria-current": sev === v ? "true" : null }, v === "all" ? "All" : severityWord(v)),
    ),
    h("a", { class: "btn small ghost", href: href({ corroborated: only2 ? null : "1" }, null), "aria-current": only2 ? "true" : null }, "Two tools agree"),
    device ? h("a", { class: "btn small", href: href({ device: null }, null) }, `Clear device ${device}`) : null,
  );
  const picks = list.map((d) =>
    h(
      "a",
      { class: "pick", href: href({}, d.id), "aria-current": selected && selected.id === d.id ? "true" : null },
      sevBadge(d.severity),
      h("span", { class: "title" }, d.title),
      h("span", { class: "meta" }, d.src && d.dst ? `${d.src} to ${d.dst}` : d.dst || d.src || "no network endpoint"),
      h("span", { class: "meta" }, laneMini(d, record)),
    ),
  );
  return h(
    "section",
    { class: "stack" },
    h("h2", {}, `Findings (${list.length})`),
    filters,
    list.length
      ? h("div", { class: "twopane" }, h("div", { class: "listpane" }, picks), h("div", { class: "detail" }, selected ? renderFinding(record, selected, ctx) : null))
      : h("div", { class: "empty" }, "No findings match these filters.", " ", h("a", { href: base }, "Clear filters")),
  );
}

function evidenceTab(record, ctx) {
  const viewers = new Map();
  const rows = record.evidence.map((e) => {
    const slot = h("div", { class: "stack" });
    viewers.set(e.sha256, slot);
    const derived = isDerived(record, e);
    const textual = ["zeek_log", "suricata_eve", "plc_st", "syslog", "csv", "csv_assets", "csv_historian", "tshark_tsv"].includes(e.kind);
    return h(
      "tr",
      {},
      h("td", {}, e.name, derived ? h("div", { class: "xs faint" }, `produced from ${e.origin}`) : null),
      h("td", {}, KIND_NAMES[e.kind] || e.kind),
      h("td", { class: "num" }, fmtBytes(e.size)),
      h("td", { class: "mono", title: e.sha256 }, shortHash(e.sha256)),
      h(
        "td",
        {},
        h("a", { class: "btn small", href: api.downloadUrl(ctx.id, e.sha256), download: "" }, "Download"),
        " ",
        textual ? h("button", { class: "btn small ghost", type: "button", onclick: () => showLines(slot, ctx, e, 1) }, "Preview") : null,
        slot,
      ),
    );
  });
  const runs = record.tool_runs.map((r) =>
    h("tr", {}, h("td", {}, r.tool), h("td", {}, r.pcap), h("td", {}, r.ok ? "Completed" : `Failed: ${r.error}`), h("td", { class: "num" }, `${r.seconds.toFixed(1)} s`)),
  );
  return h(
    "section",
    { class: "stack-lg" },
    h(
      "section",
      { class: "stack" },
      h("h2", {}, `Evidence files (${rows.length})`),
      h("p", { class: "muted" }, "Every file is identified by its SHA-256 hash. Files the tools produced list the capture they came from, so each finding traces back to the original upload."),
      h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["File", "Type", "Size", "SHA-256", "Actions"].map((c) => h("th", {}, c)))), h("tbody", {}, rows))),
    ),
    runs.length
      ? h("section", { class: "stack" }, h("h2", {}, "Tool runs"), h("div", { class: "tablewrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Tool", "Capture", "Result", "Time"].map((c) => h("th", {}, c)))), h("tbody", {}, runs))))
      : null,
  );
}

export function renderInvestigator(record, tab, selectedId, query, ctx) {
  const body = { devices: () => devicesTab(record), communication: () => communicationTab(record, ctx), findings: () => findingsTab(record, ctx, selectedId, query), evidence: () => evidenceTab(record, ctx), report: () => reportTab(record) }[tab] || (() => findingsTab(record, ctx, selectedId, query));
  return h("div", { class: "wide stack-lg" }, flowNav(record, tab), body());
}
