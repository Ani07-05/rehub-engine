import { h } from "../dom.js";
import { ATTACK_NOTE, caveatList, deviceText, headline, impactLine, networkFindings, uploadedEvidence } from "../narrate.js";
import { fmtTime, plural } from "../dom.js";
import { flowSteps } from "./engineflow.js";
import { flowStages } from "../narrate.js";
import { laneMini, sevBadge } from "./shared.js";

const MAX_SHOWN = 6;

function findingRow(record, d) {
  const inv = record.investigation;
  const impact = impactLine(d);
  const who = d.src && d.dst ? `From ${deviceText(inv, d.src)} to ${deviceText(inv, d.dst)}` : d.dst ? `On ${deviceText(inv, d.dst)}` : "";
  return h(
    "a",
    { class: "row-link", href: `#/i/${record.id}/findings/${d.id}` },
    h("span", { class: "title" }, sevBadge(d.severity), " ", d.title),
    laneMini(d, record),
    h("span", { class: "meta" }, [who, impact].filter(Boolean).join(". ")),
    h("span", { class: "open" }, "Open evidence"),
  );
}

function involved(record, findings) {
  const inv = record.investigation;
  const ips = [];
  for (const d of findings) for (const ip of [d.src, d.dst]) if (ip && !ips.includes(ip)) ips.push(ip);
  return ips.slice(0, 8).map((ip) => h("li", {}, deviceText(inv, ip)));
}

export function renderSummary(record) {
  const inv = record.investigation;
  const answer = headline(record);
  const network = networkFindings(record);
  const key = inv.detections.filter((d) => d.severity === "high" || d.severity === "medium");
  const shown = key.slice(0, MAX_SHOWN);
  const caveats = caveatList(record);
  const hasAttack = inv.detections.some((d) => d.attack.length);
  return h(
    "div",
    { class: "col stack-lg" },
    h(
      "section",
      { class: "stack" },
      h("h1", {}, "What happened"),
      answer.map((p) => h("p", { class: "answer" }, p)),
      h(
        "p",
        { class: "small muted" },
        `Read ${plural(uploadedEvidence(record).length, "file")}, found ${plural(Object.keys(inv.assets).length, "asset")} and ${plural(Object.keys(inv.flows).length, "conversation")}. Analyzed on this computer, ${fmtTime(Date.parse(record.created) / 1000)}.`,
      ),
    ),
    shown.length
      ? h(
          "section",
          { class: "stack" },
          h("h2", {}, "Key detections"),
          h("p", { class: "small muted" }, "The tool lanes show who saw each detection: Zeek (protocol actions), Suricata (rule alerts), tshark (packet details) and PLC (program logic). Filled lanes saw it."),
          shown.map((d) => findingRow(record, d)),
          key.length > shown.length ? h("a", { href: `#/i/${record.id}/findings` }, `Show all ${key.length} detections`) : null,
        )
      : null,
    h("section", { class: "stack" }, h("h2", {}, "How ReHub got here"), h("p", { class: "small muted" }, "Each step feeds the next. Select one to open it."), flowSteps(record, flowStages(record))),
    network.length
      ? h("section", { class: "stack" }, h("h2", {}, "Who is involved"), h("ul", { class: "bullets" }, involved(record, network)))
      : null,
    h(
      "section",
      { class: "stack" },
      h("h2", {}, "What we could not verify"),
      caveats.length
        ? h("ul", { class: "bullets" }, caveats.map((c) => h("li", {}, c)))
        : h("p", { class: "muted" }, "Nothing was flagged as missing. A detection that is not listed here was still not proven safe."),
      hasAttack ? h("p", { class: "small muted" }, ATTACK_NOTE) : null,
    ),
    h("p", { class: "filters" }, h("a", { class: "btn", href: `#/i/${record.id}/findings` }, "Dig deeper in Investigator mode"), h("a", { class: "btn", href: `#/i/${record.id}/report` }, "Open the report")),
  );
}
