import { h, mount } from "../dom.js";
import { api } from "../api.js";
import { ATTACK_NOTE, deviceText, parseRef, plainMeaning, timeText, toolList } from "../narrate.js";
import { codeBlock, evidenceBySha, laneBig, sevBadge, showLines, showPackets } from "./shared.js";

function plcImpact(impact) {
  const readerLines = impact.readers.map((r) => {
    const m = /^([^:]+(?::[^:]*)?:\d+): (.*)$/.exec(r);
    return m ? [m[1], m[2]] : ["", r];
  });
  return h(
    "div",
    { class: "varbox" },
    h("div", {}, h("b", { class: "mono" }, impact.variable), " ", h("span", { class: "muted mono" }, `${impact.address} ${impact.dtype}`)),
    impact.comment ? h("p", { class: "small muted" }, impact.comment) : null,
    impact.new_values ? h("p", { class: "small" }, "Written value: ", h("code", {}, impact.new_values)) : null,
    impact.readers.length
      ? h(
          "div",
          { class: "stack" },
          h("p", { class: "small muted" }, "Read by the program here:"),
          h(
            "div",
            { class: "code", role: "group" },
            readerLines.map(([loc, text]) => h("div", { class: "ln" }, h("i", {}, loc), h("span", {}, text))),
          ),
        )
      : h("p", { class: "small muted" }, "No program logic reads this value."),
    impact.drives.length ? h("p", { class: "small" }, "Drives: ", h("b", {}, impact.drives.join(", "))) : null,
    impact.size_known ? null : h("p", { class: "small muted" }, "The size of this variable's type is unknown, so the register overlap is approximate."),
  );
}

function refRow(ctx, ref) {
  const parsed = parseRef(ref.ref, ref.tool);
  const ev = evidenceBySha(ctx.record, ref.evidence_id);
  const viewer = h("div", { class: "stack" });
  const actions = [];
  if (parsed.kind === "line" && ev) {
    actions.push(h("button", { class: "btn small", type: "button", onclick: () => showLines(viewer, ctx, ev, parsed.line) }, "Show source line"));
  }
  if (parsed.kind === "frames" && ctx.flowKey) {
    actions.push(h("button", { class: "btn small", type: "button", onclick: () => showPackets(viewer, ctx, ctx.flowKey) }, "Show packets"));
  }
  if (parsed.kind === "plc" && ev) {
    const m = /:(\d+)$/.exec(parsed.where);
    if (ev.kind === "plc_st" && m) {
      actions.push(h("button", { class: "btn small", type: "button", onclick: () => showLines(viewer, ctx, ev, Number(m[1])) }, "Show source"));
    } else {
      actions.push(h("span", { class: "xs faint" }, `Location inside the project: ${parsed.where}`));
    }
  }
  if (ev) actions.push(h("a", { class: "btn small ghost", href: api.downloadUrl(ctx.id, ev.sha256), download: "" }, "Download file"));
  return h(
    "li",
    {},
    h("div", { class: "small" }, h("b", {}, ref.tool), " ", h("span", { class: "mono" }, ref.ref)),
    h("div", { class: "filters" }, actions),
    viewer,
  );
}

export function renderFinding(record, d, ctx) {
  const inv = record.investigation;
  const flow = d.flow_key ? inv.flows[d.flow_key] : null;
  const local = { ...ctx, record, flowKey: d.flow_key };
  const attackBlock = d.attack.length
    ? h(
        "div",
        {},
        h("p", { class: "small muted" }, "ATT&CK for ICS candidates"),
        h("div", {}, d.attack.map((a) => h("span", { class: "chip" }, a))),
        h("p", { class: "xs faint" }, ATTACK_NOTE),
      )
    : null;
  const attrs = Object.entries(d.attrs || {}).filter(([k]) => !["project", "variable"].includes(k));
  return h(
    "article",
    { class: "stack-lg", "aria-labelledby": "finding-title" },
    h(
      "header",
      { class: "stack" },
      h("h2", { id: "finding-title" }, d.title),
      h("div", { class: "filters" }, sevBadge(d.severity), h("span", { class: "muted small" }, `${d.count} ${d.count === 1 ? "event" : "events"}`), h("span", { class: "muted small" }, timeText(d.first_ts))),
      d.src || d.dst
        ? h(
            "dl",
            { class: "kv" },
            h("dt", {}, "From"),
            h("dd", {}, d.src ? deviceText(inv, d.src) : "not applicable"),
            h("dt", {}, "To"),
            h("dd", {}, d.dst ? deviceText(inv, d.dst) : "not applicable"),
            flow ? [h("dt", {}, "Conversation"), h("dd", { class: "mono" }, `${flow.src}:${flow.sport} to ${flow.dst}:${flow.dport} ${flow.proto || ""} ${flow.service || ""}`)] : null,
            h("dt", {}, "Seen by"),
            h("dd", {}, toolList(d.tools)),
          )
        : null,
    ),
    h("section", { class: "stack" }, h("h3", {}, "Who saw it"), laneBig(d, record), d.corroborated ? h("p", { class: "small muted" }, "Two independent tools reported this, which raises confidence.") : h("p", { class: "small muted" }, "Only one tool reported this. Treat it as unconfirmed until you check the evidence.")),
    h("section", { class: "stack" }, h("h3", {}, "What this means"), h("p", {}, plainMeaning(d)), attackBlock),
    d.plc.length
      ? h("section", { class: "stack" }, h("h3", {}, "Effect on the PLC program"), d.plc.map(plcImpact), h("p", { class: "small muted" }, d.plc[0].assumption))
      : null,
    attrs.length && d.tools.includes("plc")
      ? h("section", { class: "stack" }, h("h3", {}, "Why it was flagged"), h("p", {}, d.attrs.detail || ""))
      : null,
    h("section", { class: "stack" }, h("h3", {}, "Evidence"), h("ul", { class: "list" }, d.refs.map((r) => refRow(local, r)))),
  );
}
