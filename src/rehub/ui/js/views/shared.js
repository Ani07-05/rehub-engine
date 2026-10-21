import { h, s, mount } from "../dom.js";
import { sevShape } from "../icons.js";
import { api } from "../api.js";
import { lanes, severityWord } from "../narrate.js";

export function sevBadge(sev) {
  return h("span", { class: `sev ${sev || "info"}` }, sevShape(sev), severityWord(sev));
}

export function laneMini(d, record) {
  const ls = lanes(d, record);
  const label = ls.map((l) => `${l.name} ${l.on ? "saw it" : "did not see it"}`).join(", ");
  return h(
    "span",
    { class: "lanes-mini", role: "img", "aria-label": label },
    ls.map((l) => h("span", { class: `lane-mini${l.on ? "" : " off"}`, "aria-hidden": "true" }, l.name)),
  );
}

export function laneBig(d, record) {
  const ls = lanes(d, record);
  const n = ls.length;
  const row = h(
    "div",
    { class: "lanes" },
    ls.map((l) =>
      h(
        "div",
        { class: `lane${l.on ? "" : " off"}` },
        h("b", {}, l.name),
        h("span", {}, l.on ? l.caption : `${l.caption}: not seen`),
      ),
    ),
  );
  row.style.setProperty("--n", String(n));
  const paths = ls.map((l, i) => {
    const x = ((i + 0.5) / n) * 100;
    return s("path", { class: l.on ? "on" : "off", d: `M${x} 0V9L50 33` });
  });
  const join = s("svg", { class: "lane-join", viewBox: "0 0 100 34", preserveAspectRatio: "none", "aria-hidden": "true" }, paths);
  return h("div", {}, row, join, h("div", { class: "claim" }, d.title));
}

export function codeBlock(lines, hit) {
  return h(
    "div",
    { class: "code", role: "group" },
    lines.map(([num, text]) => h("div", { class: `ln${num === hit ? " hit" : ""}` }, h("i", {}, String(num)), h("span", {}, text))),
  );
}

export async function showLines(target, ctx, ev, line) {
  mount(target, h("div", { class: "skeleton" }));
  try {
    const start = Math.max(1, line - 2);
    const data = await api.lines(ctx.id, ev.sha256, start, 7);
    mount(target, codeBlock(data.lines.map((t, i) => [data.start + i, t]), line));
  } catch (err) {
    mount(target, h("div", { class: "callout err" }, err.message));
  }
}

export async function showPackets(target, ctx, flowKey) {
  mount(target, h("div", { class: "skeleton" }));
  try {
    const data = await api.packets(ctx.id, flowKey, 120);
    if (!data.packets.length) return mount(target, h("div", { class: "empty" }, "No packet list is available for this flow."));
    const rows = data.packets.map((p) =>
      h(
        "tr",
        {},
        h("td", { class: "num" }, String(p.frame)),
        h("td", { class: "mono" }, `${p.src}${p.sport != null ? ":" + p.sport : ""}`),
        h("td", { class: "mono" }, `${p.dst}${p.dport != null ? ":" + p.dport : ""}`),
        h("td", {}, p.protocol),
        h("td", {}, p.info),
      ),
    );
    mount(
      target,
      h(
        "div",
        { class: "tablewrap" },
        h(
          "table",
          {},
          h("thead", {}, h("tr", {}, ["Frame", "From", "To", "Protocol", "Info"].map((c) => h("th", {}, c)))),
          h("tbody", {}, rows),
        ),
      ),
      data.truncated ? h("p", { class: "small muted" }, "Showing the first 120 packets. Download the packet list from the Evidence tab for the rest.") : null,
    );
  } catch (err) {
    mount(target, h("div", { class: "callout err" }, err.message));
  }
}

export function evidenceBySha(record, sha) {
  return record.evidence.find((e) => e.sha256 === sha);
}
