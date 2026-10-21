import { h, mount } from "../dom.js";
import { api } from "../api.js";
import { sevShape } from "../icons.js";

const LOOK = {
  ok: { sev: null, cls: "ok", word: "Ready" },
  warn: { sev: "medium", cls: "medium", word: "Needs attention" },
  fail: { sev: "high", cls: "high", word: "Not working" },
};

function badge(status) {
  const look = LOOK[status] || LOOK.fail;
  return h("span", { class: `sev ${look.cls}` }, sevShape(look.sev), look.word);
}

function versions(checks) {
  const parts = [];
  for (const [id, name] of [["zeek", "Zeek"], ["suricata", "Suricata"], ["tshark", "tshark"]]) {
    const c = checks.find((x) => x.id === id);
    if (c && c.status === "ok") parts.push(`${name} ${c.detail.replace("version ", "")}`);
  }
  return parts.join(", ");
}

export function systemCheck() {
  const root = h("section", { class: "panel pad status", "aria-live": "polite" });
  const draw = async (force) => {
    mount(root, h("div", { class: "skeleton" }), h("p", { class: "small muted" }, "Checking that the tools work on a sample capture..."));
    try {
      const report = await api.doctor(force);
      const bad = report.checks.filter((c) => c.status !== "ok");
      const lead = report.status === "ok" ? versions(report.checks) : report.status === "fail" ? "Analysis will not work until this is fixed." : "ReHub works, with caveats.";
      mount(
        root,
        h("div", { class: "filters" }, badge(report.status), h("span", { class: "muted small" }, lead), h("span", { class: "grow" }), h("button", { class: "btn small ghost", type: "button", onclick: () => draw(true) }, "Check again")),
        bad.length ? h("ul", {}, bad.map((c) => h("li", {}, h("div", { class: "filters" }, badge(c.status), h("b", {}, c.label)), h("p", { class: "small muted" }, c.detail), c.fix ? h("p", { class: "small" }, c.fix) : null))) : null,
        h("details", {}, h("summary", { class: "small" }, "Show all checks"), h("ul", {}, report.checks.map((c) => h("li", { class: "small" }, badge(c.status), " ", h("b", {}, c.label), h("span", { class: "muted" }, ` ${c.detail}`))))),
      );
    } catch (err) {
      mount(root, h("div", { class: "filters" }, badge("fail"), h("span", { class: "muted small" }, err.message)));
    }
  };
  draw(false);
  return root;
}
