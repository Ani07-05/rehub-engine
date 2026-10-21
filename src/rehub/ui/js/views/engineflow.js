import { h } from "../dom.js";
import { mark } from "../marks.js";
import { PREVIEW_STAGES, STAGE_TABS } from "../narrate.js";

const TOOLS = [
  ["zeek", "Zeek", "Protocol actions"],
  ["suricata", "Suricata", "Rule alerts"],
  ["tshark", "tshark", "Packet details"],
];
const WORDS = { idle: "Waiting", queued: "Waiting", running: "Working", done: "Done", failed: "Failed", skipped: "Not needed" };

function glyph(state) {
  return h("span", { class: "eg-mark" }, mark(state === "done" ? "done" : state === "failed" ? "failed" : "idle"));
}

function box(cls, state, title, caption, detail) {
  return h("div", { class: `eg-box ${cls}`, "data-state": state }, glyph(state), h("b", {}, title), h("span", { class: "eg-cap" }, caption), detail ? h("span", { class: "eg-detail" }, detail) : null);
}

function arrow(on) {
  return h("div", { class: `eg-arrow${on ? " on" : ""}`, "aria-hidden": "true" });
}

export function engineDiagram({ input = "idle", tools = {}, engine = "idle", stages = null } = {}) {
  const toolBoxes = TOOLS.map(([id, name, caption]) => {
    const state = tools[id] || (input === "done" && Object.keys(tools).length === 0 && engine !== "idle" ? "skipped" : "idle");
    return box("eg-tool", state, name, caption, WORDS[state]);
  });
  const stageDefs = stages || PREVIEW_STAGES;
  const stageBoxes = stageDefs.map((st) => box("eg-stage", stages ? "done" : "idle", st.label, stages ? st.result : st.question));
  return h(
    "figure",
    { class: "engine", "aria-label": "How ReHub works: evidence goes through Zeek, Suricata and tshark, then the ReHub engine, then five stages." },
    box("eg-input", input, "PCAP / OT evidence", "One upload, one investigation"),
    arrow(input === "done"),
    h("div", { class: "eg-tools" }, toolBoxes),
    arrow(Object.values(tools).includes("done")),
    box("eg-engine", engine, "ReHub engine", "Normalize, link evidence, keep tool attribution"),
    arrow(engine === "done"),
    h("ol", { class: "eg-stages" }, stageBoxes.map((b) => h("li", {}, b))),
  );
}


export function flowSteps(record, stages) {
  return h(
    "ol",
    { class: "flowlist" },
    stages.map((st) =>
      h(
        "li",
        {},
        h("a", { class: "flowstep", href: `#/i/${record.id}/${STAGE_TABS[st.id]}` },
          h("span", { class: "flowstep-head" }, h("b", {}, st.label), h("span", { class: "flowstep-result" }, st.result)),
          h("span", { class: "flowstep-q" }, st.question),
          h("span", { class: "flowstep-did" }, st.did),
        ),
      ),
    ),
  );
}
