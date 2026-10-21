import { h, mount } from "./dom.js";
import { api } from "./api.js";
import { brandMark } from "./icons.js";
import { renderHome } from "./views/home.js";
import { renderSummary } from "./views/summary.js";
import { renderInvestigator } from "./views/investigate.js";
import { fmtTime } from "./dom.js";

const app = document.getElementById("app");
const bar = document.getElementById("bar");
const cache = new Map();
let lastTab = "findings";
let seq = 0;

function navigate(hash) {
  if (location.hash === hash) route();
  else location.hash = hash;
}

function topbar(record, mode) {
  const kids = [
    h("a", { class: "brand", href: "#/" }, brandMark(), "ReHub"),
  ];
  if (record) {
    kids.push(h("span", { class: "case" }, `Case ${record.id.slice(0, 6)}, ${fmtTime(Date.parse(record.created) / 1000)}`));
    kids.push(h("span", { class: "grow" }));
    kids.push(
      h(
        "div",
        { class: "seg", role: "group", "aria-label": "Reading mode" },
        h("button", { type: "button", "aria-pressed": mode === "summary" ? "true" : "false", onclick: () => navigate(`#/i/${record.id}`) }, "Summary"),
        h("button", { type: "button", "aria-pressed": mode === "investigator" ? "true" : "false", onclick: () => navigate(`#/i/${record.id}/${lastTab}`) }, "Investigator"),
      ),
    );
  } else {
    kids.push(h("span", { class: "grow" }));
  }
  kids.push(h("a", { class: record ? "btn" : "btn ghost", href: "#/" }, "New investigation"));
  mount(bar, kids);
}

function failure(err) {
  mount(app, h("div", { class: "col stack" }, h("h1", {}, "Something went wrong"), h("div", { class: "callout err" }, err.message), h("p", {}, h("a", { class: "btn", href: "#/" }, "Back to start"))));
}

async function loadRecord(id) {
  if (cache.has(id)) return cache.get(id);
  const body = await api.get(id);
  if (body.status.stage === "done") cache.set(id, body.record);
  return body.record || body;
}

async function showInvestigation(id, tab, detId, query, token) {
  mount(app, h("div", { class: "col stack" }, h("div", { class: "skeleton" }), h("div", { class: "skeleton" })));
  const record = await loadRecord(id);
  if (token !== seq) return;
  if (!record.investigation) {
    const stage = record.status && record.status.stage;
    topbar(null);
    return mount(
      app,
      h(
        "div",
        { class: "col stack" },
        h("h1", {}, stage === "failed" ? "This investigation did not finish" : "This investigation is not ready"),
        h("p", { class: "muted" }, stage === "failed" ? (record.status.detail || "No reason was recorded.") : `Current state: ${stage}.`),
        h("a", { class: "btn", href: "#/" }, "Back to start"),
      ),
    );
  }
  const mode = tab ? "investigator" : "summary";
  if (tab) lastTab = tab;
  topbar(record, mode);
  document.title = `Case ${record.id.slice(0, 6)} - ReHub`;
  const ctx = { id: record.id, record };
  mount(app, mode === "summary" ? renderSummary(record) : renderInvestigator(record, tab, detId, query, ctx));
}

async function route() {
  const token = ++seq;
  const hash = location.hash.slice(1) || "/";
  const [path, qs] = hash.split("?");
  const parts = path.split("/").filter(Boolean);
  document.title = "ReHub";
  try {
    if (!parts.length) {
      topbar(null);
      renderHome(app, navigate);
    } else if (parts[0] === "i" && /^[0-9a-f]{12}$/.test(parts[1] || "")) {
      await showInvestigation(parts[1], parts[2], parts[3], new URLSearchParams(qs || ""), token);
    } else {
      topbar(null);
      failure(new Error("That page does not exist."));
    }
  } catch (err) {
    if (token === seq) {
      topbar(null);
      failure(err);
    }
  }
  if (token === seq) {
    window.scrollTo(0, 0);
    app.focus({ preventScroll: true });
  }
}

window.addEventListener("hashchange", route);
route();
