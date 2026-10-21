import { h, mount } from "../dom.js";
import { api } from "../api.js";
import { mark } from "../marks.js";
import { themeButton } from "../theme.js";
import { chainStatus, serviceChain } from "../narrate.js";

const STAGGER_MS = 260;
let lastChain = null;

export function lastProblems() {
  return lastChain && chainStatus(lastChain) !== "ok" ? lastChain.filter((n) => n.status !== "ok") : [];
}

function node(def) {
  const el = h("li", { class: "svc", "data-state": "checking", role: "listitem" },
    h("span", { class: "svc-mark" }, mark("checking")),
    h("span", { class: "svc-name" }, def.label),
    h("span", { class: "svc-sub" }, "Checking"),
  );
  return el;
}

function settle(el, result) {
  el.dataset.state = result.status;
  mount(el.querySelector(".svc-mark"), mark(result.status));
  el.querySelector(".svc-sub").textContent = result.sub;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function renderSplash(root, enter) {
  const placeholders = [{ label: "Storage" }, { label: "Zeek" }, { label: "Suricata" }, { label: "tshark" }];
  const nodes = placeholders.map(node);
  const button = h("button", { class: "btn primary enter", type: "button", disabled: true, onclick: enter }, "Enter");
  const items = [];
  nodes.forEach((n, i) => {
    items.push(n);
    items.push(h("li", { class: "svc-link", "aria-hidden": "true" }));
  });
  items.push(h("li", { class: "svc-enter" }, button));
  const problems = h("div", { class: "stack", "aria-live": "polite" });
  const again = h("button", { class: "btn small ghost", type: "button", hidden: true }, "Check again");
  const chain = h("ol", { class: "chain", "aria-label": "Service checks" }, items);

  const run = async () => {
    button.disabled = true;
    button.textContent = "Enter";
    again.hidden = true;
    mount(problems);
    nodes.forEach((n) => { n.dataset.state = "checking"; mount(n.querySelector(".svc-mark"), mark("checking")); n.querySelector(".svc-sub").textContent = "Checking"; });
    chain.querySelectorAll(".svc-link").forEach((l) => l.classList.remove("on"));
    let result;
    try {
      result = serviceChain((await api.doctor(true)).checks);
    } catch (err) {
      result = serviceChain([]).map((r) => ({ ...r, sub: "No answer", problems: [{ label: "ReHub", detail: err.message, fix: "Restart ReHub and reload this page." }] }));
    }
    lastChain = result;
    const links = [...chain.querySelectorAll(".svc-link")];
    for (let i = 0; i < nodes.length; i++) {
      await sleep(matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : STAGGER_MS);
      settle(nodes[i], result[i]);
      if (result[i].status === "ok") links[i].classList.add("on");
    }
    const status = chainStatus(result);
    button.disabled = false;
    button.textContent = status === "fail" ? "Enter anyway" : "Enter";
    button.focus({ preventScroll: true });
    const bad = result.filter((r) => r.status !== "ok");
    if (bad.length) {
      mount(problems, bad.map((r) => h("div", { class: "callout" }, h("b", {}, `${r.label}: `), r.problems.map((p) => `${p.detail}${p.fix ? " " + p.fix : ""}`).join(" "))));
      again.hidden = false;
    }
  };
  again.addEventListener("click", run);
  mount(root, h("div", { class: "splash" }, h("div", { class: "splash-tools" }, themeButton()), h("h1", { class: "wordmark" }, "REHUB"), chain, problems, h("p", {}, again)));
  run();
}
