import { h, s } from "../dom.js";

const W = 760;
const ROW = 62;
const NODE_W = 250;
const NODE_H = 44;
const RANK = { high: 3, medium: 2, low: 1 };

function trim(text, n) {
  return text.length > n ? `${text.slice(0, n - 1)}...` : text;
}

function side(asset) {
  return asset.kind === "controller" ? "right" : "left";
}

export function flowMap(record, onSelect) {
  const inv = record.investigation;
  const assets = Object.values(inv.assets);
  const lefts = assets.filter((a) => side(a) === "left");
  const rights = assets.filter((a) => side(a) === "right");
  const rows = Math.max(lefts.length, rights.length, 1);
  const height = rows * ROW + 24;
  const pos = new Map();
  lefts.forEach((a, i) => pos.set(a.id, { x: 0, y: 12 + i * ROW, side: "left" }));
  rights.forEach((a, i) => pos.set(a.id, { x: W - NODE_W, y: 12 + i * ROW, side: "right" }));

  const worst = new Map();
  for (const d of inv.detections) {
    if (!d.flow_key) continue;
    const prev = worst.get(d.flow_key);
    if (!prev || (RANK[d.severity] || 0) > (RANK[prev] || 0)) worst.set(d.flow_key, d.severity);
  }

  const edges = [];
  const groups = new Map();
  for (const f of Object.values(inv.flows)) {
    const key = `${f.src}|${f.dst}|${f.service || f.proto}`;
    const g = groups.get(key) || { src: f.src, dst: f.dst, label: f.service || f.proto || "", flows: [], sev: null };
    g.flows.push(f);
    const sev = worst.get(f.key);
    if (sev && (RANK[sev] || 0) > (RANK[g.sev] || 0)) g.sev = sev;
    groups.set(key, g);
  }
  for (const g of groups.values()) {
    const a = pos.get(g.src);
    const b = pos.get(g.dst);
    if (!a || !b) continue;
    const x1 = a.side === "left" ? a.x + NODE_W : a.x;
    const x2 = b.side === "left" ? b.x + NODE_W : b.x;
    const y1 = a.y + NODE_H / 2;
    const y2 = b.y + NODE_H / 2;
    const mid = (x1 + x2) / 2;
    const path = s("path", {
      class: `edge${g.sev ? ` flag ${g.sev}` : ""}`,
      d: `M${x1} ${y1}C${mid} ${y1} ${mid} ${y2} ${x2} ${y2}`,
    });
    const label = s("text", { class: "label", x: mid, y: (y1 + y2) / 2 + 4, "text-anchor": "middle" }, g.label);
    edges.push({ path, label, g });
  }

  const nodes = assets.map((a) => {
    const p = pos.get(a.id);
    const vendor = a.vendor ? a.vendor.split(" (")[0] : a.locally_administered_mac ? "unidentified device" : a.kind;
    const node = s(
      "g",
      { class: "node", transform: `translate(${p.x} ${p.y})`, tabindex: 0, role: "button", "aria-label": `${a.id}, ${vendor}. Show its detections.` },
      s("rect", { width: NODE_W, height: NODE_H, rx: 10 }),
      s("text", { x: 14, y: 19 }, a.id),
      s("text", { class: "sub", x: 14, y: 35 }, trim(`${vendor}${a.kind === "controller" ? " controller" : ""}`, 40)),
    );
    const choose = () => onSelect(a.id);
    node.addEventListener("click", choose);
    node.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), choose()));
    node.addEventListener("pointerenter", () => edges.forEach((e) => e.path.classList.toggle("dim", e.g.src !== a.id && e.g.dst !== a.id)));
    node.addEventListener("pointerleave", () => edges.forEach((e) => e.path.classList.remove("dim")));
    return node;
  });

  const svg = s(
    "svg",
    { class: "map", viewBox: `0 0 ${W} ${height}`, role: "group", "aria-label": "Who talks to whom. Clients on the left, controllers on the right. Dashed colored lines carry detections." },
    edges.map((e) => e.path),
    nodes,
    edges.map((e) => e.label),
  );
  return h(
    "div",
    { class: "stack" },
    h("div", { class: "panel pad" }, svg),
    h("p", { class: "small muted" }, "Clients are on the left and controllers on the right. A dashed colored line means a detection was raised on that conversation; select an asset to see its detections."),
  );
}
