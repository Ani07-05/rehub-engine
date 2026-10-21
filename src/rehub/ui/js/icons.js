import { s } from "./dom.js";

export function brandMark() {
  return s(
    "svg",
    { width: 22, height: 22, viewBox: "0 0 22 22", fill: "none", stroke: "currentColor", "stroke-width": 1.2, "aria-hidden": "true" },
    s("rect", { x: 1, y: 1, width: 5, height: 5, rx: 1.5 }),
    s("rect", { x: 8.5, y: 1, width: 5, height: 5, rx: 1.5 }),
    s("rect", { x: 16, y: 1, width: 5, height: 5, rx: 1.5 }),
    s("path", { d: "M3.5 6v3.5L11 13m0 0l7.5-3.5V6M11 8.5V13" }),
    s("rect", { x: 5.5, y: 15.5, width: 11, height: 5, rx: 1.5 }),
  );
}

export function chevron() {
  return s(
    "svg",
    { width: 10, height: 14, viewBox: "0 0 10 14", fill: "none", stroke: "currentColor", "stroke-width": 1.2, "aria-hidden": "true" },
    s("path", { d: "M2 1l6 6-6 6" }),
  );
}

export function sevShape(severity) {
  const common = { width: 11, height: 11, viewBox: "0 0 11 11", fill: "currentColor", "aria-hidden": "true" };
  if (severity === "high") return s("svg", common, s("path", { d: "M5.5 .5l5.5 10H0z" }));
  if (severity === "medium") return s("svg", common, s("rect", { x: 1, y: 1, width: 9, height: 9, rx: 1.5 }));
  if (severity === "low") return s("svg", common, s("circle", { cx: 5.5, cy: 5.5, r: 4.5 }));
  return s("svg", { ...common, fill: "none", stroke: "currentColor", "stroke-width": 1.2 }, s("circle", { cx: 5.5, cy: 5.5, r: 4 }));
}
