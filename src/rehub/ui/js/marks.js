import { s } from "./dom.js";

export function mark(state) {
  const ring = { cx: 10, cy: 10, r: 8.5, fill: "none", stroke: "currentColor", "stroke-width": 1.4 };
  const svg = (kids) => s("svg", { width: 20, height: 20, viewBox: "0 0 20 20", "aria-hidden": "true" }, kids);
  if (state === "ok" || state === "done") return svg([s("circle", ring), s("path", { d: "M6 10.4l2.8 2.8L14.2 7.4", fill: "none", stroke: "currentColor", "stroke-width": 1.6 })]);
  if (state === "warn") return svg([s("rect", { x: 2.5, y: 2.5, width: 15, height: 15, rx: 3, fill: "currentColor" })]);
  if (state === "fail" || state === "failed") return svg([s("path", { d: "M10 1.5l8.5 16h-17z", fill: "currentColor" })]);
  return svg([s("circle", ring)]);
}
