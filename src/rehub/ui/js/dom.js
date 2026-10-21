const SVG_NS = "http://www.w3.org/2000/svg";

function append(el, kids) {
  for (const kid of kids) {
    if (kid == null || kid === false) continue;
    if (Array.isArray(kid)) append(el, kid);
    else el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
}

function apply(el, attrs) {
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value == null || value === false) continue;
    if (key === "class") el.setAttribute("class", value);
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, String(value));
  }
}

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  apply(el, attrs);
  append(el, kids);
  return el;
}

export function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  apply(el, attrs);
  append(el, kids);
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function mount(el, ...kids) {
  clear(el);
  append(el, kids);
}

export function fmtTime(ts) {
  if (ts == null) return "unknown time";
  const d = new Date(ts * 1000);
  return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many || one + "s"}`;
}

export function shortHash(sha) {
  return sha.slice(0, 12);
}
