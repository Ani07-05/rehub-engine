import { h, mount, fmtBytes, plural, fmtTime } from "../dom.js";
import { api } from "../api.js";

const PLC_FILE = /\.(st|xml|l5x)$/i;
const IP_LIKE = /^[0-9a-f:.]{3,45}$/i;
const STEPS = [
  ["upload", "Uploading your files"],
  ["ingest", "Reading and fingerprinting the evidence"],
  ["analyze", "Running Zeek, Suricata and tshark"],
  ["correlate", "Joining the results"],
];

let chosen = [];

function stepList(active) {
  const idx = STEPS.findIndex(([id]) => id === active);
  return h(
    "ol",
    { class: "steps", "aria-label": "Progress" },
    STEPS.map(([id, label], i) =>
      h("li", { "data-state": i < idx ? "done" : i === idx ? "active" : "todo", "aria-current": i === idx ? "step" : null }, h("span", { class: "dot", "aria-hidden": "true" }), label),
    ),
  );
}

async function runAnalysis(root, navigate) {
  const files = chosen.slice();
  const plcIps = {};
  for (const f of files) if (f.ip) plcIps[f.file.name] = f.ip.trim();
  const track = h("div", { class: "bar-fill" });
  const status = h("div", { "aria-live": "polite" });
  const show = (active, extra) => mount(root, h("div", { class: "col stack-lg" }, h("h1", {}, "Analyzing"), stepList(active), h("div", { class: "bar-track" }, track), status, extra || null));
  show("upload");
  try {
    const { id } = await api.create();
    const total = files.reduce((n, f) => n + f.file.size, 0) || 1;
    let done = 0;
    for (const f of files) {
      status.textContent = `Uploading ${f.file.name}`;
      await api.upload(id, f.file, (frac) => {
        track.style.transform = `scaleX(${(done + frac * f.file.size) / total})`;
      });
      done += f.file.size;
    }
    track.style.transform = "scaleX(1)";
    status.textContent = "";
    await api.run(id, plcIps);
    chosen = [];
    for (;;) {
      const body = await api.get(id);
      const stage = body.status.stage;
      if (stage === "done") return navigate(`#/i/${id}`);
      if (stage === "failed") throw new Error(body.status.detail || "The analysis failed.");
      show(stage === "queued" ? "ingest" : stage);
      await new Promise((r) => setTimeout(r, 700));
    }
  } catch (err) {
    mount(
      root,
      h(
        "div",
        { class: "col stack" },
        h("h1", {}, "That did not finish"),
        h("div", { class: "callout err" }, err.message),
        h("p", {}, h("button", { class: "btn primary", type: "button", onclick: () => navigate("#/") }, "Back to start")),
      ),
    );
  }
}

function fileRows(list, rerender) {
  return h(
    "ul",
    { class: "filelist" },
    list.map((entry, i) => {
      const plc = PLC_FILE.test(entry.file.name);
      const ip = plc
        ? h("input", {
            class: "input mono",
            type: "text",
            placeholder: "Controller IP (optional)",
            "aria-label": `Controller IP for ${entry.file.name}`,
            value: entry.ip || "",
            oninput: (e) => {
              entry.ip = e.target.value;
              e.target.removeAttribute("aria-invalid");
            },
          })
        : h("span", { class: "faint small" }, fmtBytes(entry.file.size));
      return h(
        "li",
        {},
        h("span", { class: "name" }, entry.file.name, plc ? h("span", { class: "faint small" }, `  ${fmtBytes(entry.file.size)}`) : null),
        ip,
        h("button", { class: "btn small ghost", type: "button", "aria-label": `Remove ${entry.file.name}`, onclick: () => (chosen.splice(i, 1), rerender()) }, "Remove"),
      );
    }),
  );
}

function recentItem(item, reload) {
  let armed = false;
  const del = h("button", { class: "btn small ghost danger", type: "button" }, "Delete");
  del.addEventListener("click", async () => {
    if (!armed) {
      armed = true;
      del.textContent = "Confirm delete";
      setTimeout(() => ((armed = false), (del.textContent = "Delete")), 4000);
      return;
    }
    try {
      await api.remove(item.id);
      reload();
    } catch (err) {
      del.textContent = err.message;
    }
  });
  const done = item.stage === "done";
  const names = (item.names || []).join(", ") || "Investigation";
  const meta = done
    ? `${plural(item.detections, "finding")}, ${item.high} high, ${plural(item.assets, "device")}`
    : item.stage === "failed"
      ? "Did not finish"
      : item.stage;
  return h(
    "li",
    { class: "panel pad" },
    h("div", { class: "filters" }, h("a", { class: "title", href: `#/i/${item.id}` }, names), h("span", { class: "grow" }), del),
    h("p", { class: "small muted" }, `${meta}. ${item.created ? fmtTime(Date.parse(item.created) / 1000) : ""}`),
  );
}

export function renderHome(root, navigate) {
  const recent = h("div", { class: "stack" });
  const loadRecent = async () => {
    try {
      const { investigations } = await api.list();
      mount(
        recent,
        investigations.length
          ? [h("h2", {}, "Recent investigations"), h("ul", { class: "list" }, investigations.map((i) => recentItem(i, loadRecent)))]
          : null,
      );
    } catch (err) {
      mount(recent, h("div", { class: "callout err" }, err.message));
    }
  };
  const area = h("div", { class: "stack" });
  const input = h("input", { class: "sr", type: "file", multiple: true, id: "pick", "aria-label": "Choose evidence files" });
  const drop = h(
    "label",
    { class: "drop", for: "pick" },
    h("h1", {}, "Drop evidence here"),
    h("p", { class: "muted" }, "A packet capture, Zeek logs, Suricata alerts, PLC project files, or a zip of these."),
    h("p", { class: "small faint" }, "Everything is analyzed on this computer. Nothing is uploaded anywhere else."),
    h("span", { class: "btn" }, "Choose files"),
    input,
  );
  const draw = () => {
    const err = h("p", { class: "small", role: "alert" });
    const go = h("button", { class: "btn primary", type: "button", disabled: chosen.length === 0 }, chosen.length ? `Analyze ${plural(chosen.length, "file")}` : "Analyze");
    go.addEventListener("click", () => {
      const bad = chosen.find((f) => f.ip && !IP_LIKE.test(f.ip.trim()));
      if (bad) {
        err.textContent = `"${bad.ip}" is not an IP address. Leave it empty if you do not know it.`;
        return;
      }
      runAnalysis(root, navigate);
    });
    mount(area, chosen.length ? fileRows(chosen, draw) : null, chosen.length ? h("div", { class: "filters" }, go, err) : null);
  };
  const add = (files) => {
    for (const file of files) if (!chosen.some((c) => c.file.name === file.name)) chosen.push({ file, ip: "" });
    draw();
  };
  input.addEventListener("change", () => (add([...input.files]), (input.value = "")));
  for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => (e.preventDefault(), drop.classList.add("over")));
  for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, (e) => (e.preventDefault(), drop.classList.remove("over")));
  drop.addEventListener("drop", (e) => add([...e.dataTransfer.files]));
  mount(root, h("div", { class: "col stack-lg" }, drop, area, recent));
  draw();
  loadRecent();
}
