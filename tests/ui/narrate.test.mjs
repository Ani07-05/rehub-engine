import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  caveatList, deviceText, headline, impactLine, lanes, networkFindings, parseRef, plainMeaning, severityWord, uploadedEvidence,
} from "../../src/rehub/ui/js/narrate.js";

const load = () => JSON.parse(readFileSync(process.env.REHUB_RECORD, "utf8"));
const byTitle = (record, title) => record.investigation.detections.find((d) => d.title === title);

test("headline states actor, actions, targets, confidence and PLC effect", () => {
  const [actors, confidence, impact] = headline(load());
  assert.match(actors, /^10\.0\.0\.66 \(unidentified device\) sent /);
  assert.match(actors, /a PLC stop command to 10\.0\.0\.30 \(Siemens AG controller\)/);
  assert.match(actors, /2 register write commands to 10\.0\.0\.20 \(Telemecanique Electrique controller, pump program\)/);
  assert.equal(confidence, "Two independent tools agree on all of them.");
  assert.equal(impact, "In the pump PLC program these writes change Setpoint, PumpSpeed and SpeedLimit, which feed ReliefValve and PumpRun.");
});

test("headline never claims safety when nothing was found", () => {
  const record = load();
  record.investigation.detections = [];
  const out = headline(record);
  assert.equal(out[0], "No risky commands were found in this capture.");
  assert.match(out[1], /does not prove the network was clean/);
  record.investigation.caveats = [];
  record.warnings = [];
  assert.equal(headline(record).length, 1);
});

test("single-tool findings are called unconfirmed", () => {
  const record = load();
  for (const d of record.investigation.detections) d.corroborated = false;
  assert.equal(headline(record)[1], "Only one tool reported this, so treat it as unconfirmed.");
  record.investigation.detections[0].corroborated = true;
  assert.match(headline(record)[1], /^Two independent tools agree on 1 of \d+\.$/);
});

test("static PLC findings are not described as network activity", () => {
  const record = load();
  const net = networkFindings(record);
  assert.ok(net.length > 0 && net.every((d) => !(d.tools.length === 1 && d.tools[0] === "plc")));
  const plc = record.investigation.detections.find((d) => d.tools.length === 1 && d.tools[0] === "plc");
  assert.match(plainMeaning(plc), /not something seen on the network/);
});

test("tool lanes reflect which tools actually saw the finding", () => {
  const record = load();
  const write = byTitle(record, "Modbus WRITE_SINGLE_REGISTER");
  assert.deepEqual(lanes(write, record).map((l) => [l.id, l.on]), [["zeek", true], ["suricata", true], ["tshark", true], ["plc", true]]);
  const plcOnly = record.investigation.detections.find((d) => d.title.startsWith("PLC logic:"));
  assert.deepEqual(lanes(plcOnly, record).filter((l) => l.on).map((l) => l.id), ["plc"]);
  record.plc = [];
  assert.equal(lanes(write, record).length, 3);
});

test("impact line names variables and what they drive", () => {
  const record = load();
  assert.equal(impactLine(byTitle(record, "Modbus WRITE_SINGLE_REGISTER")), "Changes Setpoint, which controls ReliefValve.");
  assert.equal(impactLine(byTitle(record, "S7comm PLC Stop")), "");
});

test("device text uses vendor only when known and flags unidentified hardware", () => {
  const inv = load().investigation;
  assert.equal(deviceText(inv, "10.0.0.30"), "10.0.0.30 (Siemens AG controller)");
  assert.equal(deviceText(inv, "172.16.0.5"), "172.16.0.5 (client)");
  assert.equal(deviceText(inv, null), "an unknown device");
});

test("caveats merge warnings and failed tool runs without duplicates", () => {
  const record = load();
  record.warnings = ["x.csv: csv is stored but not analyzed yet.", "x.csv: csv is stored but not analyzed yet."];
  record.tool_runs.push({ tool: "suricata", pcap: "a.pcap", ok: false, error: "boom", outputs: [], seconds: 0, pcap_sha256: "z" });
  const list = caveatList(record);
  assert.equal(list.filter((c) => c.startsWith("x.csv")).length, 1);
  assert.ok(list.includes("suricata failed on a.pcap: boom"));
});

test("evidence refs parse by kind", () => {
  assert.deepEqual(parseRef("zeek/conn.log:L3", "zeek"), { kind: "line", file: "zeek/conn.log", line: 3 });
  assert.deepEqual(parseRef("tshark/packets.tsv:frames 31-44", "tshark"), { kind: "frames", file: "tshark/packets.tsv", from: 31, to: 44 });
  assert.deepEqual(parseRef("pump.st:PumpControl:27", "plc"), { kind: "plc", file: "pump.st", where: "PumpControl:27" });
  assert.equal(parseRef("odd", "zeek").kind, "other");
});

test("uploaded evidence excludes tool-produced files", () => {
  const names = uploadedEvidence(load()).map((e) => e.name).sort();
  assert.deepEqual(names, ["ot-demo.pcap", "pump.st"]);
});

test("severity words", () => {
  assert.equal(severityWord("high"), "High");
  assert.equal(severityWord(null), "Info");
});

test("confidence wording distinguishes corroboration from static review hints", async () => {
  const { confidenceText, reportFileName } = await import("../../src/rehub/ui/js/narrate.js");
  const record = load();
  assert.match(confidenceText(byTitle(record, "Modbus WRITE_SINGLE_REGISTER")), /^Confirmed by two independent tools \(Suricata and Zeek\)\.$/);
  const plc = record.investigation.detections.find((d) => d.tools.length === 1 && d.tools[0] === "plc");
  assert.match(confidenceText(plc), /not a network observation/);
  const single = { tools: ["suricata"], corroborated: false };
  assert.match(confidenceText(single), /one tool only \(Suricata\); treat as unconfirmed/);
  assert.equal(reportFileName(record), `rehub-report-${record.id}.html`);
});

const okChecks = () => [
  { id: "data", label: "Data folder", status: "ok", detail: "/data is writable", fix: "" },
  { id: "disk", label: "Free disk space", status: "ok", detail: "777.4 GB free", fix: "" },
  { id: "zeek", label: "Zeek", status: "ok", detail: "version 8.0.10", fix: "" },
  { id: "zeek-ics", label: "Zeek industrial protocol plugins", status: "ok", detail: "S7comm and EtherNet/IP available", fix: "" },
  { id: "suricata", label: "Suricata", status: "ok", detail: "version 8.0.7", fix: "" },
  { id: "tshark", label: "tshark", status: "ok", detail: "version 4.4.19", fix: "" },
  { id: "selftest-zeek", label: "Zeek reads a sample capture", status: "ok", detail: "found the Modbus write", fix: "" },
  { id: "selftest-suricata", label: "Suricata raises an alert", status: "ok", detail: "rule fired", fix: "" },
  { id: "selftest-tshark", label: "tshark lists packets", status: "ok", detail: "listed", fix: "" },
];

test("service chain runs left to right and shows versions when healthy", async () => {
  const { serviceChain, chainStatus } = await import("../../src/rehub/ui/js/narrate.js");
  const chain = serviceChain(okChecks());
  assert.deepEqual(chain.map((n) => n.label), ["Storage", "Zeek", "Suricata", "tshark"]);
  assert.deepEqual(chain.map((n) => n.sub), ["777.4 GB free", "8.0.10", "8.0.7", "4.4.19"]);
  assert.equal(chainStatus(chain), "ok");
});

test("a failing self test marks only its service and keeps the reason", async () => {
  const { serviceChain, chainStatus } = await import("../../src/rehub/ui/js/narrate.js");
  const checks = okChecks();
  checks.find((c) => c.id === "selftest-suricata").status = "fail";
  checks.find((c) => c.id === "selftest-suricata").detail = "no alert fired";
  checks.find((c) => c.id === "zeek-ics").status = "warn";
  const chain = serviceChain(checks);
  assert.deepEqual(chain.map((n) => n.status), ["ok", "warn", "fail", "ok"]);
  assert.equal(chain[2].sub, "Not working");
  assert.equal(chain[2].problems[0].detail, "no alert fired");
  assert.equal(chain[1].sub, "Needs attention");
  assert.equal(chainStatus(chain), "fail");
});

test("missing results never look healthy", async () => {
  const { serviceChain } = await import("../../src/rehub/ui/js/narrate.js");
  const chain = serviceChain([]);
  assert.ok(chain.every((n) => n.status === "fail"));
});
