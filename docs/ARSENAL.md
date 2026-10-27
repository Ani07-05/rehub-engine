# Black Hat Asia 2027 Arsenal submission kit

Call for Tools: opened 2026-09-04, closes 2026-11-02, notification 2026-12-01 (verified on blackhat.com/html/arsenal-call-for-tools.html). Close time: 2026-11-02 23:59 Singapore time (UTC+8), which is 21:29 IST. Arsenal days: 2027-03-02 and 2027-03-03, Singapore (Black Hat Asia runs 2027-02-28 to 03-03). Contact: arsenal@blackhat.com.

Official terms: submitting means you agree to present both days (time shared on acceptance). Benefit: one complimentary Briefings/Business Hall pass. Travel and hotel are the presenter's cost. Form fields are behind the CFP login (https://asia-arsenal-cfp.blackhat.com/); the draft text below follows the usual fields.

Form rules (CFP page):
- Draft in a separate document first; the form times out.
- NO source code, code snippets, shell commands or HTML in any field. The content filter blocks them and the submit errors. Keep the install one-liner and any `curl | sh` out of the form; give the repo and docs URLs only.
- Content must be educational and community-focused, not promotional. Avoid superlatives and "product" wording.
- Repo link required; private link is accepted, public is fine.
- Optional plain-text "Upload File" for whitepaper or research.
- Up to four tools per person, one submission each. Submit only ReHub.
- Confirmation email from noreply@email.blackhat.com within 24h (check spam), else mail arsenal@blackhat.com.
- Tools at any stage are welcome if functional enough for an interactive demo.
- Demo is open and conversational, not a scripted talk: expect visitors to drop in and ask; the 5-minute loop below is for that.

## Rules that apply (Arsenal CFP pages, 2025 to 2026)

| Rule | Status |
| --- | --- |
| Open source, link to code | MIT, https://github.com/Ani07-05/rehub-engine, public |
| No sales pitch, demo limited to the submitted tool | Nothing sold; landing page has no pricing or contact-sales |
| 3+ pages English docs (description, install, usage) | `site/docs/`: overview, install, usage, reference, architecture. Live at https://rehub-engine.vercel.app/docs/ |
| Works before you apply, easy to run | One-line install verified from clean home |
| Present both days, own laptop | Confirm travel and availability before submitting |
| Recorded video if selected | Script below; record after acceptance, rehearse now |
| Demo without real hardware | Built-in pump station case plus `samples/` |

## Form text (draft, edit before pasting)

**Tool name:** ReHub

**One-line summary:** Local OT investigation tool: drop in a capture and PLC logic, get an explained answer instead of a query.

**Short description (about 100 words):**
ReHub runs Zeek, Suricata and tshark on an OT capture in one hardened, offline container, normalizes their output, and joins it with PLC logic (Structured Text, PLCopen XML, Rockwell L5X). It answers in plain language first: which device did what to which controller, which register write touched which PLC variable and the outputs it drives, and which independent tools agree. Every claim links to the file, line and packets behind it. Evidence is SHA-256 fingerprinted, limits are listed ("what we could not verify"), and ATT&CK for ICS techniques are candidates, never verdicts. Report exports as one offline HTML file.

**Detailed description / what is new:**
- Network x PLC-logic join: Modbus register writes traced to PLC variables, readers and outputs (address mapping shown as an assumption).
- Cross-tool corroboration by Community ID flow plus Modbus transaction id (own Community ID v1 implementation, verified against Zeek and Suricata).
- Evidence integrity: hashes, tool attribution, deterministic output, honest-limits section.
- Light local install: two containers, engine has no network route, UI on 127.0.0.1 only, no telemetry.
- Contrast: Malcolm is a full SOC platform; Zui is a query explorer. ReHub is answer-first and PLC-aware. It wraps Zeek, Suricata and tshark and does not replace them.

**Why Arsenal / audience:** OT incident responders, ICS red and blue teams, researchers triaging captures without lab hardware.

**Links:** code https://github.com/Ani07-05/rehub-engine, docs https://rehub-engine.vercel.app/docs/, site https://rehub-engine.vercel.app

**License:** MIT. **Platforms:** Docker with Compose v2 (amd64, arm64). Linux and Windows untested, macOS tested.

**Bio:** TODO (user writes; name, role, prior work, links).

**Demo needs:** own laptop, power, no network required after image pull.

## Demo script (5 minutes, booth loop)

1. (0:00) Pitch in one sentence: "Drop in an OT capture and PLC logic, get who did what to which controller, with proof."
2. (0:20) `curl -fsSL https://rehub-engine.vercel.app/install.sh | sh` already run; show doctor screen: Storage, Zeek, Suricata, tshark, self-test ok.
3. (0:50) Press **Try the demo** (pump station, rogue device 10.0.0.66).
4. (1:10) Read the Summary sentence: stop command to 10.0.0.30, 2 register writes to 10.0.0.20, two independent tools agree.
5. (1:50) Switch to Investigator: Assets (vendor by ARP, not guessed), Communication, Detections with tool lanes (Zeek, Suricata, tshark, PLC logic).
6. (2:40) Open a Modbus write: register, value, linked PLC variable, logic that reads it, outputs it drives. Point out the assumption badge.
7. (3:30) Evidence tab: SHA-256, file, line, packets. "What we could not verify" list.
8. (4:15) Report tab: download standalone HTML, open it offline.
9. (4:45) Drop `samples/` files to show other evidence types. Close: repo link, MIT, no data leaves the machine.

Backup if Docker fails on stage: pre-recorded video of the same run, and a pre-exported report HTML.

## Remaining before submit (due 2026-11-02)

1. Sign in at the CFP site and compare its form fields to the draft above (dates already verified).
2. Write bio; confirm both-day availability and that you can fund travel and hotel for Singapore, Arsenal on 2027-03-02 and 03-03.
3. README: point to this file and the docs URL (done).
4. Re-run the one-line install and doctor on a clean machine the day before.
5. Pin GitHub Actions to commit SHAs (repo visibly maintained).
6. Large-capture timing test, record tool versions in the investigation record (known gaps; mention in docs as limits if not done).
7. Rehearse demo; screen-record a backup video.
8. Submit at least a day early.
