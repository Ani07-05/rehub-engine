---
version: 1
slug: "src-rehub-ui-index-html"
primary_target: "src/rehub/ui/index.html"
related_targets: []
---

# Surface: ReHub investigation UI

Scope: the whole local web UI (home/upload, run progress, investigation in two modes). Visitor mode: Operate.

Audience and job: a half-technical, half-non-technical person handed OT evidence after an incident. Job: learn what happened in plain words, then dig into proof on demand, and be able to defend it. Constraints: offline, strict CSP (no inline script or style, no external hosts), plain HTML/CSS/JS served by the Python server, all file-derived text escaped, evidence download-only, light-on-dark contrast, keyboard operable, severity never by colour alone.

Chosen direction (user-pinned, no concept roll): the black thin-outline world of the user's flow diagram. Memorable moment: tool lanes. Each finding shows Zeek, Suricata, tshark (and PLC when a project is linked) as outlined lanes that converge on the claim; lit lanes saw it, dim dashed lanes did not, so corroboration is geometry you read at a glance.

Unresolved: Report tab content arrives with the report export step. No real customer data exists; demo data is synthetic and labelled.

## Direction contract

THESIS: One investigation, two depths. The summary answers in sentences and the investigator opens the same facts as evidence. Refuses the SOC dashboard of tiles, charts and counters.
OWN-WORLD: Pure black ground, hairline outlines (1px, white at low alpha) carrying all structure, 12px radii on panels and 8px on controls, white text, one cool grey secondary tier. Colour only for state: high, medium and low severity each paired with a distinct shape and a word, corroboration in white. System sans for everything, monospace only for IPs, hashes, code and numbers in tabular alignment. Primary action is a solid white button.
STORY: The reader learns who did what to which device and process, how sure the tool is and why, what could not be verified, then can open any claim down to the file, line, packet and hash.
FIRST VIEWPORT: Top bar with wordmark left, investigation switcher, a Summary/Investigator segmented control and New investigation right. Below, one centered column roughly 760px: a plain-language paragraph answering what happened, then the key findings as outlined rows each carrying severity word, title, affected device and its tool lanes, then a plain list of what could not be verified. In Investigator mode the nav runs Devices, Communication, Findings, Evidence in the diagram's order joined by drawn chevrons, with a findings list left and the detail pane right.
FORM: Story column plus flow-nav investigator, from the user-confirmed structure option; user-pinned, no roll, no seed key.
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
