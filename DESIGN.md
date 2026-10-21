---
name: ReHub
description: A thin-outline investigation surface, black by default with a light theme, that answers in plain language first and opens every claim down to its evidence.
colors:
  ground: "#000000"
  text: "#f4f4f4"
  text-secondary: "#c4c4c4"
  text-tertiary: "#9a9a9a"
  line: "rgba(255, 255, 255, 0.18)"
  line-strong: "rgba(255, 255, 255, 0.36)"
  line-soft: "rgba(255, 255, 255, 0.09)"
  severity-high: "#ff6b5e"
  severity-medium: "#f2b24a"
  severity-low: "#9aa3ad"
  hover: "rgba(255, 255, 255, 0.05)"
  selected-tint: "rgba(255, 255, 255, 0.1)"
  scrollbar-thumb: "#3a3a3a"
  paper-ground: "#ffffff"
  paper-text: "#111111"
  paper-text-secondary: "#444444"
  paper-text-tertiary: "#666666"
  paper-line: "rgba(0, 0, 0, 0.18)"
  paper-line-strong: "rgba(0, 0, 0, 0.42)"
  paper-line-soft: "rgba(0, 0, 0, 0.09)"
  paper-hover: "rgba(0, 0, 0, 0.04)"
  paper-selected-tint: "rgba(0, 0, 0, 0.07)"
  paper-scrollbar-thumb: "#c6c6c6"
  paper-severity-high: "#b3261e"
  paper-severity-medium: "#8a5a00"
  paper-severity-low: "#4a5560"
typography:
  headline:
    fontFamily: "system-ui, -apple-system, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "2rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  answer:
    fontFamily: "system-ui, -apple-system, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 500
    lineHeight: 1.45
    letterSpacing: "-0.01em"
  wordmark:
    fontFamily: "system-ui, -apple-system, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "clamp(4.5rem, 17vw, 12rem)"
    fontWeight: 700
    lineHeight: 0.9
    letterSpacing: "-0.04em"
  title:
    fontFamily: "system-ui, -apple-system, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "1.1875rem"
    fontWeight: 650
    lineHeight: 1.3
  body:
    fontFamily: "system-ui, -apple-system, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "system-ui, -apple-system, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 500
    lineHeight: 1.4
  map-label:
    fontFamily: "system-ui, -apple-system, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: "10.5px"
    fontWeight: 400
    lineHeight: 1.2
  data:
    fontFamily: "ui-monospace, SF Mono, Menlo, Consolas, monospace"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.55
rounded:
  hairline: "2px"
  focus: "4px"
  chip: "6px"
  control: "8px"
  panel: "12px"
  lane: "10px"
  drop: "16px"
spacing:
  xs: "0.35rem"
  sm: "0.6rem"
  md: "1rem"
  lg: "1.25rem"
  section: "2.25rem"
components:
  button-primary:
    backgroundColor: "{colors.text}"
    textColor: "{colors.ground}"
    rounded: "{rounded.control}"
    padding: "0.5rem 1rem"
  button-secondary:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "0.5rem 1rem"
  panel:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.text}"
    rounded: "{rounded.panel}"
    padding: "1.1rem 1.25rem"
  lane-lit:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.text}"
    rounded: "{rounded.lane}"
    padding: "0.65rem 0.75rem"
  lane-dim:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.text-tertiary}"
    rounded: "{rounded.lane}"
    padding: "0.65rem 0.75rem"
---

# Design System: ReHub

## Overview

**Creative North Star: "The Evidence Chain."** One investigation, two depths. The summary answers in sentences; the investigator opens the same facts as evidence. Nothing is decoration: every outline, lane and label says where a claim came from and how sure the tool is.

The world is the user's own flow diagram: a pure black ground, hairline outlines, white text, calm and quiet. Structure is carried by thin outlines rather than fills, shadows or tiles. The one memorable thing is the **tool lanes**: Zeek, Suricata, tshark and PLC drawn as outlined boxes that converge on the claim. A lit lane saw it; a dim dashed lane did not. Corroboration is geometry you read at a glance.

It refuses the SOC dashboard: no tiles of counters, no charts for their own sake, no neon-on-black glow.

**Key characteristics:**
- True black ground, outline-only structure, white as the only emphasis color.
- Colour appears only for state: severity, always paired with a drawn shape and a word.
- System sans for everything; monospace only for IPs, hashes, code and tabular numbers.
- Two reading modes on one set of facts: Summary (one 760px column) and Investigator (flow-nav with list and detail panes).

## Colors

A restrained, near-monochrome palette. Colour is a semantic signal, never decoration.

### Primary
- **Ink white** (`#f4f4f4`): all primary text, selected outlines, the primary button fill. White is the accent.

### Neutral
- **Ground black** (`#000000`): the page and every panel. Panels are distinguished by outline, not fill.
- **Secondary text** (`#c4c4c4`) and **tertiary text** (`#9a9a9a`): supporting copy and unlit states; both pass 4.5:1 on black.
- **Hairline** (`rgba(255,255,255,0.18)`), **strong hairline** (`0.36`), **soft hairline** (`0.09`): default outline, hover/selected outline, table row dividers.

### State
- **Severity high** (`#ff6b5e`) with a filled triangle, **medium** (`#f2b24a`) with a filled square, **low** (`#9aa3ad`) with a filled circle. Always shape plus word plus colour.

### Named Rules
**The State-Only Colour Rule.** Colour never decorates. If an element is coloured it is reporting severity. Everything else is white, grey or outline.

**The Outline-Is-Structure Rule.** No shadows, no tinted panels. A thin outline declares a region; a brighter outline declares selection.

## Typography

**Display / body / label:** system UI sans (`system-ui, -apple-system, Segoe UI, Helvetica Neue, Arial`). **Data:** `ui-monospace, SF Mono, Menlo, Consolas`.

A fixed rem scale (no fluid type) with a ~1.2 step: 0.8 / 0.875 / 1 / 1.1875 / 1.5 / 2rem on a 16px base, line-height 1.55. Body measure stays at or under 62ch.

### Hierarchy
- **Wordmark** (700, clamp 4.5 to 12rem, -0.04em): the opening screen only. The one fluid, oversized type in the system; nowhere else breaks the fixed scale.
- **Headline** (600, 2rem, -0.02em): page statements such as "What happened".
- **Answer** (500, 1.5rem, 1.5): the plain-language paragraphs. The largest text on screen, because the answer is the point.
- **Title** (650, 1.1875rem): section headings and finding titles.
- **Body** (400, 1rem): running text.
- **Label** (500, 0.875rem): table headers, meta lines, chips.
- **Map label** (400, 10.5px): node captions and edge labels inside the SVG flow map only.
- **Data** (mono, 0.875rem): IPs, hashes, code lines, packet fields; tabular numerals.

### Named Rules
**The Mono-Means-Data Rule.** Monospace is only for things a person might copy: addresses, hashes, variable names, code. Never as a "technical" costume on labels.

### Light theme (also print and the downloaded report)
Black is the default and the identity. A light theme is one click away (a sun and moon button in the top bar and on the opening screen) and is remembered in the browser; it never follows the system setting on its own. It is the same system on a white ground: ground `#ffffff`, text `#111111`, secondary `#444444`, tertiary `#666666`, hairlines as black at 18, 42 and 9 percent, and darker severity colours (`#b3261e`, `#8a5a00`, `#4a5560`) that keep 4.5:1 on white. The primary button inverts to black. Structure is still hairline outlines and severity is still shape plus word plus colour. Print and the standalone report download use this theme; the downloaded file has no scripts and a CSP that allows nothing but its own styles.

## Layout

- **Summary:** a single centered column, 760px, generous vertical rhythm (2.25rem between sections).
- **Investigator:** a wide container (up to 1240px). A flow-nav runs Devices, Communication, Findings, Evidence in the order of the product's own diagram, joined by drawn chevrons. Findings use a two-pane layout (list 280 to 400px, detail fills).
- **Responsive:** structural, not fluid. Under 820px the two panes stack and tool lanes become two columns; the lane connector is hidden. Tables scroll inside their own outlined wrapper; nothing scrolls the page sideways.
- **Alignment:** left-aligned text everywhere. Centering is reserved for the drop zone and the lane captions.

## Elevation & Depth

Flat. There are no shadows anywhere. Depth is expressed only by outline brightness (hover and selection step from hairline to strong hairline to white) and, for the one overlay-free interaction, by inline expansion rather than modals.

## Shapes

Rounded rectangles: **8px** controls, **10px** lanes and variable boxes, **12px** panels and rows, **6px** chips and the segmented control's inner buttons, **16px** the drop zone, **4px** focus rings, **2px** progress tracks. Pills are not used. Dashed outlines mean "not seen" (dim lanes) or "drop target"; solid means present.

## Components

### Buttons
- **Primary** (solid white, black text, 8px): the one main action per view, such as Analyze.
- **Secondary** (outline, white text): New investigation, Download, Show source line.
- **Ghost**: low-emphasis actions; gains an outline on hover. States: hover brightens the outline, focus is a 2px white ring offset 3px, disabled drops to 40% opacity.

### Segmented control
Summary / Investigator mode switch. The pressed segment inverts (white fill, black text).

### Tool lanes (signature)
Four outlined boxes in a row (Zeek "Protocol actions", Suricata "Rule alerts", tshark "Packet details", PLC "Program logic") with one connector line per lane converging on a claim box that carries the finding title. Lit lanes have a solid white outline and a filled dot; dim lanes are dashed and grey with a hollow dot. A compact one-line version appears on every list row. The connectors reveal once on open (reduced-motion safe).

### Finding rows and picks
Outlined 12px rows: severity shape and word, title, who-to-whom meta, compact lanes. Hover and selection brighten the outline; no fill.

### Tables
Outlined wrapper, hairline row dividers, sticky-free, horizontally scrollable inside the wrapper. Numbers use tabular figures.

### Code and evidence viewers
Gutter-and-line grid in monospace inside a hairline box; the referenced line gets a faint white tint. Evidence is only ever shown as escaped text or offered as a download.

### Opening screen (service chain)
A huge REHUB wordmark, then one line left to right: Storage, Zeek, Suricata, tshark, Enter. Each service is an outlined box with a drawn mark: dashed and pulsing while checking, a ring with a check when ready, a square (needs attention) or triangle (not working) with its word otherwise. Thin links between boxes fill white as each service passes. The real results arrive together and are revealed in order, 260ms apart. Enter is the last node and the focused default; if anything fails it reads "Enter anyway" and the reasons appear below. Reduced motion shows all results at once.

### Engine diagram and flow list
Your flow diagram drawn live: PCAP / OT evidence, then Zeek (protocol actions), Suricata (rule alerts) and tshark (packet details), then the ReHub engine, then five stage boxes: Assets, Communication, Detections, Evidence, Report. Boxes are dashed when waiting, solid with a pulsing ring while working, solid with a check when done, and red with a triangle when failed; the arrows between rows turn white as each row completes. On the Start page it is a static explanation; on the progress screen the tool states are real, read from the pipeline status. On the Summary the same five stages become a vertical flow list ("How ReHub got here"): each row gives the stage, its result in numbers, the plain question it answers, and one sentence on what the engine did, joined by a rail of ring nodes. In Investigator mode the stage names are the navigation, with a small count after each.

### Flow map
SVG, clients on the left and controllers on the right, curved hairline edges. A dashed coloured edge carries a finding. Nodes are keyboard focusable buttons.

## Do's and Don'ts

### Do
- **Do** state the answer in a plain sentence first, then show the proof one step away.
- **Do** pair every severity colour with its shape and a word.
- **Do** show what could not be verified as prominently as what was found.
- **Do** keep every interactive element a standard, keyboard-operable control.
- **Do** escape all file-derived text; build the DOM with text nodes only.

### Don't
- **Don't** add tiles of big numbers, sparklines, glows, gradients or shadows.
- **Don't** colour anything that is not reporting a state.
- **Don't** use a modal where inline expansion works.
- **Don't** put an eyebrow label above a heading or number sections that are not a sequence.
- **Don't** imply certainty the evidence does not support: ATT&CK mappings are candidates, and the Modbus address mapping is an assumption that must be stated.
