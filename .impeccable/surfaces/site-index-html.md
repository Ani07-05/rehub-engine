---
version: 1
slug: "site-index-html"
primary_target: "site/index.html"
related_targets: []
---

# Surface: ReHub landing page

Scope: one static public page for the ReHub engine, with the install command. Visitor mode: Persuade. Audience: OT incident responders, security researchers and Black Hat Arsenal reviewers who read an installer before they pipe it to a shell.

Audience, job, action: decide in under a minute whether this is real, then copy the install command (or the from-source commands) with confidence about what it does. Proof: real product screenshots, the real answer ReHub wrote for the built-in demo case, the isolation facts that were actually verified, pinned tool versions, honest platform status. Constraints: no invented customers, benchmarks or awards; the demo data is synthetic and labelled; the one-line install works only after the repo is public and the image is published, and the page says so; static HTML, CSS and JS with a strict CSP and no third-party requests; dark default with a light theme; works without JavaScript apart from the copy button and the origin-aware command.

Chosen structure: incident briefing (dealt candidate 2 of 7), answer first, with v1's trust sections lower. Memorable moment: the page opens by showing what ReHub concluded about a real case, in plain sentences, above the install command.

Unresolved: the production domain and when the image is published. The command defaults to the raw GitHub URL and upgrades to the page's own origin when served over http(s).

## Direction contract

THESIS: Show the answer before the pitch. Earns trust by opening on ReHub's own conclusion about a case, with real screenshots, and by being as open about the installer as about the product. Refuses the dev-tool landing page of hero slogan, feature icon grid and logo wall.
OWN-WORLD: The product's world unchanged: black ground by default, white as the accent, hairline outlines carrying all structure, 12px panels, system sans, monospace only for commands and data, a huge REHUB wordmark, severity never by colour alone, a light theme one click away. Screenshots sit in outlined frames; the flow diagram is the product's own.
STORY: The visitor reads what happened in the demo case, sees how two independent tools and the PLC logic back it up, learns the evidence is local and fingerprinted, then gets a command they can read first, run, and undo.
FIRST VIEWPORT: Left-aligned REHUB wordmark at display scale, one sentence of what it does, then the briefing (the demo answer in three short paragraphs) beside or above a real Summary screenshot, with the install box immediately below: tabs for One line and From source, a copy button, and a plain pre-release note. A small theme toggle and a GitHub link sit top right.
FORM: Incident briefing structure, user-chosen with the recommendation to borrow v1's trust sections; seed key fb5f319e, candidate 2 of 7.
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
