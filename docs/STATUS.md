# Status and decisions

Handoff notes so work can resume on any machine.

## Goal

Black Hat Arsenal tool: drop in OT evidence, get an investigation (assets, communication, detections, evidence, report), fully local. Arsenal Asia 2027 call closes 2026-11-02, notification 2026-12-01 (verified on the official Call for Tools page; closes 23:59 Singapore time; Arsenal days 2027-03-02 and 03-03, Singapore). Submission kit: `docs/ARSENAL.md`. Arsenal needs open source, no sales pitch, 3+ pages of docs, a demo that works without real hardware.

## Why this is different

- Malcolm is a heavy SOC platform. Zui is a query explorer that already correlates Zeek and Suricata (uid, Community ID). Zeek plus Suricata correlation alone is not the pitch.
- ReHub's pitch: network evidence joined to PLC logic, an answer instead of a query, evidence integrity (hashes, tool attribution, deterministic output), light local install.

## Built

Evidence sniffer and safe ingest, tool runners and image, Zeek/Suricata/tshark adapters, Community ID, correlator, PLC adapter and register linker, investigation pipeline (`rehub analyze`, `rehub show`) with JSON persistence. Full test suite passes (`uv run pytest`), including an end to end run in a no-network, read-only, cap-dropped container.

## Decisions

- Python 3.13 and uv. Engine and tools share one image; tools run as subprocesses, no Docker socket.
- Own Community ID v1 implementation, verified against Zeek and Suricata output.
- Findings merge across tools by flow plus Modbus transaction id, or a 1 second window for S7.
- MACs: ARP is authoritative. MACs seen on routed traffic are never attributed to hosts (gateway heuristic).
- No IEEE OUI database committed (redistribution terms unclear). Small embedded ICS vendor table plus optional `REHUB_OUI` CSV.
- ATT&CK for ICS: only T0855, T0836, T0858 are mapped, reported as candidates. Authorization context is not visible in a capture.
- PLC: ST, PLCopen XML, L5X static analysis only. Binary project files (`.ACD`, `.zap16`) are hashed and stored. Modbus wire address N is assumed to be `%MW N`; this is shown as an assumption wherever used.
- Emerging Threats Open rules are not bundled yet. Sources disagree on license wording (BSD, MIT, old GPL sids). Check the current LICENSE file before bundling.

## Next, in order

1. (done) pipeline runner, API, UI (`rehub serve`). Design context lives in `PRODUCT.md` and `DESIGN.md`; the surface brief and direction contract are in `.impeccable/surfaces/`.
2. (done) Report: Report tab, print to PDF, and a standalone no-script HTML download with hashes, caveats and the ATT&CK note, built in the browser from the same logic as the Summary.
5. (done, CI verified) `compose.yml` (engine on an internal-only network, gateway publishing 127.0.0.1, read-only, cap_drop ALL, limits), `scripts/install.sh`, `.github/workflows/ci.yml` (tests, then multi-arch image build on native runners and a merged GHCR manifest). The workflow has run: tests pass, both amd64 and arm64 images build on native runners (about 8 to 10 minutes each, no cache), and the publish job merged them into one multi-arch index at `ghcr.io/ani07-05/rehub-engine:latest` (digest in the run log). The repository is now public. The package was created private and GitHub has no API to change a package's visibility, so it must be flipped in the UI (https://github.com/users/Ani07-05/packages/container/rehub-engine/settings, "Change visibility"); until then anonymous pulls get a 401 and the one-line install cannot work. The PR-only `stack` job (install and isolation check) has not run yet. Actions are on major versions and trigger a Node 20 deprecation notice; pin to commit SHAs and update before release. The GHA build cache is disabled (its backend errored); add a registry cache later to cut build time.
6. Emerging Threats rules bundle after the license check.
7. (partly done) Real-capture testing: `scripts/real-pcap-smoke.sh` downloads five small public ICS captures (Modbus, S7, DNP3) and runs them through the image. It found and fixed Modbus transaction-id reuse merging distinct commands. Still to do: a large capture (tens of MB or more) for time and memory.
8. Docs, demo script.

## Security model of the web UI

Loopback bind by default, Host allowlist (DNS rebinding), `X-Rehub` header and Origin check on every mutation. Sign-in is OPT-IN (the user chose no token for a local tool): `REHUB_TOKEN`, `REHUB_AUTH=1` or `rehub serve --auth` turn on a per-install token (`<data>/.token`, mode 0600) exchanged for an HttpOnly SameSite=Strict cookie then redirected, Bearer header for scripts, 5 failures per minute lockout. `rehub token [--rotate]` prints the sign-in link. With sign-in off, any local process that can reach the port can use ReHub, so the installer must publish the port on 127.0.0.1 only. `/api/health` is always public.

## Landing page

`site/index.html` (built to the `.impeccable/surfaces/site-index-html.md` contract: incident briefing structure, v1's trust sections). `scripts/install.sh` is now one self-contained file (compose embedded by `scripts/embed-compose.py`; a test keeps it equal to `compose.yml`). The repository and the image package are public and the one-line install was verified end to end (clean home, piped from raw GitHub, real GHCR image, doctor ok, demo analysis ok, clean uninstall); the pre-release notes are gone from the page. The site is already deployed as Vercel project `rehub-engine` at https://rehub-engine.vercel.app (separate from the v1 project `rehub` at rehub-rose.vercel.app, which was left untouched); it is CLI-deployed, not connected to Git. Screenshots are real UI captures of the synthetic demo case (`site/img/PROVENANCE.md`).

## Known limits

- `correlate` holds all events in memory; very large captures will hurt.
- Assets are keyed by IP; DHCP churn and multi-IP devices are not merged.
- Nested archives are stored as unknown.
- The pinned Debian `tshark` version in the Dockerfile will eventually disappear from the mirror (affects image builds only).
- Graphical PLC bodies (LD, FBD) are not analyzed.

## Workflow notes

- Rebuild the image after changing `src/`, then run `./scripts/regen-fixtures.sh` if tool output changes. Stale images silently produce old fixtures.
- Conventional Commits, subject 50 chars or less, no em dashes.
