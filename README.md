# ReHub

Drop in OT evidence, get an investigation you can explain. ReHub runs Zeek, Suricata and tshark on a capture, joins their output with your PLC logic, and answers in plain language first, with the proof one click away. It runs on your own machine and never sends anything out.

```
PCAP / OT evidence
        |
  Zeek      Suricata      tshark
  (protocol (rule         (packet
   actions)  alerts)       details)
        |
  ReHub engine: normalize, link evidence, keep tool attribution
        |
  Assets > Communication > Detections > Evidence > Report
```

Status: work in progress, aimed at Black Hat Arsenal. Engine, CLI, web UI, report, installer and tests work. The CI workflow and the published image have not run yet (see `docs/STATUS.md`).

## What you get

- **A plain-language answer.** For the demo case: `10.0.0.66 (unidentified device) sent a PLC stop command to 10.0.0.30 (Siemens AG controller) and 2 register write commands to 10.0.0.20 ... Two independent tools agree on all of them.`
- **Two reading modes.** Summary for the story, Investigator for the detail, on the same facts. A light and a dark theme.
- **One flow.** Assets, Communication, Detections, Evidence, Report, each with the question it answers and what the engine did.
- **Tool lanes.** Every detection shows which tools saw it (Zeek, Suricata, tshark, PLC logic), so agreement between independent tools is visible.
- **Network joined to PLC logic.** A Modbus register write is traced to the PLC variable it overlaps, the logic that reads it and the outputs it drives. The address mapping is shown as an assumption.
- **Honest limits.** Missing tools, capture loss, ambiguous hardware addresses and unparsed files are listed under "What we could not verify". ATT&CK for ICS techniques are candidates, never verdicts.
- **Evidence you can defend.** Every file is fingerprinted (SHA-256), tool output names the capture it came from, and each detection links to the file, line and packets behind it. The report prints or downloads as one offline HTML file with no scripts.

Inputs: pcap and pcapng, Zeek logs, Suricata `eve.json`, PLC Structured Text, PLCopen XML and Rockwell L5X, or a zip/tar of these. Other files are stored and listed as not analyzed.

## Install

Needs Docker (Desktop or Engine) with Compose v2.

```sh
./scripts/install.sh --local      # from a checkout: builds the image
./scripts/install.sh              # pulls the published image
```

Once the repository is public: `curl -fsSL https://raw.githubusercontent.com/Ani07-05/rehub-engine/main/scripts/install.sh | sh`. The script is short; read it first.

It starts two containers from `compose.yml`:

- **engine**: parses the evidence on a network with no route out (it cannot reach the internet or resolve names), read-only root, all capabilities dropped, no-new-privileges, memory and process limits. It publishes no ports.
- **gateway**: a ~50 line TCP forwarder that publishes the UI on `127.0.0.1` only.

Then it runs the doctor, prints the address and opens it. Also: `install.sh --update`, `--status`, `--uninstall [--purge]`, `--port N`, `--auth`.

## Use it

Open http://localhost:8080. A REHUB screen checks Storage, Zeek, Suricata and tshark (including a self-test on a built-in capture), then you press Enter. On the start page, drop evidence or press **Try the demo** for a built-in pump station case with a rogue device.

Sign-in is off by default because ReHub is local only. `install.sh --auth`, `REHUB_TOKEN` or `rehub serve --auth` turn on an access token (a sign-in link is printed; the token becomes an HttpOnly cookie).

From a terminal, with the tools available (they are inside the image):

```sh
docker run --rm --network none --read-only --tmpfs /tmp --user "$(id -u):$(id -g)" \
  -v "$PWD/fixtures:/in:ro" -v "$PWD/data:/data" rehub:dev \
  rehub --data /data analyze /in/ot-demo.pcap /in/plc/pump.st --plc-ip pump.st=10.0.0.20
```

Commands: `analyze`, `show <id>`, `doctor [--quick]`, `serve [--auth]`, `token [--rotate]`, `gateway`.

## Security model

Loopback bind, a Host allowlist against DNS rebinding, an `X-Rehub` header plus Origin check on every change, evidence only ever served as a download, every file-derived string set as text (never HTML), a strict CSP with no inline script or style, upload size caps and sanitized names, zip/tar/gzip bomb limits, XML DTD and entity rejection for PLC files. See `docs/STATUS.md` for the full list and the known limits.

## Develop

```sh
uv sync
uv run pytest                 # unit, API, UI logic (needs node), and container tests if the image exists
uv run ruff check . && uv run ruff format --check . && uv run mypy
docker build -f docker/Dockerfile -t rehub:dev .
./scripts/regen-fixtures.sh   # after changing tool output or the demo capture
./scripts/real-pcap-smoke.sh  # downloads five small public ICS captures and runs them
```

```
src/rehub/
  sniff.py ingest.py     identify evidence by content, store it by hash, unpack bundles safely
  tools.py doctor.py     Zeek / Suricata / tshark runners and the self-test
  adapters/              tool output to one Event schema
  communityid.py         Community ID v1 (verified against Zeek and Suricata)
  correlate.py model.py  assets, flows, detections, corroboration, ATT&CK candidates
  plc/                   PLC project parsing, static analysis, register-to-variable linking
  pipeline.py cli.py     upload to investigation, persistence, CLI
  api.py auth.py drill.py local HTTP API, optional token, evidence drill-down
  gateway.py             tiny TCP forwarder used by the compose stack
  ui/                    web UI: plain HTML, CSS and JS, no build step
docker/ compose.yml      tool image and hardened stack
fixtures/                synthetic OT capture, real tool output, PLC projects
PRODUCT.md DESIGN.md     product context and design system
```

## Tools it wraps

Zeek 8.0.10 with the CISA ICSNPP S7comm and EtherNet/IP plugins, Suricata 8.0.7, tshark 4.4.19. ReHub wraps them and does not replace them.

## License

MIT
