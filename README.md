# ReHub

Local, offline investigation engine for OT network evidence. One upload runs Zeek, Suricata and tshark, correlates their output with PLC logic files, and keeps tool attribution on every finding.

Status: work in progress. Engine, CLI, API, web UI and report export work; the installer is not built yet. See `docs/STATUS.md`.

## What it does today

- Identifies evidence by content (pcap, Zeek logs, Suricata `eve.json`, tshark exports, PLC ST / PLCopen XML / L5X, syslog, CSV) and stores it by SHA-256, safely unpacking zip, tar and gzip bundles.
- Runs Zeek (with CISA ICSNPP plugins), Suricata and tshark inside one container.
- Correlates all three by Community ID: assets, flows, detections, with corroboration across tools.
- Maps Modbus register writes to the PLC variables they hit, the logic that reads them and the outputs they drive.
- Flags capture gaps and missing tools instead of treating silence as clean.

## Try it

With the tool image built (`docker build -f docker/Dockerfile -t rehub:dev .`):

```sh
docker run --rm --network none --read-only --tmpfs /tmp --user "$(id -u):$(id -g)" \
  -v "$PWD/fixtures:/in:ro" -v "$PWD/data:/data" rehub:dev \
  rehub --data /data analyze /in/ot-demo.pcap /in/plc/pump.st --plc-ip pump.st=10.0.0.20
```

Or run the web UI (open http://localhost:8080):

```sh
docker run --rm -p 127.0.0.1:8080:8080 -e REHUB_HOST=0.0.0.0 --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
  -v "$PWD/data:/data" rehub:dev rehub --data /data serve
```

## Develop

```sh
uv sync
uv run pytest
uv run ruff check . && uv run mypy
```

Tool container and integration tests (needs Docker):

```sh
docker build -f docker/Dockerfile -t rehub:dev .
uv run pytest tests/test_tools_docker.py
./scripts/regen-fixtures.sh   # rebuild fixtures from the image
```

## Layout

```
src/rehub/
  sniff.py ingest.py     evidence identification and safe storage
  tools.py               zeek / suricata / tshark runners
  adapters/              tool output to common Event schema
  communityid.py         Community ID v1
  pipeline.py cli.py     upload to investigation, persistence, CLI
  api.py drill.py        local HTTP API and evidence drill-down
  ui/                    web UI, plain HTML/CSS/JS, no build step
  correlate.py model.py  assets, flows, detections
  plc/                   PLC project parsing, analysis, register linking
docker/                  tool image
fixtures/                synthetic OT pcap, real tool output, PLC projects
```

## License

MIT
