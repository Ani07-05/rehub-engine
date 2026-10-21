#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
out=$(mktemp -d)
uv run python fixtures/gen_ot_pcap.py fixtures/ot-demo.pcap
cp fixtures/ot-demo.pcap src/rehub/data/demo/ot-demo.pcap
cp fixtures/plc/pump.st src/rehub/data/demo/pump.st
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/fixtures:/in:ro" -v "$out:/out" rehub:dev python3 -c "
from pathlib import Path
from rehub import tools
p = Path('/in/ot-demo.pcap')
for fn, d in ((tools.run_zeek, 'zeek'), (tools.run_suricata, 'suricata'), (tools.run_tshark, 'tshark')):
    fn(p, Path('/out') / d)
"
rm -rf fixtures/ot-demo
mkdir -p fixtures/ot-demo/zeek fixtures/ot-demo/suricata fixtures/ot-demo/tshark
for f in conn cotp modbus modbus_detailed s7comm; do cp "$out/zeek/$f.log" fixtures/ot-demo/zeek/; done
cp "$out/suricata/eve.json" fixtures/ot-demo/suricata/
cp "$out/tshark/packets.tsv" fixtures/ot-demo/tshark/
rm -rf "$out"
