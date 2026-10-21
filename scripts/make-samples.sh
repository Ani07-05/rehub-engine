#!/bin/sh
# Rebuilds samples/ . Needs docker, the rehub:dev image and uv.
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d); chmod 777 "$tmp"
run() { docker run --rm --network none --read-only --tmpfs /tmp --user "$(id -u):$(id -g)" -v "$PWD/fixtures:/in:ro" -v "$tmp:/out" -w /out "${REHUB_IMAGE:-rehub:dev}" "$@"; }
run zeek -C -r /in/ot-demo.pcap /opt/rehub/zeek/rehub.zeek "LogAscii::use_json=F"
mkdir -p samples/zeek-tsv samples/tshark
for f in conn cotp modbus modbus_detailed s7comm; do cp "$tmp/$f.log" "samples/zeek-tsv/$f.log"; done
docker run --rm --network none --read-only --tmpfs /tmp --user "$(id -u):$(id -g)" -v "$PWD/fixtures:/in:ro" "${REHUB_IMAGE:-rehub:dev}" tshark -r /in/ot-demo.pcap -T ek -c 10 > samples/tshark/packets.ek.json 2>/dev/null
uv run python fixtures/gen_samples.py
rm -rf "$tmp"
du -sh samples | cut -f1 | sed 's/^/samples size: /'
