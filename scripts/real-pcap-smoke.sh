#!/bin/sh
# Downloads a few small public ICS captures (not committed, see the source repo for terms)
# and runs each through the ReHub image with no network. Needs docker and the rehub:dev image.
set -eu
dir=$(mktemp -d)
base=https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps
curl -fsSL -o "$dir/modbus1.pcap" "$base/ModbusTCP/modbus_test_data_part1.pcap"
curl -fsSL -o "$dir/modbus2.pcap" "$base/ModbusTCP/modbus_test_data_part2.pcap"
curl -fsSL -o "$dir/s7_time.pcap" "$base/s7/s7comm_reading_setting_plc_time.pcap"
curl -fsSL -o "$dir/s7_hmi.pcap" "$base/s7/S7-1511_db2_var1_HMI.pcap"
curl -fsSL -o "$dir/dnp3.pcap" "$base/dnp3/dnp3_test_data_part1.pcap"
for f in modbus1 modbus2 s7_time s7_hmi dnp3; do
  data=$(mktemp -d); chmod 777 "$data"
  echo "=== $f"
  docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL \
    --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
    -v "$dir:/in:ro" -v "$data:/data" "${REHUB_IMAGE:-rehub:dev}" \
    rehub --data /data analyze "/in/$f.pcap" 2>/dev/null | sed -n '/^Assets/,$p'
done
