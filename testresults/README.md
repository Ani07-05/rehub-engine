# Test results

Validation runs of the ReHub engine at commit aef8ad2638da7af8c4e521237fa070e9902de0dc, 2026-10-31 IST. Full record for the TRL form: [VALIDATION.md](VALIDATION.md).

- `logs/`: command output (`doctor`, `analyze`, failed-run cases, container boundary checks, pytest) and the stored investigation JSON.
- `screenshots/`: real UI on the same runs, headless Chrome at 1280 px. 01 to 05 are the passing run (case 0d8d20e56763); 06 is the truncated-capture case (9ca4303379d5) where Zeek and tshark fail and only Suricata is shown.
- `SHA256SUMS`: hashes of every file here. Check with `shasum -a 256 -c SHA256SUMS`.

Inputs are the synthetic `samples/capture/ot-demo.pcap` and `samples/plc/pump.st`. No live PLC or HMI was used.
