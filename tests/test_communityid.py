import json
from pathlib import Path

import pytest

from rehub.communityid import community_id

DEMO = Path(__file__).resolve().parent.parent / "fixtures" / "ot-demo"


def test_spec_example() -> None:
    assert (
        community_id("128.232.110.120", "66.35.250.204", 34855, 80, "tcp")
        == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    )


def test_direction_independent() -> None:
    fwd = community_id("10.0.0.1", "10.0.0.2", 1234, 502, "tcp")
    rev = community_id("10.0.0.2", "10.0.0.1", 502, 1234, "tcp")
    assert fwd == rev


def test_seed_changes_id() -> None:
    assert community_id("10.0.0.1", "10.0.0.2", 1, 2, "tcp") != community_id(
        "10.0.0.1", "10.0.0.2", 1, 2, "tcp", seed=1
    )


def test_ipv6() -> None:
    cid = community_id("fe80::1", "fe80::2", 1000, 2000, "udp")
    assert cid is not None and cid.startswith("1:")


@pytest.mark.parametrize(
    ("src", "dst", "proto"),
    [
        ("10.0.0.1", "10.0.0.2", "icmp"),
        ("10.0.0.1", "fe80::1", "tcp"),
        ("not-an-ip", "10.0.0.2", "tcp"),
    ],
)
def test_unsupported_returns_none(src: str, dst: str, proto: str) -> None:
    assert community_id(src, dst, 1, 2, proto) is None


def test_matches_zeek_conn_log() -> None:
    rows = [json.loads(line) for line in (DEMO / "zeek" / "conn.log").read_text().splitlines()]
    assert rows
    for r in rows:
        got = community_id(
            r["id.orig_h"], r["id.resp_h"], r["id.orig_p"], r["id.resp_p"], r["proto"]
        )
        assert got == r["community_id"]


def test_matches_suricata_flows() -> None:
    events = [
        json.loads(line) for line in (DEMO / "suricata" / "eve.json").read_text().splitlines()
    ]
    flows = [e for e in events if e["event_type"] == "flow"]
    assert flows
    for e in flows:
        got = community_id(e["src_ip"], e["dest_ip"], e["src_port"], e["dest_port"], e["proto"])
        assert got == e["community_id"]
