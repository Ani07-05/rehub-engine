from rehub.correlate import correlate
from rehub.modbus import note_write, write_from_attrs
from rehub.model import ModbusWrite
from rehub.schema import Event, EventKind
from rehub.serialize import detection_from_dict, to_jsonable

FLOW = "1:modbus-writes"


def suri(code: int, **write: str) -> dict[str, str]:
    attrs = {"modbus.request.function_raw": str(code)}
    attrs.update({f"modbus.request.write.{k}": v for k, v in write.items()})
    return attrs


def test_single_register_from_suricata_and_zeek() -> None:
    s = write_from_attrs(suri(6, address="10", data="1000"), "suricata")
    z = write_from_attrs(
        {
            "func": "WRITE_SINGLE_REGISTER",
            "address": "10",
            "quantity": "1",
            "request_values": "[1000]",
        },
        "zeek",
    )
    assert s is not None and z is not None
    assert (s.kind, s.address, s.values) == ("register", 10, ["1000"])
    assert (z.kind, z.address, z.values) == ("register", 10, ["1000"])


def test_multiple_registers_decode_big_endian_bytes() -> None:
    w = write_from_attrs(suri(16, address="0", quantity="2", data="'\x10'\x10"), "suricata")
    assert w is not None and w.values == ["10000", "10000"] and w.quantity == 2


def test_short_register_data_is_not_guessed() -> None:
    w = write_from_attrs(suri(16, address="0", quantity="4", data="'\x10"), "suricata")
    assert w is not None and w.values == []


def test_single_coil_on_and_off() -> None:
    on = write_from_attrs(suri(5, address="3", data="65280"), "suricata")
    off = write_from_attrs(
        {"func": "WRITE_SINGLE_COIL", "address": "4", "request_values": "[False]"}, "zeek"
    )
    assert on is not None and on.kind == "coil" and on.values == ["ON"]
    assert off is not None and off.values == ["OFF"]


def test_multiple_coils_unpack_bits_lsb_first() -> None:
    w = write_from_attrs(suri(15, address="0", quantity="10", data="\x05\x02"), "suricata")
    assert w is not None
    assert w.values == ["ON", "OFF", "ON", "OFF", "OFF", "OFF", "OFF", "OFF", "OFF", "ON"]


def test_mask_write_and_read_write_multiple() -> None:
    m = write_from_attrs(
        {
            **suri(22, address="7"),
            "modbus.request.write.and_mask": "0x00F2",
            "modbus.request.write.or_mask": "0x0025",
        },
        "suricata",
    )
    assert m is not None and m.op == "mask" and m.values == ["AND 0x00F2", "OR 0x0025"]
    rw = write_from_attrs(suri(23, address="20", quantity="1", data="\x00\x2a"), "suricata")
    assert rw is not None and rw.values == ["42"] and rw.address == 20


def test_reads_and_unknown_functions_are_not_writes() -> None:
    assert write_from_attrs({"func": "READ_HOLDING_REGISTERS", "address": "0"}, "zeek") is None
    assert write_from_attrs(suri(3, address="0"), "suricata") is None
    assert write_from_attrs({"func": "WRITE_SINGLE_REGISTER"}, "zeek") is None
    assert write_from_attrs({"func": "WRITE_FILE_RECORD", "address": "1"}, "zeek") is None
    assert write_from_attrs({}, "zeek") is None


def test_same_write_seen_by_two_tools_counts_once() -> None:
    writes: list[ModbusWrite] = []
    a = write_from_attrs(suri(6, address="10", data="1000"), "suricata")
    b = write_from_attrs(
        {"func": "WRITE_SINGLE_REGISTER", "address": "10", "request_values": "[1000]"}, "zeek"
    )
    assert a is not None and b is not None
    note_write(writes, a, 50)
    note_write(writes, b, 50)
    [only] = writes
    assert only.seen == {"suricata": 1, "zeek": 1} and only.count == 1


def req(ts: float, tid: str, func: str) -> Event:
    return Event(
        ts=ts, tool="zeek", kind=EventKind.PROTOCOL_ACTION, evidence_id="e", src="10.0.0.9",
        dst="10.0.0.3", sport=3082, dport=502, proto="modbus", flow_key=FLOW,
        attrs={"pdu_type": "REQ", "func": func, "tid": tid},
    )  # fmt: skip


def detail(ts: float, tid: str, func: str, address: int, values: str) -> Event:
    return Event(
        ts=ts, tool="zeek", kind=EventKind.PROTOCOL_ACTION, evidence_id="e", src="10.0.0.9",
        dst="10.0.0.3", proto="modbus_detailed", flow_key=FLOW,
        attrs={
            "func": func, "tid": tid, "address": str(address), "quantity": "1",
            "request_values": values,
        },
    )  # fmt: skip


def test_one_detection_lists_every_distinct_write() -> None:
    func = "WRITE_SINGLE_REGISTER"
    events = [
        req(100.0, "1", func), detail(100.0, "1", func, 10, "[1000]"),
        req(100.2, "1", func), detail(100.2, "1", func, 11, "[5]"),
        req(100.4, "1", func), detail(100.4, "1", func, 10, "[1000]"),
        req(100.6, "1", func), detail(100.6, "1", func, 10, "[0]"),
    ]  # fmt: skip
    inv = correlate(events)
    [det] = inv.detections
    got = [(w.address, w.values, w.count) for w in det.writes]
    assert got == [(10, ["1000"], 2), (11, ["5"], 1), (10, ["0"], 1)]


def test_write_cap_reports_omitted() -> None:
    func = "WRITE_SINGLE_REGISTER"
    events: list[Event] = []
    for i in range(60):
        t = 100.0 + i * 0.1
        events += [req(t, "1", func), detail(t, "1", func, i, "[1]")]
    [det] = correlate(events).detections
    assert len(det.writes) == 50 and det.attrs["writes_omitted"] == "10"


def test_writes_survive_json_round_trip_and_old_records_load() -> None:
    func = "WRITE_SINGLE_REGISTER"
    [det] = correlate([req(1.0, "1", func), detail(1.0, "1", func, 10, "[1000]")]).detections
    data = to_jsonable(det)
    assert data["writes"][0]["count"] == 1
    assert detection_from_dict(data).writes == det.writes
    del data["writes"]
    assert detection_from_dict(data).writes == []


def test_zeek_mask_write_and_read_write_logs() -> None:
    mask = write_from_attrs(
        {"func": "MASK_WRITE_REGISTER", "address": "7", "and_mask": "242", "or_mask": "37"}, "zeek"
    )
    assert mask is not None and mask.values == ["AND 0x00F2", "OR 0x0025"]
    rw = write_from_attrs(
        {
            "func": "READ_WRITE_MULTIPLE_REGISTERS", "write_start_address": "20",
            "write_registers": "[42, 43]", "read_start_address": "0", "read_quantity": "1",
        },
        "zeek",
    )  # fmt: skip
    assert rw is not None and (rw.address, rw.quantity, rw.values) == (20, 2, ["42", "43"])


def test_mask_write_ignores_response_masks() -> None:
    attrs = {
        **suri(22, address="7", and_mask="242", or_mask="37"),
        "modbus.response.write.and_mask": "242",
        "modbus.response.write.or_mask": "37",
    }
    w = write_from_attrs(attrs, "suricata")
    assert w is not None and w.values == ["AND 0x00F2", "OR 0x0025"]
