import ast
import json

from rehub.model import ModbusWrite

MODBUS_CODES = {
    "READ_COILS": 1, "READ_DISCRETE_INPUTS": 2, "READ_HOLDING_REGISTERS": 3,
    "READ_INPUT_REGISTERS": 4, "WRITE_SINGLE_COIL": 5, "WRITE_SINGLE_REGISTER": 6,
    "READ_EXCEPTION_STATUS": 7, "DIAGNOSTICS": 8, "GET_COMM_EVENT_COUNTER": 11,
    "GET_COMM_EVENT_LOG": 12, "WRITE_MULTIPLE_COILS": 15, "WRITE_MULTIPLE_REGISTERS": 16,
    "REPORT_SLAVE_ID": 17, "READ_FILE_RECORD": 20, "WRITE_FILE_RECORD": 21,
    "MASK_WRITE_REGISTER": 22, "READ_WRITE_MULTIPLE_REGISTERS": 23, "READ_FIFO_QUEUE": 24,
    "ENCAP_INTERFACE_TRANSPORT": 43,
}  # fmt: skip
SURICATA_NAMES = {
    "WrSingleCoil": 5, "WrSingleReg": 6, "WrMultCoils": 15, "WrMultRegs": 16,
    "MaskWrReg": 22, "RdWrMultRegs": 23,
}  # fmt: skip
COIL_CODES = frozenset({5, 15})
REGISTER_CODES = frozenset({6, 16, 22, 23})
VALUE_CAP = 64
ON = ("true", "1", "65280")
OFF = ("false", "0")


def function_code(attrs: dict[str, str]) -> int | None:
    raw = attrs.get("modbus.request.function_raw", "")
    if raw.isdigit():
        return int(raw)
    name = attrs.get("func") or attrs.get("modbus.request.function_code", "")
    code = MODBUS_CODES.get(name) or SURICATA_NAMES.get(name)
    return code


def _int(text: str | None, default: int) -> int:
    return int(text) if text and text.isdigit() else default


def _parse_list(text: str) -> list[str] | None:
    for parse in (json.loads, ast.literal_eval):
        try:
            value = parse(text)
        except (ValueError, SyntaxError):
            continue
        if isinstance(value, list):
            return [str(v) for v in value[:VALUE_CAP]]
    return None


def _coil(value: str) -> str:
    low = value.lower()
    return "ON" if low in ON else "OFF" if low in OFF else value


def _from_bytes(code: int, data: str, quantity: int) -> list[str] | None:
    if any(ord(c) > 0xFF for c in data):
        return None
    raw = [ord(c) for c in data]
    if code in REGISTER_CODES:
        if len(raw) < 2 * quantity:
            return None
        return [str((raw[i] << 8) | raw[i + 1]) for i in range(0, 2 * min(quantity, VALUE_CAP), 2)]
    if len(raw) * 8 < quantity:
        return None
    bits = [(raw[i // 8] >> (i % 8)) & 1 for i in range(min(quantity, VALUE_CAP))]
    return ["ON" if b else "OFF" for b in bits]


def _hex(value: str) -> str:
    return f"0x{int(value):04X}" if value.isdigit() else value


def _listed(attrs: dict[str, str]) -> list[str] | None:
    return _parse_list(attrs.get("request_values") or attrs.get("write_registers", ""))


def _values(code: int, attrs: dict[str, str], quantity: int) -> tuple[list[str], str]:
    listed = _listed(attrs)
    if listed is not None:
        return ([_coil(v) for v in listed] if code in COIL_CODES else listed), "set"
    if code == 22:
        masks = [
            f"{label} {_hex(attrs[k])}"
            for label, suffix in (("AND", "and_mask"), ("OR", "or_mask"))
            for k in sorted(attrs)
            if k == suffix or k == f"modbus.request.write.{suffix}"
        ]
        return masks, "mask"
    data = attrs.get("modbus.request.write.data")
    if data is None:
        return [], "set"
    if code in (5, 6):
        return [_coil(data) if code == 5 else data], "set"
    return _from_bytes(code, data, quantity) or [], "set"


def write_from_attrs(attrs: dict[str, str], tool: str) -> ModbusWrite | None:
    code = function_code(attrs)
    if code not in COIL_CODES | REGISTER_CODES:
        return None
    address = (
        attrs.get("address")
        or attrs.get("write_start_address")
        or attrs.get("modbus.request.write.address", "")
    )
    if not address.isdigit():
        return None
    listed = _listed(attrs)
    quantity = _int(
        attrs.get("quantity") or attrs.get("modbus.request.write.quantity"),
        len(listed) if listed else 1,
    )
    values, op = _values(code, attrs, quantity)
    return ModbusWrite(
        code=code,
        kind="coil" if code in COIL_CODES else "register",
        address=int(address),
        quantity=quantity,
        values=values,
        op=op,
        seen={tool: 1},
    )


def note_write(writes: list[ModbusWrite], new: ModbusWrite, cap: int) -> bool:
    for w in writes:
        if (w.code, w.address, w.quantity) != (new.code, new.address, new.quantity):
            continue
        if w.values and new.values and w.values != new.values:
            continue
        if not w.values:
            w.values, w.op = new.values, new.op
        for tool, n in new.seen.items():
            w.seen[tool] = w.seen.get(tool, 0) + n
        return True
    if len(writes) >= cap:
        return False
    writes.append(new)
    return True
