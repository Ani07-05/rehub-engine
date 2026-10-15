import base64
import hashlib
import ipaddress
import struct

PROTO_NUMBERS = {"tcp": 6, "udp": 17, "sctp": 132}


def community_id(
    src: str, dst: str, sport: int, dport: int, proto: str | int, seed: int = 0
) -> str | None:
    number = PROTO_NUMBERS.get(proto.lower()) if isinstance(proto, str) else proto
    if number is None or number not in PROTO_NUMBERS.values():
        return None
    try:
        a = ipaddress.ip_address(src)
        b = ipaddress.ip_address(dst)
    except ValueError:
        return None
    if a.version != b.version:
        return None
    first, second = (a.packed, sport), (b.packed, dport)
    if second < first:
        first, second = second, first
    digest = hashlib.sha1(
        struct.pack(">H", seed)
        + first[0]
        + second[0]
        + bytes([number, 0])
        + struct.pack(">HH", first[1], second[1]),
        usedforsecurity=False,
    ).digest()
    return "1:" + base64.b64encode(digest).decode()
