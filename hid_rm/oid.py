"""ASN.1 Object Identifier encode/decode (DER), used throughout the reader's
config MIB and its SEOS PACS credential addressing -- both live under the same
enterprise arc 1.3.6.1.4.1.29240.

CORRECTION: an earlier note in this project claimed PEN 24632. Verified by hand:
2B 06 01 04 01 81 E4 38 decodes to 1.3.6.1.4.1.29240, not 24632
(81 E4 38 = continuation(1),continuation(100),final(56) = (1<<14)|(100<<7)|56 = 29240).
"""


def decode(b: bytes) -> str:
    """DER OID bytes -> dotted string, e.g. b'\\x2b\\x06...' -> '1.3.6...'"""
    if not b:
        raise ValueError("empty OID")
    vals = [b[0] // 40, b[0] % 40]
    n = 0
    for x in b[1:]:
        n = (n << 7) | (x & 0x7F)
        if not x & 0x80:
            vals.append(n)
            n = 0
    if n != 0:
        raise ValueError("truncated OID (incomplete multi-byte arc)")
    return ".".join(map(str, vals))


def encode(dotted: str) -> bytes:
    """dotted string -> DER OID bytes."""
    arcs = [int(x) for x in dotted.split(".")]
    out = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        if arc == 0:
            out += b"\x00"
            continue
        chunk = []
        n = arc
        while n > 0:
            chunk.append(n & 0x7F)
            n >>= 7
        chunk.reverse()
        for i in range(len(chunk) - 1):
            chunk[i] |= 0x80
        out += bytes(chunk)
    return out


def try_decode(b: bytes):
    """decode() but returns None instead of raising, for scanning untrusted data."""
    try:
        return decode(b)
    except Exception:
        return None
