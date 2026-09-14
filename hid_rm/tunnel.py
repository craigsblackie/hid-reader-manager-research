"""Build/parse the Artemis "partial read" SNMP GET that the app injects into
the reader's poll loop -- reverse-engineered from the real captured session
(PROTOCOL.md sec:31-33).

Wire template for one injected command (phone->reader, answering the reader's
`00 CA 00 00 00` GET_DATA poll):

    44 0A 44 00 00 00 A0 <L1> 94 <L2> 30 <L3> <SNMPv3 msg> 90 00

`30 <L3> ...` is a normal SNMPv3 message as produced by snmpv3.build_message
(see snmpv3.py); `94 <L2>` and `A0 <L1>` are two enclosing Artemis TLVs with no
semantic content of their own (`A0` mirrors the SNMP PDU type: 0xA0=GET,
0xA3=SET). `44 0A 44 00 00 00` and the trailing `90 00` are constant.

Every plain (noAuthNoPriv) config item is read via one extra indirection: the
SNMP GET is *always* addressed to the fixed meta-OID STORE_OPERATION_PARTIAL_READ
(03000306), and the *value* field (normally unused on a GET, but build_message
happily wraps whatever bytes we pass it in the same OCTET STRING) carries
`SEQUENCE { OID target, INTEGER offset, INTEGER length }`. The reader answers
with a varbind whose OID is the *target* OID and whose value is up to `length`
bytes of it starting at `offset` -- values over ~128B need repeat GETs with
increasing offsets (validated against the real multi-part reads of
DATAMODELS_VS_PROTOCOL_TABLE, SEOS_ADMIN_CARD_APP, SEOS_PACS_CONFIG).

The USM header fields observed in every real request are FIXED constants, not
per-reader/per-session values -- no discovery handshake is needed for
noAuthNoPriv reads:
    engine_id = 03010705 (== the OEM_ADMIN_ENGINEID OID, reused as a literal)
    user_name = 03010704 (== the OEM_ADMIN_USERNAME OID, reused as a literal)
    engine_boots = 0, engine_time = 0
"""
import os
from . import snmpv3

STORE_OPERATION_PARTIAL_READ = bytes.fromhex("03000306")
FIXED_ENGINE_ID = bytes.fromhex("03010705")
FIXED_USER = bytes.fromhex("03010704")
GET_TAG, SET_TAG = 0xA0, 0xA3

_HDR = bytes.fromhex("440a44000000")
_TAIL = bytes.fromhex("9000")


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def _ber_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(content)) + content


def _seq(*parts: bytes) -> bytes:
    return _ber_tlv(0x30, b"".join(parts))


def _int(n: int) -> bytes:
    if n == 0:
        return _ber_tlv(0x02, b"\x00")
    nbytes = (n.bit_length() + 7) // 8
    b = n.to_bytes(nbytes, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _ber_tlv(0x02, b)


def build_partial_read_get(target_oid: bytes, offset: int = 0, length: int = 128,
                            msg_id: int | None = None, request_id: int | None = None) -> bytes:
    """Full injected-command bytes for a keyless read of `target_oid` at
    [offset, offset+length). Byte-exact against the app's own wire format
    (verified against real captured requests in PROTOCOL.md sec:33)."""
    msg_id = msg_id if msg_id is not None else int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
    request_id = request_id if request_id is not None else int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
    partial_read_value = _seq(_ber_tlv(0x06, target_oid), _int(offset), _int(length))
    snmp = snmpv3.build_message(snmpv3.GET_REQUEST, STORE_OPERATION_PARTIAL_READ, partial_read_value,
                                engine_id=FIXED_ENGINE_ID, user_name=FIXED_USER,
                                engine_boots=0, engine_time=0, msg_id=msg_id, request_id=request_id)
    inner = _ber_tlv(0x94, snmp)
    outer = _ber_tlv(GET_TAG, inner)
    return _HDR + outer + _TAIL


def _tlv(b, i):
    t = b[i]; l = b[i + 1]; j = i + 2
    if l == 0x82:
        l = (b[j] << 8) | b[j + 1]; j += 2
    elif l == 0x81:
        l = b[j]; j += 1
    return t, b[j:j + l], j + l


def parse_response(body: bytes):
    """Parse a reassembled reader->phone PUT_DATA APDU body. Returns
    {'target_oid':hex,'value':bytes} for a cleartext SNMP result, {'encrypted':
    True} for authPriv, or None if this isn't a recognisable SNMP result."""
    idx = body.find(b"\xbd")
    if idx < 0:
        return None
    _, val, _ = _tlv(body, idx)
    if not val or val[0] != 0x8a:
        return None
    _, snmp, _ = _tlv(val, 0)
    _, seq, _ = _tlv(snmp, 0)
    i = 0
    _, ver, i = _tlv(seq, i)
    _, gd, i = _tlv(seq, i)
    _, sp, i = _tlv(seq, i)
    rest = seq[i:]
    if not rest or rest[0] != 0x30:
        return {"encrypted": True}
    _, sc, _ = _tlv(rest, 0)
    si = 0
    _, ceid, si = _tlv(sc, si)
    _, cname, si = _tlv(sc, si)
    _, pdu, si = _tlv(sc, si)
    pi = 0
    _, rid, pi = _tlv(pdu, pi)
    _, es, pi = _tlv(pdu, pi)
    _, ei, pi = _tlv(pdu, pi)
    _, vbl, pi = _tlv(pdu, pi)
    out = []
    vi = 0
    while vi < len(vbl):
        _, vb, vi = _tlv(vbl, vi)
        bi = 0
        _, o, bi = _tlv(vb, bi)
        _, v, bi = _tlv(vb, bi)
        out.append((o.hex(), v))
    if not out:
        return None
    oidhex, value = out[0]
    return {"target_oid": oidhex, "value": value}
