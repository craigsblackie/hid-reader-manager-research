"""Parse an Android/Linux Bluetooth HCI snoop log of a phone<->reader management
session and decode the HID management exchange.

No BLE sniffer hardware is needed: Android's built-in "Bluetooth HCI snoop log"
(Developer options) records every BLE packet the phone sends/receives to a
btsnoop file. Capture a Reader Manager management session, pull the log, and this
extracts the GATT writes/notifications on the reader's data characteristic,
reassembles the ProtocolV1 fragments, and decodes the APDUs / SNMP messages
using the same hid_rm logic as the live tools.

btsnoop format: 8-byte "btsnoop\\0" ident + u32 version + u32 datalink, then
records: u32 orig_len, u32 incl_len, u32 flags, u32 drops, u64 ts, <packet>.
For HCI-UART (datalink 1002) the packet starts with an HCI type byte
(0x02 = ACL). We follow ACL -> L2CAP -> ATT (CID 0x0004) and pull the value of
Write Command/Request (0x52/0x12) and Handle Value Notification (0x1B).
"""
import struct
from . import framing, seos, snmpv3, emulate, oid as oidmod


def _iter_records(data: bytes):
    if data[:8] != b"btsnoop\x00":
        raise ValueError("not a btsnoop file")
    # skip 8 ident + 4 version + 4 datalink
    off = 16
    while off + 24 <= len(data):
        orig_len, incl_len, flags, drops, ts = struct.unpack_from(">IIIIq", data, off)
        off += 24
        pkt = data[off:off + incl_len]
        off += incl_len
        # flags bit0: 1 = received (controller->host), 0 = sent (host->controller)
        yield ("rx" if (flags & 1) else "tx"), pkt


def _att_from_acl(pkt: bytes):
    """pkt starts with HCI type byte. For ACL (0x02): [type][handle+flags u16]
    [acl_len u16][l2cap_len u16][l2cap_cid u16][att...]. Return att bytes if
    CID==0x0004 (ATT), else None. Handles only single-frame (non-continuation)
    L2CAP for simplicity (BLE ATT PDUs on the data char are small)."""
    if not pkt or pkt[0] != 0x02:
        return None
    if len(pkt) < 9:
        return None
    # pkt[1:3] handle+flags, pkt[3:5] acl_len, pkt[5:7] l2cap_len, pkt[7:9] cid
    cid = struct.unpack_from("<H", pkt, 7)[0]
    if cid != 0x0004:
        return None
    return pkt[9:]


# ATT opcodes carrying a characteristic value
_ATT_WRITE_CMD = 0x52
_ATT_WRITE_REQ = 0x12
_ATT_NOTIFY = 0x1B
_ATT_WRITE_CMD_SIGNED = 0xD2


def extract_gatt_values(data: bytes, handle: int | None = None):
    """Yield (direction, att_handle, value_bytes) for every ATT write/notify.
    If `handle` is given, only that attribute handle is returned."""
    for direction, pkt in _iter_records(data):
        att = _att_from_acl(pkt)
        if not att or len(att) < 3:
            continue
        op = att[0]
        if op in (_ATT_WRITE_CMD, _ATT_WRITE_REQ, _ATT_NOTIFY, _ATT_WRITE_CMD_SIGNED):
            att_handle = struct.unpack_from("<H", att, 1)[0]
            value = att[3:]
            if handle is not None and att_handle != handle:
                continue
            yield direction, att_handle, value


def _guess_data_handle(data: bytes):
    """Find the attribute handle that carries ProtocolV1 fragments (first byte
    0xC0/0x80|n/0x40/0xE0..). That's the reader's aa00 data characteristic."""
    from collections import Counter
    votes = Counter()
    for _, h, v in extract_gatt_values(data):
        if v and (v[0] == 0xC0 or v[0] == 0x40 or (v[0] & 0x80) or (v[0] & 0xE0) == 0xE0):
            votes[h] += 1
    return votes.most_common(1)[0][0] if votes else None


def decode_session(data: bytes, handle: int | None = None, auth_key: bytes = None,
                   priv_key: bytes = None):
    """Reassemble the ProtocolV1 stream on the data characteristic and decode
    each complete message (APDU or SNMP). Returns a list of decoded events."""
    if handle is None:
        handle = _guess_data_handle(data)
    events = []
    # separate tx (phone->reader) and rx (reader->phone) reassembly buffers
    bufs = {"tx": [], "rx": []}
    for direction, h, v in extract_gatt_values(data, handle):
        if not v:
            continue
        hdr = v[0]
        if (hdr & 0xE0) == 0xE0:
            events.append({"dir": direction, "kind": "extension", "raw": v.hex(),
                           "note": seos.describe(v) if hdr == 0xE1 else "ext"})
            bufs[direction] = []
            continue
        bufs[direction].append(v)
        # complete when we see a single (0xC0) or a Final (0x40)
        if hdr == 0xC0 or hdr == 0x40:
            body = framing.ble_reassemble(bufs[direction]); bufs[direction] = []
            events.append(_decode_message(direction, body, auth_key, priv_key))
    return events


def _decode_message(direction, body, auth_key, priv_key):
    ev = {"dir": direction, "raw": body.hex()}
    if not body:
        ev["kind"] = "empty"; return ev
    # reader->phone frames are raw APDUs; phone->reader may be [len][apdu][crc]
    apdu = body
    if len(body) > 4 and body[0] == 0x00 and ((body[0] << 8) | body[1]) + 4 == len(body):
        try:
            _, apdu, _ = framing.parse_response(body)
        except Exception:
            apdu = body
    ins = apdu[1] if len(apdu) > 1 else None
    if ins == framing.INS_SELECT_FILE and len(apdu) >= 5:  # SELECT AID
        aid = apdu[5:5 + apdu[4]]
        ev["kind"] = "SELECT_AID"; ev["aid"] = aid.hex()
        ev["name"] = emulate.classify_aid(aid)
    elif ins == 0xA5:  # SELECT ADF (config leak)
        ev["kind"] = "SELECT_ADF"; ev["oids"] = _adf_oids(apdu)
    elif ins in (framing.INS_GET_DATA, framing.INS_PUT_DATA):  # SNMP carrier
        ev["kind"] = "SNMP_SET" if ins == framing.INS_PUT_DATA else "SNMP_GET"
        ev.update(_decode_snmp(apdu[5:], auth_key, priv_key))
    elif ins == 0x87:
        ev["kind"] = "SEOS_AUTHENTICATE (AKE)"
    elif ins == 0x15:
        ev["kind"] = "CORE_ADMIN"
    else:
        ev["kind"] = f"apdu(ins={ins:02x})" if ins is not None else "data"
    return ev


def _adf_oids(apdu):
    oids = []; d = apdu[5:5 + apdu[4]] if len(apdu) >= 5 else b""; i = 0
    while i + 1 < len(d):
        t, l = d[i], d[i + 1]
        if t == 0x06 and i + 2 + l <= len(d):
            try:
                oids.append(oidmod.decode(d[i + 2:i + 2 + l]))
            except Exception:
                pass
        i += 2 + l
    return oids


def _decode_snmp(msg, auth_key, priv_key):
    out = {}
    try:
        rep = snmpv3.parse_report(msg)  # cleartext USM header fields
        out["engine_id"] = rep["engine_id"]; out["engine_boots"] = rep["engine_boots"]
        out["engine_time"] = rep["engine_time"]
        out["user"] = rep["user_name"].decode("latin1", "replace")
    except Exception:
        pass
    if auth_key or priv_key:
        try:
            dec = snmpv3.parse_secured_response(msg, auth_key=auth_key, priv_key=priv_key, verify=False)
            out["varbinds"] = [{"oid": vb["oid"], "value": vb["value"].hex() if vb["value"] else None}
                               for vb in dec["varbinds"]]
        except Exception as e:
            out["decrypt_error"] = str(e)
    else:
        out["note"] = "authPriv payload encrypted; supply keys to decrypt, else replayable via config-apply"
    return out


def render(events) -> str:
    lines = ["HID BLE management session (from HCI snoop):", ""]
    for i, e in enumerate(events):
        arrow = "phone->reader" if e["dir"] == "tx" else "reader->phone"
        head = f"[{i:3}] {arrow}  {e['kind']}"
        extra = ""
        if e.get("name"):
            extra = f"  {e['name']}"
        elif e.get("oids"):
            extra = "  OIDs=" + ",".join(e["oids"])
        elif e.get("engine_id"):
            extra = f"  engineId={e['engine_id']} user={e.get('user','')}"
            if e.get("varbinds"):
                extra += " " + "; ".join(f"{v['oid']}={v['value']}" for v in e["varbinds"])
        elif e.get("note") and e["kind"] == "extension":
            extra = f"  {e['note']}"
        lines.append(head + extra)
    return "\n".join(lines)
