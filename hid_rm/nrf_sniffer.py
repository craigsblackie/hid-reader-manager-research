"""Driver for an nRF52 dongle running the nRF Sniffer for Bluetooth LE firmware
(VID 1915), reimplemented from scratch, to capture a phone<->reader BLE session
over the air and decode the HID management exchange.

Validated against the reader: the phone<->reader link is UNENCRYPTED at the BLE
link layer, so the captured data-channel PDUs carry the ProtocolV1 fragments /
APDUs / SNMP in cleartext -- this observes the SEOS admin AKE and the SNMP
management messages that we can't perform ourselves.

Protocol (reverse-engineered, working):
  serial 1_000_000 8N1; custom SLIP (START=0xAB END=0xBC ESC=0xCD, escape=+1).
  packet = SLIP( [payload_len][00][protover=3][ctr_lo][ctr_hi][id] + payload ).
  Commands: REQ_SCAN_CONT=0x07, REQ_FOLLOW=0x00 (payload: 6-byte address in
  DISPLAY/big-endian order + addr_type[1=random]). Events: id 0x02 = adv PDU,
  0x06 = data-channel PDU, 0x0e = idle/empty. Event payload = 9-byte meta
  [flags,channel,rssi,evt_ctr(2),timestamp(4)] + BLE packet [access_addr(4)+PDU].
"""
import time
from . import framing, btsnoop

START, END, ESC = 0xAB, 0xBC, 0xCD
REQ_FOLLOW, REQ_SCAN_CONT = 0x00, 0x07
EVENT_ADV, EVENT_DATA = 0x02, 0x06
META_LEN = 9


def _wrap(body: bytes) -> bytes:
    out = bytearray([START])
    for b in body:
        if b in (START, END, ESC):
            out += bytes([ESC, b + 1])
        else:
            out.append(b)
    out.append(END)
    return bytes(out)


def _cmd(pid: int, payload: bytes = b"") -> bytes:
    return _wrap(bytes([len(payload), 0, 3, 0, 0, pid]) + payload)


def _unescape(b: bytes) -> bytes:
    o = bytearray(); i = 0
    while i < len(b):
        if b[i] == ESC and i + 1 < len(b):
            o.append(b[i + 1] - 1); i += 2
        else:
            o.append(b[i]); i += 1
    return bytes(o)


class Sniffer:
    def __init__(self, port: str = "/dev/ttyACM2"):
        import serial
        self.s = serial.Serial(port, 1000000, timeout=0.1)
        time.sleep(0.3); self.s.reset_input_buffer()
        self._cur = None

    def follow(self, mac_display: str):
        """Lock onto a device by its display MAC (e.g. 'C0:60:33:15:2B:31').
        Address goes to the firmware in big-endian/display byte order."""
        addr = bytes(int(x, 16) for x in mac_display.split(":"))
        atype = 1 if (addr[0] & 0xC0) == 0xC0 else 0     # C0.. = static random
        self.s.reset_input_buffer()
        self.s.write(_cmd(REQ_SCAN_CONT)); time.sleep(0.3)
        self.s.write(_cmd(REQ_FOLLOW, addr + bytes([atype]))); time.sleep(0.3)

    def read_frames(self, duration: float):
        """Yield decoded sniffer frames (id, payload) for `duration` seconds."""
        t0 = time.time()
        while time.time() - t0 < duration:
            data = self.s.read(self.s.in_waiting or 1)
            for b in data:
                if b == START:
                    self._cur = bytearray()
                elif b == END and self._cur is not None:
                    f = _unescape(bytes(self._cur)); self._cur = None
                    if len(f) >= 6:
                        yield f[5], f[6:]
                elif self._cur is not None:
                    self._cur.append(b)

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def _att_from_data_pdu(payload: bytes):
    """From an EVENT_DATA payload return the ATT PDU bytes, or None. Rather than
    assume exact meta/LL offsets (which vary), locate the L2CAP ATT channel: an
    L2CAP header is [len(2 LE)][cid(2 LE)] and ATT is cid 0x0004. We scan for a
    `<len> 04 00` where `len` == the trailing ATT PDU length. ProtocolV1
    fragments are <=20B so each ATT PDU fits one LL PDU (no L2CAP reassembly)."""
    for i in range(2, len(payload) - 4):
        if payload[i] == 0x04 and payload[i + 1] == 0x00:      # candidate ATT CID
            l2_len = payload[i - 2] | (payload[i - 1] << 8)
            att = payload[i + 2:i + 2 + l2_len]
            if 3 <= len(att) == l2_len and att[0] in (0x1B, 0x52, 0x12, 0xD2, 0x1D, 0x0B):
                return att
    return None


def capture_session(port: str, mac_display: str, duration: float = 20.0,
                    auth_key: bytes = None, priv_key: bytes = None,
                    raw_out: str = None):
    """Follow `mac_display`, capture for `duration` s, reassemble ProtocolV1 per
    direction and decode. Returns the decoded event list (btsnoop-style). If
    `raw_out` is given, every EVENT_DATA payload is also appended there (hex per
    line) for offline re-analysis."""
    sn = Sniffer(port)
    rawf = open(raw_out, "w") if raw_out else None
    try:
        sn.follow(mac_display)
        bufs = {"tx": [], "rx": []}
        events = []
        for fid, payload in sn.read_frames(duration):
            if fid != EVENT_DATA:
                continue
            if rawf:
                rawf.write(payload.hex() + "\n"); rawf.flush()
            att = _att_from_data_pdu(payload)
            if not att or len(att) < 3:
                continue
            op = att[0]
            # Notify(0x1B)=reader->phone(rx); Write Cmd/Req(0x52/0x12)=phone->reader(tx)
            if op == 0x1B:
                direction = "rx"
            elif op in (0x52, 0x12):
                direction = "tx"
            else:
                continue
            value = att[3:]
            if not value:
                continue
            hdr = value[0]
            if (hdr & 0xE0) == 0xE0:
                from . import seos
                events.append({"dir": direction, "kind": "extension", "raw": value.hex(),
                               "note": seos.describe(value) if hdr == 0xE1 else "ext"})
                bufs[direction] = []
                continue
            bufs[direction].append(value)
            if hdr == 0xC0 or hdr == 0x40:
                body = framing.ble_reassemble(bufs[direction]); bufs[direction] = []
                events.append(btsnoop._decode_message(direction, body, auth_key, priv_key))
        return events
    finally:
        sn.close()
        if rawf:
            rawf.close()


def decode_raw(raw_path: str, auth_key: bytes = None, priv_key: bytes = None):
    """Re-decode a saved raw capture (hex EVENT_DATA payloads, one per line)."""
    bufs = {"tx": [], "rx": []}
    events = []
    for line in open(raw_path):
        line = line.strip()
        if not line:
            continue
        att = _att_from_data_pdu(bytes.fromhex(line))
        if not att or len(att) < 3:
            continue
        op = att[0]
        direction = "rx" if op == 0x1B else ("tx" if op in (0x52, 0x12) else None)
        if direction is None:
            continue
        value = att[3:]
        if not value:
            continue
        hdr = value[0]
        if (hdr & 0xE0) == 0xE0:
            from . import seos
            events.append({"dir": direction, "kind": "extension", "raw": value.hex(),
                           "note": seos.describe(value) if hdr == 0xE1 else "ext"})
            bufs[direction] = []
            continue
        bufs[direction].append(value)
        if hdr == 0xC0 or hdr == 0x40:
            body = framing.ble_reassemble(bufs[direction]); bufs[direction] = []
            events.append(btsnoop._decode_message(direction, body, auth_key, priv_key))
    return events
