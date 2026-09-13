"""Artemis transport framing over BLE / NFC / serial.

Reverse-engineered from HidGlobal.ArtemisManager (decompiled):

Reader message on the wire (BLE data characteristic 0000aa00-...):

    +----------------+------------------------------+-----------+
    | u16 length BE  |  APDU  (length bytes)        | u16 CRC16 |
    +----------------+------------------------------+-----------+
      len = len(APDU)                                 CRC16/CCITT-Kermit
                                                      over [len_hi,len_lo,APDU]

  - length prefix is BIG-endian (array[0]=len>>8, array[1]=len).
  - CRC is crc16.frame_crc_bytes(len_prefix + apdu)  (see crc16.py).
  - APDU = ISO7816:  CLA INS P1 P2 Lc  DATA...
      * Lc == len(DATA); if Lc==0 an extended (u16) length header is used.
  - DATA carries either a BER-encoded Artemis `Payload` (core/HF/LF/... commands)
    or an SNMPv3 message (reader-config MIB get/set).

Response payload offset (GetPayloadOffset, decompiled):
    SERIAL -> 6 ; BLE/NFC -> 7 if apdu[4]==0 else 5
i.e. the reader echoes the APDU header (CLA INS P1 P2 Lc) before the
[u16 len][data][crc] body.

NOTE: for reader-config the DATA is an SNMPv3 message wrapped in a GET_DATA(0xCA)/
PUT_DATA(0xDA) APDU. The exact CLA/P1/P2 bytes are set inside an obfuscated async
state machine and should be confirmed against a live reader; the framing + CRC and
the SNMP/Artemis payloads below are validated.
"""
from . import crc16

# ISO7816 (from HidGlobal.ArtemisManager ISO7816 constants)
OFFSET_CLA, OFFSET_INS, OFFSET_P1, OFFSET_P2, OFFSET_LC, OFFSET_DATA = 0, 1, 2, 3, 4, 5
INS_SELECT_FILE  = 0xA4
INS_GET_DATA     = 0xCA
INS_GET_RESPONSE = 0xC0
INS_PUT_DATA     = 0xDA


def build_apdu(ins, data=b"", cla=0x00, p1=0x00, p2=0x00):
    """Short ISO7816 APDU: CLA INS P1 P2 Lc DATA."""
    if len(data) > 255:
        raise ValueError("use extended APDU for >255 bytes of data")
    return bytes([cla, ins, p1, p2, len(data)]) + data


def frame(apdu: bytes) -> bytes:
    """Wrap an APDU in the Artemis [len][apdu][crc] frame (what goes on aa00)."""
    n = len(apdu)
    head = bytes([(n >> 8) & 0xFF, n & 0xFF])
    return head + apdu + crc16.frame_crc_bytes(head + apdu)


def payload_offset(apdu_or_resp: bytes, comm="BLE") -> int:
    if comm == "SERIAL":
        return 6
    return 7 if apdu_or_resp[4] == 0 else 5


def parse_response(buf: bytes, comm="BLE"):
    """Return (echoed_apdu_header, data, crc_ok) from a reader response frame."""
    off = payload_offset(buf, comm)
    header = buf[:off]
    body = buf[off:]
    length = (body[0] << 8) | body[1]
    data = body[2:2 + length]
    crc_rx = body[2 + length:2 + length + 2]
    crc_ok = crc16.frame_crc_bytes(body[:2 + length]) == crc_rx
    return header, data, crc_ok


# =============================================================================
# BLE fragmentation (ProtocolV1Fragment, from Plugin.BLE.Abstractions) - LIVE-VERIFIED
# Each 20-byte GATT write is prefixed with a 1-byte fragment header:
#   0xC0            = InitialAndFinal (single complete message)
#   0x80|remaining  = InitialWithMore (remaining>0 fragments follow, remaining<=31)
#   1..31           = Intermediate (value = fragments still remaining)
#   0x40            = Final
#   0xE0..0xFF      = Extension  (0xE1 EOT/status, 0xE2 FW, 0xE5 config)
# Without this header the reader reads your first byte as a fragment count and
# replies e1 05 (FRAG_TIMEOUT). WITH it, the reader accepts and drives its
# transaction (verified against reader C0:60:33:15:2B:31).
# =============================================================================

def ble_fragment(frame: bytes, payload_per_fragment: int = 19):
    """Split an Artemis frame into ProtocolV1 BLE fragments (list of writes)."""
    if len(frame) <= payload_per_fragment:
        return [bytes([0xC0]) + frame]
    chunks = [frame[i:i + payload_per_fragment]
              for i in range(0, len(frame), payload_per_fragment)]
    n = len(chunks)
    out = []
    for i, ch in enumerate(chunks):
        if i == 0:
            hdr = 0x80 | min(n - 1, 31)
        elif i == n - 1:
            hdr = 0x40
        else:
            hdr = (n - 1 - i) & 0x1F
        out.append(bytes([hdr]) + ch)
    return out


def ble_fragment_type(first_byte: int) -> str:
    b = first_byte
    if (b & 0xE0) == 0xE0:
        return "extension"
    if b == 0xC0:
        return "single"
    if b & 0x80:
        return f"initial(more={b & 0x1F})"
    if b == 0x40:
        return "final"
    return f"intermediate(rem={b})"


def ble_reassemble(fragments):
    """Concatenate fragment payloads (skips extension/status frames)."""
    buf = b""
    for f in fragments:
        if not f or (f[0] & 0xE0) == 0xE0:
            continue
        buf += f[1:]
    return buf
