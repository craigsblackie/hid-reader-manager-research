"""CRC-16 used by the HID Artemis reader framing.

Reverse-engineered from HidGlobal.ArtemisManager `Crc16` (decompiled):
  - lookup table == reflected CRC-16/CCITT ("Kermit") table, poly 0x8408
  - INIT constant = 0xE012, but the frame builder calls Compute(init=0, ...)
  - update:  crc = (crc >> 8) ^ TABLE[(crc ^ byte) & 0xFF]
  - the C# Compute() returns the byte-SWAPPED result: ((crc<<8)|(crc>>8)) & 0xFFFF
  - Util.SetUInt16 then stores that value little-endian.

Net on-wire effect for the 2 trailing CRC bytes: they equal the raw (un-swapped)
crc in BIG-endian order. `frame_crc_bytes()` reproduces the exact C# byte output.
"""

def _make_table(poly=0x8408):
    tbl = []
    for b in range(256):
        c = b
        for _ in range(8):
            c = (c >> 1) ^ poly if (c & 1) else (c >> 1)
        tbl.append(c & 0xFFFF)
    return tbl

TABLE = _make_table()
# sanity: matches the literal table decompiled from the app
assert TABLE[:4] == [0x0000, 0x1189, 0x2312, 0x329B], "CRC table mismatch"


def compute(data: bytes, init: int = 0) -> int:
    """Raw CRC (NOT byte-swapped). Matches the internal accumulator."""
    crc = init & 0xFFFF
    for byte in data:
        crc = (crc >> 8) ^ TABLE[(crc ^ byte) & 0xFF]
    return crc & 0xFFFF


def compute_csharp(data: bytes, init: int = 0) -> int:
    """Exactly what HidGlobal Crc16.Compute() returns (byte-swapped)."""
    crc = compute(data, init)
    return ((crc << 8) | (crc >> 8)) & 0xFFFF


def frame_crc_bytes(data: bytes, init: int = 0) -> bytes:
    """The 2 CRC bytes as they appear on the wire (SetUInt16 little-endian of the
    swapped value)."""
    val = compute_csharp(data, init)
    return bytes([val & 0xFF, (val >> 8) & 0xFF])


if __name__ == "__main__":
    # No official test vector is published; this documents behaviour.
    d = bytes.fromhex("0004a50286 00".replace(" ", ""))
    print("raw     :", hex(compute(d)))
    print("csharp  :", hex(compute_csharp(d)))
    print("wire crc:", frame_crc_bytes(d).hex())
