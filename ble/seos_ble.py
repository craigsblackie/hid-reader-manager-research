"""
SEOS (HID) BLE reader client -- configure a HID MultiClass SE reader from Linux.

Reverse-engineered from the HID Reader Manager / Assa Abloy MobileKey SDK
(jadx_out/sources/com/assaabloy/...). Verified against a live reader
(C0:60:33:15:2B:31 "Seos") on BlueZ.

Transport
---------
BLE GATT (confirmed by live discovery):
  service        00009800-0000-1000-8000-00177a000002
  data char      0000aa00-0000-1000-8000-00177a000002   [write-without-response, notify]
  CCCD           00002902-0000-1000-8000-00805f9b34fb   (enable notify)

Protocol
--------
Each BLE write carries one full SEOS APDU (CLA INS P1 P2 [Lc data] [Le]).
The reader replies over the notification channel with [data][SW1 SW2].
  0x9000 success
  0x61xx more bytes available -> continue with GET RESPONSE (00 C0 00 00 xx)
  0x6Cxx wrong Le            -> retry with Le = xx

Run:
    python seos_ble.py scan
    python seos_ble.py --addr C0:60:33:15:2B:31 open            # open SEOS session (SELECT)
    python seos_ble.py --addr C0:60:33:15:2B:31 select          # select SEOS applet
    python seos_ble.py --addr C0:60:33:15:2B:31 getdata 06      # read tag 0x06
    python seos_ble.py --addr C0:60:33:15:2B:31 configure 06    # open + read config
    python seos_ble.py --addr C0:60:33:15:2B:31 initfs          # initialize filesystem
"""

from __future__ import annotations

import asyncio
import sys

from bleak import BleakClient, BleakScanner

# --------------------------------------------------------------------------- #
# GATT layout (verified live on the HID MultiClass SE reader)
# --------------------------------------------------------------------------- #
SEOS_SERVICE = "00009800-0000-1000-8000-00177a000002"
SEOS_DATA_CHAR = "0000aa00-0000-1000-8000-00177a000002"
CCCD = "00002902-0000-1000-8000-00805f9b34fb"

# --------------------------------------------------------------------------- #
# SEOS constants (com.assaabloy.seos.access)
# --------------------------------------------------------------------------- #
# CLA
CLA_STD = 0x00
CLA_PROP = 0x80

# INS
INS_SELECT_AID = 0xA4
INS_SELECT_ADF = 0xA5
INS_AUTHENTICATE = 0x87
INS_CORE_ADMINISTRATION = 0x15
INS_FS_OPS = 0xE6
INS_GET_DATA = 0xCD
INS_PUT_DATA = 0xDD
INS_GEN_ASYMMETRIC_KEY_PAIR = 0x47
INS_REMOVE = 0xED
INS_RESPONSE = 0xC0
INS_AMR = 0x41

# Applet AIDs (com.assaabloy.seos.access.util.SeosConstants)
SEOS_AID = bytes.fromhex("A0000004400001010001")
FILE_SYSTEM_AID = bytes.fromhex("A0000004400002010001")
MOBILE_KEYS_OID_ROOT = bytes.fromhex("2A8570811E10")
INIT_FILESYSTEM_PARAMS = bytes.fromhex("1F40 0A A0000004400002010001 00 0400 0400 00 0400".replace(" ", ""))

# Status words
SW_NO_ERROR = 0x9000
SW_BYTES_REMAINING = 0x6100


def _sw_name(sw: int) -> str:
    table = {
        0x9000: "NO_ERROR",
        0x6100: "BYTES_REMAINING",
        0x6310: "MORE_DATA_AVAILABLE",
        0x6700: "WRONG_LENGTH",
        0x6B00: "WRONG_P1P2",
        0x6C00: "CORRECT_LE",
        0x6D00: "INS_NOT_SUPPORTED",
        0x6E00: "CLA_NOT_SUPPORTED",
        0x6F00: "NO_PRECISE_DIAGNOSIS",
        0x6982: "SECURITY_STATUS_NOT_SATISFIED",
        0x6983: "FILE_INVALID",
        0x6984: "DATA_INVALID",
        0x6985: "CONDITIONS_NOT_SATISFIED",
        0x6986: "COMMAND_NOT_ALLOWED",
        0x6987: "SECURE_MESSAGING_OBJECT_MISSING",
        0x6988: "SECURE_MESSAGING_INCORRECT",
        0x6999: "APPLET_SELECT_FAILED",
        0x6A80: "WRONG_DATA",
        0x6A81: "FUNC_NOT_SUPPORTED",
        0x6A82: "FILE_NOT_FOUND",
        0x6A83: "RECORD_NOT_FOUND",
        0x6A84: "FILE_FULL",
        0x6A86: "INCORRECT_P1P2",
        # SEOS applet-specific (proprietary)
        0xE105: "SEOS_APPLET_STATE (no applet selected / not installed)",
        0xE106: "SEOS_DATA_OBJECT_NOT_FOUND",
    }
    if 0xE000 <= sw <= 0xEFFF:
        return f"SEOS_PROPRIETARY_{sw:04X}"
    return "UNKNOWN"


class ApduError(RuntimeError):
    def __init__(self, cmd_hex: str, sw: int, data: bytes):
        self.cmd_hex = cmd_hex
        self.sw = sw
        self.data = data
        super().__init__(f"APDU {cmd_hex} -> SW={sw:04X} ({_sw_name(sw)}) data={data.hex()}")


# --------------------------------------------------------------------------- #
# SEOS TLV / object parsing (reverse-engineered from the SDK)
# --------------------------------------------------------------------------- #
def seos_tag_bytes(tag_int: int) -> bytes:
    """Encode a SEOS tag int to its wire bytes (trim leading zeros of the short)."""
    b = (tag_int & 0xFFFF).to_bytes(2, "big")
    if len(b) == 2 and b[0] == 0 and b[1] != 0:
        b = b[1:]
    return b


def parse_seos_tlvs(buf: bytes) -> list[tuple[int, bytes]]:
    """Parse a sequence of SEOS objects: <tag(1-2B)> <len> <data>.

    Returns a list of (tag_int, data_bytes) in order. Tolerates trailing junk.
    """
    out = []
    i = 0
    n = len(buf)
    while i < n:
        # tag: 1 byte; if bit5 (0x20) set, the tag is 2 bytes long
        first = buf[i]
        if first & 0x20:
            if i + 2 > n:
                break
            tag = (buf[i] << 8) | buf[i + 1]
            i += 2
        else:
            tag = first
            i += 1
        if i >= n:
            break
        ln = buf[i]
        i += 1
        if ln > n - i:
            ln = n - i
        data = buf[i:i + ln]
        i += ln
        out.append((tag, data))
    return out


def _fmt_oid(oid: bytes) -> str:
    """Render an OID byte string in dotted decimal (best effort)."""
    if not oid:
        return "<empty>"
    try:
        parts = []
        first = oid[0]
        parts.append(f"{first // 40}.{first % 40}")
        val = 0
        for b in oid[1:]:
            val = (val << 7) | (b & 0x7F)
            if not (b & 0x80):
                parts.append(str(val))
                val = 0
        return ".".join(parts)
    except Exception:
        return oid.hex()


def build_apdu(cla: int, ins: int, p1: int, p2: int, data: bytes = b"", le: int | None = None) -> bytes:
    """Build a short/extended SEOS APDU command (CLA INS P1 P2 [Lc data] [Le])."""
    out = bytes([cla & 0xFF, ins & 0xFF, p1 & 0xFF, p2 & 0xFF])
    if data:
        if len(data) > 255:
            raise ValueError("data too long for this builder (use extended)")
        out += bytes([len(data)]) + data
    if le is not None:
        out += bytes([le & 0xFF])
    return out


def parse_response(buf: bytes) -> tuple[bytes, int]:
    """Split a reader response into (data, status_word)."""
    if len(buf) < 2:
        raise ApduError("<cmd>", 0xFFFF, buf)
    return buf[:-2], buf[-2] << 8 | buf[-1]


class SeosBle:
    """BLE transport + APDU exchange for a SEOS reader."""

    def __init__(self, address: str, timeout: float = 5.0, mtu: int = 247):
        self.address = address
        self.timeout = timeout
        self.mtu = mtu
        self._client: BleakClient | None = None
        self._rx: asyncio.Queue[bytes] = asyncio.Queue()
        self._lock = asyncio.Lock()

    # -- connection -------------------------------------------------------- #
    async def __aenter__(self) -> "SeosBle":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.disconnect()

    async def connect(self) -> None:
        self._client = BleakClient(self.address, timeout=30)
        await self._client.connect()
        # enable notifications on the SEOS data characteristic
        await self._client.start_notify(SEOS_DATA_CHAR, self._on_notify)
        # request a larger MTU so APDUs fit in one write (best effort)
        try:
            await self._client._backend._acquire_mtu(self.mtu)
        except Exception:
            pass
        self.log(f"connected to {self.address}; MTU={self._client.mtu_size}")

    async def disconnect(self) -> None:
        if self._client:
            try:
                await self._client.disconnect()
            except Exception:
                pass
            self._client = None

    def _on_notify(self, _char, data: bytearray) -> None:
        self._rx.put_nowait(bytes(data))

    @property
    def mtu_payload(self) -> int:
        return max(3, (self._client.mtu_size if self._client else 23) - 3)

    def log(self, msg: str) -> None:
        print(f"[seos] {msg}")

    # -- APDU exchange ----------------------------------------------------- #
    def _flush_rx(self) -> None:
        while not self._rx.empty():
            self._rx.get_nowait()

    async def _read_response(self, timeout: float) -> tuple[bytes, int]:
        buf = await asyncio.wait_for(self._rx.get(), timeout)
        data, sw = parse_response(buf)
        self.log(f"<< {buf.hex(' ')}  (SW={sw:04X} {_sw_name(sw)})")
        return data, sw

    async def exchange(self, apdu: bytes, timeout: float | None = None) -> tuple[bytes, int]:
        """Send one APDU, wait for the response, follow 0x61xx (more data) if needed."""
        timeout = timeout or self.timeout
        async with self._lock:
            self._flush_rx()
            self.log(f">> {apdu.hex(' ')}")
            await self._client.write_gatt_char(SEOS_DATA_CHAR, apdu, response=False)
            data, sw = await self._read_response(timeout)
            # follow "response bytes remaining" (0x61xx)
            while (sw & 0xFFF0) == 0x6100:
                remaining = sw & 0x00FF
                self.log(f"... more data available (~{remaining} bytes); GET RESPONSE")
                self._flush_rx()
                gr = build_apdu(CLA_STD, INS_RESPONSE, 0x00, 0x00, le=remaining or 0xFF)
                await self._client.write_gatt_char(SEOS_DATA_CHAR, gr, response=False)
                more, sw = await self._read_response(timeout)
                data += more
            if sw != SW_NO_ERROR:
                raise ApduError(apdu.hex(), sw, data)
            return data, sw

    # -- high level commands ---------------------------------------------- #
    async def select_applet(self, aid: bytes = SEOS_AID) -> tuple[bytes, int]:
        """SELECT by AID: 00 A4 04 00 <aid> 00"""
        return await self.exchange(build_apdu(CLA_STD, INS_SELECT_AID, 0x04, 0x00, aid, le=0x00))

    async def get_data(self, tag: int) -> tuple[bytes, int]:
        """GET DATA: 00 CD 3F FF <tag>"""
        return await self.exchange(build_apdu(CLA_STD, INS_GET_DATA, 0x3F, 0xFF, bytes([tag])))

    async def put_data(self, payload: bytes) -> tuple[bytes, int]:
        """PUT DATA: 00 DD 3F FF <data>"""
        return await self.exchange(build_apdu(CLA_STD, INS_PUT_DATA, 0x3F, 0xFF, payload))

    async def get_challenge(self, p2: int = 0x00, data: bytes = b"") -> tuple[bytes, int]:
        """GET CHALLENGE / AUTHENTICATE: 00 87 <p1> <p2> <data>"""
        return await self.exchange(build_apdu(CLA_STD, INS_AUTHENTICATE, 0x00, p2, data))

    async def ake(self, p1: int = 0x01) -> tuple[bytes, int]:
        """AKE key establishment: 00 87 <p1> <p2>"""
        return await self.exchange(build_apdu(CLA_STD, INS_AUTHENTICATE, p1, 0x00))

    async def core_admin(self, p1: int, p2: int, data: bytes = b"") -> tuple[bytes, int]:
        """CORE ADMINISTRATION: 80 15 <p1> <p2> [data]"""
        return await self.exchange(build_apdu(CLA_PROP, INS_CORE_ADMINISTRATION, p1, p2, data))

    async def init_filesystem(self, params: bytes = INIT_FILESYSTEM_PARAMS) -> tuple[bytes, int]:
        """INITIALIZE FILESYSTEM: 80 E6 00 00 <params>"""
        return await self.exchange(build_apdu(CLA_PROP, INS_FS_OPS, 0x00, 0x00, params))

    async def clear_filesystem(self) -> tuple[bytes, int]:
        """CLEAR FILESYSTEM: 80 E6 01 00"""
        return await self.exchange(build_apdu(CLA_PROP, INS_FS_OPS, 0x01, 0x00))

    # -- filesystem / ADF -------------------------------------------------- #
    async def list_adfs(self, include_metadata: bool = True, only_changed: bool = False) -> tuple[bytes, int]:
        """LIST ADFs: 80 15 01 <P2> 02 06 00 00  (data 06 00 = select-all OID, Le=00).

        P2 bit0 = includeMetadata, bit1 = onlyChangedAdfs.
        Response: sequence of Oid objects, each optionally followed by a
        Metadata object (if include_metadata).
        """
        p2 = (0x01 if include_metadata else 0x00) | (0x02 if only_changed else 0x00)
        return await self.exchange(build_apdu(CLA_PROP, INS_CORE_ADMINISTRATION, 0x01, p2, b"\x06\x00", le=0x00))

    async def select_adf(self, oid: bytes, relative: bool = False, p2: int = 0x00) -> tuple[bytes, int]:
        """SELECT ADF: 80 A5 04 <P2> <Lc> <06|0D> <oidlen> <oid> 00"""
        tag = 0x0D if relative else 0x06
        data = bytes([tag, len(oid)]) + oid
        return await self.exchange(build_apdu(CLA_PROP, INS_SELECT_ADF, 0x04, p2, data, le=0x00))

    async def select_global_adf(self, p2: int = 0x00) -> tuple[bytes, int]:
        """SELECT GLOBAL ADF: 80 A5 07 <P2> 00"""
        return await self.exchange(build_apdu(CLA_PROP, INS_SELECT_ADF, 0x07, p2, b"", le=0x00))

    async def read_object(self, tag: bytes) -> tuple[bytes, int]:
        """GET DATA (current file object by tag): 00 CD 3F FF <tag> 00"""
        return await self.exchange(build_apdu(CLA_STD, INS_GET_DATA, 0x3F, 0xFF, tag, le=0x00))

    async def open_session(self, aid: bytes = SEOS_AID) -> tuple[bytes, int]:
        """Open a SEOS session: SELECT the applet, tolerating applet-state SWs."""
        try:
            return await self.select_applet(aid)
        except ApduError as e:
            self.log(f"SELECT -> SW={e.sw:04X} ({_sw_name(e.sw)}); continuing")
            return e.data, e.sw

    async def dump_config(self) -> dict:
        """Unauthenticated full-config read of the reader.

        Steps:
          1. SELECT the SEOS applet
          2. LIST all ADFs (with metadata)
          3. For each ADF: SELECT it, then read its SEOS objects via GET DATA
        Returns a structured dict; also prints a human-readable report.
        """
        report: dict = {"select": None, "adfs": []}

        # 1. open the applet
        try:
            sel_data, sel_sw = await self.open_session()
            report["select"] = {"sw": sel_sw, "name": _sw_name(sel_sw), "data": sel_data.hex()}
        except ApduError as e:
            report["select"] = {"sw": e.sw, "name": _sw_name(e.sw), "data": e.data.hex()}

        # 2. list ADFs (with metadata)
        try:
            list_data, list_sw = await self.list_adfs(include_metadata=True)
        except ApduError as e:
            list_data, list_sw = e.data, e.sw
        report["list_sw"] = list_sw
        entries = parse_seos_tlvs(list_data)
        # entries alternate: Oid (tag 6) [ , Metadata (tag 0xFF41) ]
        i = 0
        adfs = []
        while i < len(entries):
            tag, data = entries[i]
            if tag == 6:  # Oid
                oid = data
                meta = None
                if i + 1 < len(entries) and entries[i + 1][0] == 0xFF41:
                    meta = entries[i + 1][1]
                    i += 1
                adfs.append({"oid": oid, "oid_str": _fmt_oid(oid), "meta": meta.hex() if meta else None})
            i += 1
        report["adfs"] = adfs

        # 3. per-ADF content read (best effort, unauthenticated)
        for a in adfs:
            a["content"] = None
            try:
                await self.select_adf(a["oid"])
            except ApduError as e:
                a["select_sw"] = e.sw
                continue
            # try to read the ADF's objects; the ADF body is a sequence of
            # SEOS objects, read via GET DATA on the current file.
            try:
                content, csw = await self.read_object(b"\x06")
                a["content"] = content.hex()
                a["content_sw"] = csw
            except ApduError as e:
                a["content_sw"] = e.sw

        _print_config_report(self.address, report)
        return report

    async def configure(self, tag: int = 0x06) -> dict:
        """
        High-level 'configure the reader' flow:
          1. open SEOS session (SELECT applet)
          2. read current configuration (GET DATA tag)
        Returns a dict describing each step's result.
        """
        steps = {}
        sel_data, sel_sw = await self.open_session()
        steps["select"] = {"sw": sel_sw, "name": _sw_name(sel_sw), "data": sel_data.hex()}
        try:
            g_data, g_sw = await self.get_data(tag)
            steps["get_data"] = {"sw": g_sw, "name": _sw_name(g_sw), "data": g_data.hex()}
        except ApduError as e:
            steps["get_data"] = {"sw": e.sw, "name": _sw_name(e.sw), "data": e.data.hex()}
        return steps


# --------------------------------------------------------------------------- #
# Human-readable report
# --------------------------------------------------------------------------- #
def _print_config_report(addr: str, report: dict) -> None:
    print("\n" + "=" * 68)
    print(f"  SEOS READER CONFIG DUMP   (unauthenticated)   {addr}")
    print("=" * 68)
    sel = report.get("select")
    if sel:
        print(f"  SELECT applet      : SW={sel['sw']:04X} ({sel['name']})")
        print(f"                       data={sel['data']}")
    print(f"  LIST ADFs          : SW={report.get('list_sw', 0):04X}")
    adfs = report.get("adfs", [])
    print(f"\n  Files (ADFs) found: {len(adfs)}")
    print("-" * 68)
    if not adfs:
        print("  (none listed — applet may need selection or AKE for full read)")
    for idx, a in enumerate(adfs, 1):
        print(f"  [{idx}] OID          : {a['oid_str']}  (raw {a['oid'].hex()})")
        if a.get("meta"):
            print(f"      metadata     : {a['meta']}")
        if a.get("select_sw") is not None:
            print(f"      select       : SW={a['select_sw']:04X} ({_sw_name(a['select_sw'])})")
        if a.get("content"):
            print(f"      content      : {a['content']}")
        if a.get("content_sw") is not None:
            print(f"      read         : SW={a['content_sw']:04X} ({_sw_name(a['content_sw'])})")
    print("=" * 68)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
async def scan(name: str | None = None, seconds: int = 10) -> None:
    print(f"Scanning for {name or '<any>'} for {seconds}s ...")

    def cb(dev, adv):
        nm = getattr(adv, "local_name", None) or getattr(dev, "name", None) or ""
        if name and name.lower() not in nm.lower():
            return
        rssi = getattr(adv, "rssi", None)
        print(f"  {dev.address}  name={nm!r}  rssi={rssi}")

    await BleakScanner.discover(detection_callback=cb, timeout=seconds)


async def run(addr: str, cmd: str, arg: str | None) -> int:
    async with SeosBle(addr) as s:
        if cmd == "dump":
            await s.dump_config()
            return 0
        if cmd == "listadfs":
            data, sw = await s.list_adfs(include_metadata=True)
            print(f"\nLIST ADFs -> SW={sw:04X} ({_sw_name(sw)})")
            print(f"  raw: {data.hex(' ')}")
            for tag, d in parse_seos_tlvs(data):
                kind = "OID" if tag == 6 else ("METADATA" if tag == 0xFF41 else f"tag={tag:04X}")
                extra = f"  oid={_fmt_oid(d)}" if tag == 6 else ""
                print(f"  {kind}: {d.hex(' ')}{extra}")
            return 0
        if cmd == "configure":
            steps = await s.configure(int(arg, 16) if arg else 0x06)
            import json
            print("\nCONFIGURE RESULT")
            print(json.dumps(steps, indent=2))
            return 0
        if cmd == "open":
            data, sw = await s.open_session()
            print(f"\nSELECT -> SW={sw:04X} ({_sw_name(sw)}) data={data.hex(' ')}")
            return 0
        try:
            if cmd == "select":
                data, sw = await s.select_applet()
            elif cmd == "getdata":
                data, sw = await s.get_data(int(arg, 16) if arg else 0x06)
            elif cmd == "putdata":
                data, sw = await s.put_data(bytes.fromhex(arg))
            elif cmd == "challenge":
                data, sw = await s.get_challenge()
            elif cmd == "ake":
                data, sw = await s.ake()
            elif cmd == "initfs":
                data, sw = await s.init_filesystem()
            elif cmd == "clearfs":
                data, sw = await s.clear_filesystem()
            else:
                data, sw = await s.exchange(build_apdu(int(cmd[:2], 16), int(cmd[2:4], 16), int(cmd[4:6], 16), int(cmd[6:8], 16), bytes.fromhex(arg) if arg else b""))
            print(f"\nRESULT  data={data.hex(' ')}  SW={sw:04X} ({_sw_name(sw)})")
            return 0 if sw == SW_NO_ERROR else 1
        except ApduError as e:
            print(f"\nAPDU error: {e}")
            return 2
        except Exception as e:
            print(f"\n{type(e).__name__}: {e}")
            return 3


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    if args[0] == "scan":
        name = args[1] if len(args) > 1 and not args[1].startswith("--") else "Seos"
        asyncio.run(scan(name))
        return

    addr = None
    i = 0
    rest = []
    while i < len(args):
        if args[i] == "--addr" and i + 1 < len(args):
            addr = args[i + 1]
            i += 2
            continue
        rest.append(args[i])
        i += 1
    if not addr:
        addr = "C0:60:33:15:2B:31"
    cmd = rest[0] if rest else "select"
    arg = rest[1] if len(rest) > 1 else None
    sys.exit(asyncio.run(run(addr, cmd, arg)))


if __name__ == "__main__":
    main()
