#!/usr/bin/env python3
"""Probe the reader's BLE FW_UPDATE (0xE2) extension path -- the one surface
PROTOCOL.md §11 says is 'deliberately NOT tested' because it is actively used by
the real app and its 4-byte ACK (84 82 00 00) 'is consistent with genuinely
initiating a firmware-flash sequence on success' (i.e. potentially destructive /
a reboot/DFU state we want to find).

Sequence:
  1. Connect, settle, observe spontaneous.
  2. Send 0xE2 + REQUEST_INIT_FLASH (84 00). If the reader ACKs with
     84 82 00 00 it has entered the firmware-flash sub-protocol.
  3. Once (maybe) in flash mode, drive it with malformed / boundary flash
     fragments and watch for: a hang, a drop, a stop-advertising (reboot), or a
     re-advertise after a gap.
  4. Report the reader's final state (still advertising? reboot? DFU-stuck?).

Usage: python3 tools/fuzz_fwupdate.py <MAC> [-v]
"""
import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hid_rm import DATA_CHAR_UUID, framing, seos

MAC_DEFAULT = "C0:60:33:15:2B:31"


async def reader_present(mac: str, timeout: float = 3.0) -> bool:
    from bleak import BleakScanner
    return mac in await BleakScanner.discover(timeout=timeout)


async def wait_reappear(mac: str, up_to: float = 60.0) -> tuple[bool, float]:
    t0 = time.monotonic()
    while time.monotonic() - t0 < up_to:
        await asyncio.sleep(1.0)
        if await reader_present(mac):
            return True, time.monotonic() - t0
    return False, up_to


async def main(mac: str, verbose: bool):
    from bleak import BleakClient
    sys.stdout.reconfigure(line_buffering=True)

    def log(*a):
        print(*a, flush=True)

    log(f"== FW_UPDATE (0xE2) probe: {mac} ==")

    rx, ev = [], asyncio.Event()

    def on_notify(_, d):
        rx.append(bytes(d)); ev.set()

    async def drain(t=2.5):
        try:
            await asyncio.wait_for(ev.wait(), timeout=t)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.05)
        frames = list(rx); rx.clear(); ev.clear()
        return frames

    async def send(b: bytes):
        await c.write_gatt_char(DATA_CHAR_UUID, b, response=False)
        await asyncio.sleep(0.05)

    c = BleakClient(mac)
    await c.connect()
    await c.start_notify(DATA_CHAR_UUID, on_notify)
    spont = await drain(2.5)
    for f in spont:
        log("  spontaneous <", f.hex(), seos.describe(f))

    log("\n[step 2] send 0xE2 + REQUEST_INIT_FLASH (84 00)")
    await send(seos.ext_frame(2, seos.REQUEST_INIT_FLASH))
    got = await drain(3.0)
    acked = False
    for f in got:
        log("  reader <", f.hex(), seos.describe(f))
        if f[1:3] == bytes.fromhex("84820000"):
            acked = True
    if not got:
        log("  (no reply to INIT_FLASH -- reader may have dropped the link or ignored it)")

    # If we got the flash-ACK, we are now (probably) in the firmware-flash
    # sub-protocol. Drive it with malformed fragments.
    flash_cases = [
        ("flash: empty fragment",        seos.ext_frame(2, b"")),
        ("flash: 1-byte garbage",        seos.ext_frame(2, b"\xaa")),
        ("flash: 20-byte garbage",       seos.ext_frame(2, b"\xaa" * 20)),
        ("flash: claims data, none",     seos.ext_frame(2, bytes.fromhex("84820000")) + seos.ext_frame(2, b"\xbb" * 8)),
        ("flash: huge 128B payload",     seos.ext_frame(2, b"\xcc" * 128)),
        ("flash: second INIT_FLASH",     seos.ext_frame(2, seos.REQUEST_INIT_FLASH)),
        ("flash: GET_PROPERTIES",        seos.ext_frame(2, seos.REQUEST_GET_PROPERTIES)),
        ("flash: GET_PROPERTIES2",       seos.ext_frame(2, seos.REQUEST_GET_PROPERTIES2)),
    ]

    crashed = None
    for name, payload in flash_cases:
        if not c.is_connected:
            log(f"\n  {name}: (link already down)")
            break
        log(f"\n  {name}:")
        try:
            await send(payload)
            got = await drain(2.5)
            for f in got:
                log("    reader <", f.hex(), seos.describe(f))
            if not got:
                log("    (no reply)")
        except Exception as e:
            log(f"    EXCEPTION: {type(e).__name__} {e}")
            crashed = name
            break
        await asyncio.sleep(0.3)

    # Final: is the reader still up? reboot?
    log("\n[final] checking reader state ...")
    try:
        await c.disconnect()
    except Exception:
        pass
    present = await reader_present(mac)
    if present:
        log(f"  reader still advertising (present now). state after: {c.is_connected and 'linked' or 'disconnected'}")
    else:
        log("  reader NOT advertising right now -- waiting for reappear (reboot?) ...")
        reappeared, secs = await wait_reappear(mac)
        log(f"  reader reappeared after {secs:.1f}s: {reappeared}  ->  REBOOT/DFU?")

    # One more scan after a beat to be sure
    await asyncio.sleep(2)
    log(f"  final present: {await reader_present(mac)}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("mac", nargs="?", default=MAC_DEFAULT)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    asyncio.run(main(args.mac, args.verbose))
