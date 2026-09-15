#!/usr/bin/env python3
"""Pinpoint which 0xE2 FW_UPDATE extension frame(s) reboot the reader.

Sends ONE candidate frame per fresh connection, observes the reader's reply, then
checks whether the reader dropped out of advertising (reboot) vs stayed up. One
connection per case keeps the connection-lockout (§18) from confounding the result
and isolates the exact trigger.

Usage: python3 tools/fuzz_fw_isolate.py <MAC> [-v]
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


async def wait_reappear(mac: str, up_to: float = 90.0) -> tuple[bool, float]:
    t0 = time.monotonic()
    while time.monotonic() - t0 < up_to:
        await asyncio.sleep(1.0)
        if await reader_present(mac):
            return True, time.monotonic() - t0
    return False, up_to


# Candidates: name -> list of single-fragment writes to send in order.
CANDIDATES = [
    ("E2 INIT_FLASH only",          [seos.ext_frame(2, seos.REQUEST_INIT_FLASH)]),
    ("E2 empty",                    [seos.ext_frame(2, b"")]),
    ("E2 1-byte garbage",           [seos.ext_frame(2, b"\xaa")]),
    ("E2 20-byte garbage",          [seos.ext_frame(2, b"\xaa" * 20)]),
    ("E2 128-byte garbage",         [seos.ext_frame(2, b"\xcc" * 128)]),
    ("E2 INIT_FLASH + 20B garbage", [seos.ext_frame(2, seos.REQUEST_INIT_FLASH),
                                      seos.ext_frame(2, b"\xaa" * 20)]),
    ("E2 double INIT_FLASH",        [seos.ext_frame(2, seos.REQUEST_INIT_FLASH),
                                      seos.ext_frame(2, seos.REQUEST_INIT_FLASH)]),
    ("E2 INIT_FLASH + ACK",         [seos.ext_frame(2, seos.REQUEST_INIT_FLASH),
                                      seos.ext_frame(2, seos.REQUEST_INIT_FLASH_ACK)]),
]


async def test_one(mac: str, name: str, writes: list, verbose: bool) -> dict:
    from bleak import BleakClient
    rx, ev = [], asyncio.Event()

    def on_notify(_, d):
        rx.append(bytes(d)); ev.set()

    async def drain(t=2.0):
        try:
            await asyncio.wait_for(ev.wait(), timeout=t)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.05)
        frames = list(rx); rx.clear(); ev.clear()
        return frames

    result = {"case": name, "reply": "", "present_after": None, "reappear": None}
    c = BleakClient(mac)
    try:
        await c.connect()
        await c.start_notify(DATA_CHAR_UUID, on_notify)
        await drain(2.0)  # spontaneous SELECT
        replies = []
        for w in writes:
            try:
                await c.write_gatt_char(DATA_CHAR_UUID, w, response=False)
            except Exception as e:
                replies.append(f"WRITE-FAIL:{type(e).__name__}")
            g = await drain(2.0)
            if g:
                replies.append(",".join(seos.describe(f) for f in g))
            if not c.is_connected:
                break
        result["reply"] = " | ".join(replies)
    except Exception as e:
        result["reply"] = f"CONNECT/EXC: {type(e).__name__}"
    finally:
        try:
            await c.disconnect()
        except Exception:
            pass

    # reboot detection
    if await reader_present(mac):
        result["present_after"] = True
        result["reappear"] = "immediate"
    else:
        reappeared, secs = await wait_reappear(mac, up_to=90.0)
        result["present_after"] = reappeared
        result["reappear"] = f"{secs:.1f}s"
        if reappeared and secs > 3.0:
            result["verdict"] = "REBOOT"
        elif reappeared:
            result["verdict"] = "link-drop"
        else:
            result["verdict"] = "DARK"
    return result


async def main(mac: str, verbose: bool):
    from bleak import BleakClient
    sys.stdout.reconfigure(line_buffering=True)
    print(f"== 0xE2 FW_UPDATE isolate: {mac} ==")
    for name, writes in CANDIDATES:
        # ensure the reader is up before each case
        if not await reader_present(mac):
            print(f"  (waiting for reader before: {name}) ...", flush=True)
            reappeared, _ = await wait_reappear(mac)
            if not reappeared:
                print(f"  [skipped {name} -- reader dark]", flush=True)
                break
        r = await test_one(mac, name, writes, verbose)
        v = r.get("verdict", "OK/stable" if r["present_after"] else "DARK")
        print(f"\n  {name:30} reply: {r['reply'][:80]}", flush=True)
        print(f"  {'':30} present-after: {r['present_after']}  reappear: {r['reappear']}  ->  {v}", flush=True)
        # give the reader a breather between cases
        await asyncio.sleep(2.0)
    print("\n== done ==", flush=True)
    print("final present:", await reader_present(mac), flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mac", nargs="?", default=MAC_DEFAULT)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    asyncio.run(main(args.mac, args.verbose))
