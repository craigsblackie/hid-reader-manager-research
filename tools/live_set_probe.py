#!/usr/bin/env python3
"""Live, reversible-by-construction probe: does the reader enforce
authentication on SNMPv3 SET (config write), the way it demonstrably does
NOT on plain-config GET (see PROTOCOL.md §30-32)?

Safety design -- this is the one live test in the toolkit that touches a WRITE
path, so it is built to be a no-op even if it "succeeds":

  1. GET the current value of a chosen OID via noAuthNoPriv (same as
     config-probe).
  2. SET that *same OID to that exact same value* via noAuthNoPriv (no keys).
     If the reader is not auth-gated on writes, this "changes" the config to
     what it already was -- a real acceptance is observable (an ack, not a
     Report/error) without altering reader state.
  3. Report ACCEPTED (write path is NOT auth-gated -- a real finding) vs
     REFUSED/no-response (write path IS gated, consistent with the app's own
     authPriv-only SET builder).

Defaults to the plain, non-dangerous MEDIA_OUTPUT item. Never targets a
DANGEROUS-flagged OID (config_oids.py) or writes a value other than the one
just read. Requires --confirm to actually transmit the SET; without it, only
the GET (read-only) half runs and the SET is printed, not sent.

Usage:
    python3 tools/live_set_probe.py <MAC> [--oid NAME_OR_HEX] [--confirm] [-v]
"""
import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hid_rm import framing, snmpv3, config_oids
from hid_rm.cli import _connect, _drain, _discover_engine, _snmp_exchange, _oid_bytes  # reuse the real session plumbing

DEFAULT_OID = "MEDIA_OUTPUT"  # plain config, not DANGEROUS, single-byte value


async def main(mac: str, oid_name: str, confirm: bool, verbose: bool):
    oid_bytes = _oid_bytes(oid_name)
    hex_oid = oid_bytes.hex() if isinstance(oid_bytes, (bytes, bytearray)) else oid_name
    info = config_oids.CONFIG_OIDS.get(hex_oid.upper()) if isinstance(hex_oid, str) else None
    if info and info[3]:
        print(f"refusing: {oid_name} is flagged DANGEROUS in config_oids.py -- pick a plain item")
        return 2

    print(f"== live_set_probe: {oid_name} against {mac} ==")
    c, rx, ev, disc = await _connect(mac)
    try:
        await _drain(rx, ev, 1.5)
        rep = await _discover_engine(c, rx, ev, verbose)
        if not rep:
            print("engine discovery failed (reader not answering SNMP discovery)")
            return 1

        # 1. Read current value, unauthenticated.
        get_msg = snmpv3.build_get(oid_bytes, engine_id=bytes.fromhex(rep["engine_id"]),
                                    user_name=b"", engine_boots=rep["engine_boots"],
                                    engine_time=rep["engine_time"])
        get_apdu = framing.build_apdu(framing.INS_GET_DATA, get_msg)
        get_data = await _snmp_exchange(c, rx, ev, get_apdu)
        if not get_data:
            print(f"GET: no response -- reader ignored the unauthenticated read; can't safely probe SET")
            return 1
        try:
            r = snmpv3.parse_secured_response(get_data, verify=False)
            vbs = [vb for vb in r["varbinds"] if vb["value"]]
        except Exception:
            vbs = []
        if not vbs:
            print(f"GET: reader refused/returned no value for {oid_name} -- can't safely probe SET "
                  f"(would have to write a value we don't actually know is current)")
            if verbose:
                print("  raw:", get_data.hex())
            return 1
        current_value = vbs[0]["value"]
        print(f"GET: current value = {current_value.hex()}  (read with NO keys, NO encryption)")

        # 2. Build the identical-value SET, unauthenticated.
        set_msg = snmpv3.build_set(oid_bytes, current_value, engine_id=bytes.fromhex(rep["engine_id"]),
                                    user_name=b"", engine_boots=rep["engine_boots"],
                                    engine_time=rep["engine_time"])
        set_apdu = framing.build_apdu(framing.INS_PUT_DATA, set_msg)

        if not confirm:
            print("\n(dry run -- pass --confirm to actually transmit the reversible SET)")
            print(f"  would SET {oid_name} = {current_value.hex()} (identical to current, via noAuthNoPriv)")
            return 0

        print("\nSending unauthenticated SET (writing back the SAME value we just read)...")
        set_data = await _snmp_exchange(c, rx, ev, set_apdu)
        if not set_data:
            print("SET: no response -- reader silently dropped the unauthenticated write "
                  "(consistent with write path being auth-gated)")
            return 0
        try:
            r = snmpv3.parse_secured_response(set_data, verify=False)
            vbs2 = [vb for vb in r["varbinds"] if vb["value"]]
            if vbs2:
                print(f"SET: *** ACCEPTED *** reader echoed back {vbs2[0]['value'].hex()} "
                      "-- write path is NOT auth-gated (finding)")
            else:
                print("SET: reader replied but with no value -- likely a Report/error "
                      "(refusal), i.e. write path IS auth-gated")
        except Exception:
            print(f"SET: reply did not parse as a value response ({len(set_data)}B) -- "
                  "likely a Report/error, i.e. write path IS auth-gated")
        if verbose:
            print("  raw:", set_data.hex())
        return 0
    finally:
        await c.disconnect()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mac")
    ap.add_argument("--oid", default=DEFAULT_OID, help=f"config-item name or hex OID (default: {DEFAULT_OID})")
    ap.add_argument("--confirm", action="store_true", help="actually transmit the SET (default: dry run, GET only)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(main(args.mac, args.oid, args.confirm, args.verbose)))
