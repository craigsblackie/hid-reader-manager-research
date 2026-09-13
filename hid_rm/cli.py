"""hid_rm CLI - unauthenticated recon, functional reads, and robustness testing
of HID Reader Manager readers you own / are authorised to test.

By default every command prints a short, plain-language summary of what matters.
Add --verbose (or -v) anywhere in the arguments to also see the raw protocol
detail (hex frames, per-round transcripts, GATT dumps, request/response bytes).

Offline (no reader):
  python -m hid_rm.cli show snmp-discovery
  python -m hid_rm.cli show core <name>              # e.g. get_reader_info
  python -m hid_rm.cli show locate [seconds] [color]  # preview find-reader payload
  python -m hid_rm.cli list                          # list core commands
  python -m hid_rm.cli decode <payload-hex>          # decode an Artemis response
  python -m hid_rm.cli decode-snmp <hex>             # parse an SNMP Report
  python -m hid_rm.cli fuzz-list                      # list robustness cases

Live over BLE (needs `bleak`):
  python -m hid_rm.cli scan
  python -m hid_rm.cli probe <MAC>                    # connect, try safe reads
  python -m hid_rm.cli core <MAC> <name>              # send a core read, decode reply
  python -m hid_rm.cli locate <MAC> [seconds] [color]  # "find reader": flash + beep it
  python -m hid_rm.cli snmp-discover <MAC>
  python -m hid_rm.cli send <MAC> <apdu-hex>
  python -m hid_rm.cli fuzz <MAC> [name]              # robustness test, watch for crash
  python -m hid_rm.cli emulate <MAC> [cooldown_sec]   # log reader's own discovery sequence
  python -m hid_rm.cli leak <MAC> [cooldown] [out]    # config leak: decoded, human-readable
  python -m hid_rm.cli enumerate <MAC> [cooldown] [out]  # everything in one pass
  python -m hid_rm.cli flipper-probe [port]              # check Flipper NFC/BT capability, scan

Add --verbose / -v to any live command for full technical detail.
"""
import asyncio, sys
from . import framing, artemis, snmpv3, seos, fuzz, emulate, leak, recon, oid_db, flipper_cli, DATA_CHAR_UUID

INS = framing.INS_GET_DATA


def _split_verbose(args):
    """Pull --verbose/-v out of an argument list; return (clean_args, verbose_bool)."""
    verbose = False
    out = []
    for a in args:
        if a in ("--verbose", "-v"):
            verbose = True
        else:
            out.append(a)
    return out, verbose


def _apdu_frame(payload):
    return framing.frame(framing.build_apdu(INS, payload))


def cmd_show(a):
    if a[0] == "snmp-discovery":
        m = snmpv3.build_discovery()
        print("snmp   :", m.hex())
        print("framed :", _apdu_frame(m).hex())
    elif a[0] == "core":
        p = artemis.core_payload(a[1])
        print("payload:", p.hex(), "(DANGER: state-changing)" if artemis.is_dangerous(a[1]) else "")
        print("framed :", _apdu_frame(p).hex())
    elif a[0] == "locate":
        seconds = float(a[1]) if len(a) > 1 else 3.0
        color = a[2] if len(a) > 2 else "blue"
        p = artemis.locate_payload(seconds=seconds, color=color)
        print("payload:", p.hex())
        print("framed :", _apdu_frame(p).hex())


async def _connect(mac):
    from bleak import BleakClient
    rx = []
    disc = {"lost": False}
    ev = asyncio.Event()

    def on_notify(_, d):
        rx.append(bytes(d)); ev.set()

    def on_disc(_):
        disc["lost"] = True; ev.set()

    c = BleakClient(mac, disconnected_callback=on_disc)
    await c.connect()
    await c.start_notify(DATA_CHAR_UUID, on_notify)
    return c, rx, ev, disc


async def _drain(rx, ev, t=3.0):
    try:
        await asyncio.wait_for(ev.wait(), timeout=t)
    except asyncio.TimeoutError:
        pass
    await asyncio.sleep(0.6)
    frames = list(rx); rx.clear(); ev.clear()
    return frames


async def cmd_probe(mac, verbose=False):
    """Connect and try the small set of reads that might work pre-auth on some
    firmware. On this project's test reader all of these are blocked (see
    PROTOCOL.md §9) -- kept here so it shows real data if run against a
    different reader/firmware where they aren't gated the same way."""
    c, rx, ev, disc = await _connect(mac)
    spontaneous = await _drain(rx, ev, 3.0)
    results = []
    for label, payload in [("snmp-discovery", snmpv3.build_discovery())] + \
            [(n, artemis.CORE[n]) for n in ("get_version_info", "get_device_info",
             "get_reader_info", "get_board_revision", "get_chip_uid", "get_secure_element_mode")]:
        if not c.is_connected:
            results.append((label, None, "connection lost")); break
        await c.write_gatt_char(DATA_CHAR_UUID, _apdu_frame(payload), response=False)
        got = await _drain(rx, ev, 2.5)
        results.append((label, got, None))
    await c.disconnect()

    if not verbose:
        blocked = sum(1 for _, got, err in results if err or not got or
                      (got and got[0][:1] in (b"\x00", b"\x81")))
        print(f"Tried {len(results)} pre-auth reads: {blocked}/{len(results)} were blocked "
              f"(no authenticated session).")
        print("(run with --verbose to see each request/response)")
        return

    print(f"Spontaneous frames on connect: {len(spontaneous)}")
    for f in spontaneous:
        print("  <", f.hex())
    for label, got, err in results:
        print(f"\n>> {label}")
        if err:
            print("   ", err); continue
        for f in got or []:
            print("  <", f.hex(), " ", seos.describe(f))


async def cmd_core(mac, name, verbose=False):
    c, rx, ev, disc = await _connect(mac)
    await _drain(rx, ev, 2.0)
    await c.write_gatt_char(DATA_CHAR_UUID, _apdu_frame(artemis.core_payload(name)), response=False)
    got = await _drain(rx, ev, 3.0)
    await c.disconnect()
    if not got:
        print(f"{name}: no response (likely blocked -- needs an authenticated session)")
        return
    if not verbose:
        print(f"{name}: {seos.describe(got[-1])}")
        print("(run with --verbose for raw frames)")
        return
    for f in got:
        print("  <", f.hex(), " ", seos.describe(f))


async def cmd_locate(mac, seconds=3.0, color="blue", beep=True, verbose=False):
    """'Find reader': flash the LED and beep for `seconds`. Unauthenticated --
    this is CoreCommand.readerLocate (tag 36), not a credential/config command,
    and needs no session on this reader."""
    payload = artemis.locate_payload(seconds=seconds, color=color, beep=beep)
    if verbose:
        print("payload:", payload.hex())
        print("framed :", _apdu_frame(payload).hex())
    c, rx, ev, disc = await _connect(mac)
    await _drain(rx, ev, 2.0)
    await c.write_gatt_char(DATA_CHAR_UUID, _apdu_frame(payload), response=False)
    got = await _drain(rx, ev, 3.0)
    await c.disconnect()
    if not got:
        print(f"locate: no response -- reader may still have flashed/beeped "
              f"(ack-less write); no confirmation available")
        return
    if not verbose:
        print(f"locate: {seos.describe(got[-1])}")
        print(f"(reader should have flashed {color} and "
              f"{'beeped' if beep else 'stayed silent'} for {seconds:g}s)")
        return
    for f in got:
        print("  <", f.hex(), " ", seos.describe(f))


async def cmd_send(mac, hexstr, verbose=False):
    c, rx, ev, disc = await _connect(mac)
    await _drain(rx, ev, 2.0)
    await c.write_gatt_char(DATA_CHAR_UUID, framing.frame(bytes.fromhex(hexstr)), response=False)
    got = await _drain(rx, ev, 3.0)
    await c.disconnect()
    if not got:
        print("no response"); return
    for f in got:
        print("  <", f.hex(), " ", seos.describe(f) if verbose else "")


async def cmd_emulate(mac, cooldown=0.0, rounds=8, fci=True, verbose=False):
    """Act as the credential/admin-probe responder and log the reader's own
    discovery sequence (SELECT ADF candidates + special AIDs)."""
    from bleak import BleakClient
    if cooldown:
        await asyncio.sleep(cooldown)
    rx = []
    ev = asyncio.Event()

    def on_notify(_, data):
        rx.append(bytes(data)); ev.set()

    async def drain(t=3.0):
        try:
            await asyncio.wait_for(ev.wait(), timeout=t)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.5)
        frames = list(rx); rx.clear(); ev.clear()
        return frames

    c = BleakClient(mac)
    await c.connect()
    await c.start_notify(DATA_CHAR_UUID, on_notify)
    spontaneous = await drain(3.5)

    responder = emulate.CardEmulationResponder(fci_for_known_aids=fci)
    oids_seen, final_status = [], None
    transcript = []
    for round_n in range(1, rounds + 1):
        if not c.is_connected:
            break
        got = await drain(3.0)
        if not got:
            break
        is_eot = any((f[0] & 0xE0) == 0xE0 for f in got)
        transcript.append(("recv", got))
        if is_eot:
            final_status = seos.EOT_STATUS.get(got[-1][1], got[-1][1])
            break
        buf = framing.ble_reassemble(got)
        if not buf:
            continue
        from . import leak as leak_mod
        oids_seen.extend(d for d in leak_mod.parse_select_adf(buf) if d not in oids_seen)
        reply = responder.reply_for(buf)
        transcript.append(("sent", reply))
        for fr in framing.ble_fragment(reply):
            await c.write_gatt_char(DATA_CHAR_UUID, fr, response=False)
            await asyncio.sleep(0.05)
    try:
        await c.disconnect()
    except Exception:
        pass

    if not verbose:
        summary = oid_db.summarize(oids_seen)
        total = summary["standard_count"] + summary["custom_count"]
        aid_names = [n for n, _ in responder.log if n != "?"]
        print(f"Reader discovery sequence: {len(responder.log)} exchange(s), "
              f"{total} credential profile(s) offered, result: {final_status or 'incomplete'}")
        if aid_names:
            print(f"Modes/AIDs seen: {', '.join(dict.fromkeys(aid_names))}")
        print("(run with --verbose for the full frame-by-frame transcript)")
        return

    print(f"[spontaneous] {len(spontaneous)} frame(s)")
    for f in spontaneous:
        print("  <", f.hex())
    for direction, payload in transcript:
        if direction == "recv":
            for f in payload:
                print("  <", f.hex())
        else:
            print("  ->", payload.hex())
    print("\nresponder log:", responder.log)
    print("final status:", final_status)


async def cmd_enumerate(mac, cooldown=0.0, out_prefix=None, verbose=False):
    """Run the full unified reconnaissance pass (recon.py) and print/save it."""
    report = await recon.enumerate_reader(mac, cooldown=cooldown)
    print(recon.render_summary(report, verbose=verbose))
    if out_prefix:
        import json
        with open(f"{out_prefix}.json", "w") as f:
            json.dump(report, f, indent=2)
        with open(f"{out_prefix}.txt", "w") as f:
            f.write(recon.render_summary(report, verbose=True))
        print(f"\nsaved: {out_prefix}.json  {out_prefix}.txt")


async def cmd_leak(mac, cooldown=0.0, out_prefix=None, verbose=False):
    """Run the unauthenticated config-leak collector and print/save a report."""
    collector = await leak.run_leak(mac, cooldown=cooldown)
    print(collector.render_text(verbose=verbose))
    if out_prefix:
        import json
        with open(f"{out_prefix}.txt", "w") as f:
            f.write(collector.render_text(verbose=True))
        with open(f"{out_prefix}.json", "w") as f:
            json.dump(collector.report(), f, indent=2)
        print(f"\nsaved: {out_prefix}.txt  {out_prefix}.json")


async def cmd_fuzz(mac, only=None, cooldown=2.0, verbose=False):
    """Send robustness cases one per fresh connection, replacing the normal '9000'
    reply to the reader's own spontaneous SELECT with the fuzz payload. Flags
    disconnect (possible crash/reboot) or stall (no reply)."""
    results = []
    for name, frags, note in fuzz.cases():
        if only and name != only:
            continue
        try:
            c, rx, ev, disc = await _connect(mac)
        except Exception as e:
            results.append((name, "CONNECT-FAIL", str(e), note)); continue
        spontaneous = await _drain(rx, ev, 3.0)
        if not spontaneous:
            results.append((name, "SKIPPED", "reader quiet (cooldown?)", note))
            try: await c.disconnect()
            except Exception: pass
            await asyncio.sleep(cooldown)
            continue
        outcome, detail = "OK", ""
        try:
            for i, fr in enumerate(frags):
                await c.write_gatt_char(DATA_CHAR_UUID, fr, response=False)
                if name == "reply_then_immediate_disconnect" and i == len(frags) - 1:
                    await c.disconnect()
                    outcome, detail = "OK", "disconnected immediately after write"
                    break
                await asyncio.sleep(0.05)
            else:
                got = await _drain(rx, ev, 2.5)
                detail = seos.describe(got[-1]) if got else "NO-RESPONSE"
                if disc["lost"] or not c.is_connected:
                    outcome = "CRASH?"
                elif not got:
                    outcome = "STALL?"
        except Exception as e:
            outcome, detail = "CRASH?", f"{type(e).__name__}"
        results.append((name, outcome, detail, note))
        try:
            await c.disconnect()
        except Exception:
            pass
        await asyncio.sleep(cooldown)

    crashes = [r for r in results if r[1] in ("CRASH?", "STALL?")]
    if not verbose:
        print(f"Robustness test: {len(results)} case(s) run, "
              f"{len(results) - len(crashes)} handled safely, {len(crashes)} flagged for review.")
        for name, outcome, detail, note in crashes:
            print(f"  ! {name}: {outcome} -- {detail}")
        if not crashes:
            print("No crash, reboot, or hang found in this run.")
        print("(run with --verbose for the full per-case detail)")
        return
    for name, outcome, detail, note in results:
        flag = f"  <-- {outcome}" if outcome not in ("OK", "SKIPPED") else ""
        print(f"{name:32} {detail}{flag}   ({note})")


def cmd_flipper_probe(port=None, verbose=False):
    """Probe a connected Flipper Zero's actual CLI capabilities (device info,
    bt/nfc command surface) and run its passive NFC scanner against whatever's
    in range -- confirms live whether a target answers as a passive tag (our
    access-control readers do not; see flipper_cli.py)."""
    p = port or flipper_cli.DEFAULT_PORT
    caps = flipper_cli.probe_capabilities(p)
    excerpt = caps["device_info_excerpt"]
    nfc_status = "available" if caps["nfc_present"] else "not found"
    print(f"Flipper at {p}: {excerpt}")
    print(f"NFC CLI: {nfc_status}   BT CLI: hci_info only (no general BLE-central scripting)")
    with flipper_cli.FlipperCLI(p) as f:
        out = f.nfc_scanner(settle=3.0)
    detected = "Protocols detected: " in out and out.split("Protocols detected:")[1].split("\n")[0].strip()
    if detected:
        print(f"NFC scan: target detected -- {detected}")
    else:
        print("NFC scan: nothing detected (expected against our reader -- it only "
              "acts as an initiator, never a passive tag; see PROTOCOL.md)")
    if verbose:
        print("\n--- raw ---")
        print(caps["top_level_commands"])
        print(out)


def main(argv):
    argv, verbose = _split_verbose(argv)
    if not argv:
        print(__doc__); return
    cmd, a = argv[0], argv[1:]
    if cmd == "show":
        cmd_show(a)
    elif cmd == "list":
        for n in artemis.CORE:
            print(("! " if artemis.is_dangerous(n) else "  ") + n)
    elif cmd == "decode":
        print(artemis.decode_response(bytes.fromhex(a[0].replace(" ", ""))))
    elif cmd == "decode-snmp":
        for k, v in snmpv3.parse_report(bytes.fromhex(a[0].replace(" ", ""))).items():
            print(f"  {k}: {v}")
    elif cmd == "fuzz-list":
        for name, frags, note in fuzz.cases():
            print(f"{name:32} {sum(len(f) for f in frags):4}B  {note}")
    elif cmd == "scan":
        from bleak import BleakScanner
        async def s():
            for d in await BleakScanner.discover(timeout=8.0):
                print(f"  {d.address}  {d.name}")
        asyncio.run(s())
    elif cmd == "probe":
        asyncio.run(cmd_probe(a[0], verbose=verbose))
    elif cmd == "core":
        asyncio.run(cmd_core(a[0], a[1], verbose=verbose))
    elif cmd == "locate":
        asyncio.run(cmd_locate(a[0], seconds=float(a[1]) if len(a) > 1 else 3.0,
                                color=a[2] if len(a) > 2 else "blue", verbose=verbose))
    elif cmd == "snmp-discover":
        asyncio.run(cmd_send(a[0], framing.build_apdu(INS, snmpv3.build_discovery()).hex(), verbose=verbose))
    elif cmd == "send":
        asyncio.run(cmd_send(a[0], a[1], verbose=verbose))
    elif cmd == "fuzz":
        asyncio.run(cmd_fuzz(a[0], a[1] if len(a) > 1 else None, verbose=verbose))
    elif cmd == "emulate":
        asyncio.run(cmd_emulate(a[0], cooldown=float(a[1]) if len(a) > 1 else 0.0, verbose=verbose))
    elif cmd == "leak":
        asyncio.run(cmd_leak(a[0], cooldown=float(a[1]) if len(a) > 1 else 0.0,
                              out_prefix=a[2] if len(a) > 2 else None, verbose=verbose))
    elif cmd == "enumerate":
        asyncio.run(cmd_enumerate(a[0], cooldown=float(a[1]) if len(a) > 1 else 0.0,
                                   out_prefix=a[2] if len(a) > 2 else None, verbose=verbose))
    elif cmd == "flipper-probe":
        cmd_flipper_probe(a[0] if a else None, verbose=verbose)
    else:
        print("unknown:", cmd); print(__doc__)


if __name__ == "__main__":
    main(argv=sys.argv[1:])
