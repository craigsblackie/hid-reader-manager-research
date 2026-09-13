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
  python -m hid_rm.cli tech <leak_report.json>       # credential technologies (KeyType terms)
  python -m hid_rm.cli settings [category]            # list reader config settings (name<->OID)
  python -m hid_rm.cli fuzz-list                      # list robustness cases

Live over BLE (needs `bleak`):
  python -m hid_rm.cli scan
  python -m hid_rm.cli probe <MAC>                    # connect, try safe reads
  python -m hid_rm.cli core <MAC> <name>              # send a core read, decode reply
  python -m hid_rm.cli locate <MAC> [seconds] [color]  # "find reader": flash + beep it
  python -m hid_rm.cli snmp-discover <MAC>
  python -m hid_rm.cli config-get <MAC> <oid> <authkey> <privkey> <user>   # authenticated read
  python -m hid_rm.cli config-set <MAC> <oid> <val> <authkey> <privkey> <user>  # authenticated write
  python -m hid_rm.cli config-apply <MAC> <msgfile> [read]   # replay a cloud/config-card SNMP package
  python -m hid_rm.cli config-probe <MAC> <oid>              # keyless (noAuthNoPriv) read test
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


def _oid_bytes(oid_or_name):
    """Resolve a config OID given as a setting name, a short hex config OID, or a
    dotted OID -> DER OID *content* bytes for the SNMP varbind."""
    from . import config_oids, oid as oidmod
    s = config_oids.resolve(oid_or_name)          # name -> hex OID (or passthrough)
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        return bytes.fromhex(s)                    # hex OID content (reader's short form)
    return oidmod.encode(s)                        # dotted OID


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


async def _snmp_exchange(c, rx, ev, apdu, timeout=4.0):
    """Send an ISO7816 APDU (SNMP-carrying) with ProtocolV1 BLE fragmentation,
    then reassemble the reader's fragmented reply and return the APDU data."""
    frame = framing.frame(apdu)
    for frag in framing.ble_fragment(frame):
        await c.write_gatt_char(DATA_CHAR_UUID, frag, response=False)
        await asyncio.sleep(0.02)
    got = await _drain(rx, ev, timeout)
    if not got:
        return None
    body = framing.ble_reassemble(got)
    if not body:
        return None
    try:
        _, data, _ = framing.parse_response(body)
        return data
    except Exception:
        return body


async def _discover_engine(c, rx, ev, verbose=False):
    apdu = framing.build_apdu(INS, snmpv3.build_discovery())
    data = await _snmp_exchange(c, rx, ev, apdu, timeout=3.0)
    if not data:
        return None
    rep = snmpv3.parse_report(data)
    if verbose:
        print(f"  engineId={rep['engine_id']} boots={rep['engine_boots']} time={rep['engine_time']}")
    return rep


async def cmd_config_get(mac, dotted_oid, auth_key, priv_key, user, verbose=False):
    """Authenticated config READ: discover engine params, then an SNMPv3 GET with
    your reader's Origo-issued auth/priv keys (see PROTOCOL.md §3). Keys are raw
    hex; supply them for a reader you own -- they are not derivable offline."""
    from . import oid as oidmod
    ak, pk = bytes.fromhex(auth_key), bytes.fromhex(priv_key)
    c, rx, ev, disc = await _connect(mac)
    await _drain(rx, ev, 1.5)
    rep = await _discover_engine(c, rx, ev, verbose)
    if not rep:
        await c.disconnect(); print("discovery failed (no engine params) -- reader unreachable?"); return
    msg = snmpv3.build_get(_oid_bytes(dotted_oid), engine_id=bytes.fromhex(rep["engine_id"]),
                           user_name=user.encode(), engine_boots=rep["engine_boots"],
                           engine_time=rep["engine_time"], auth_key=ak, priv_key=pk)
    apdu = framing.build_apdu(framing.INS_GET_DATA, msg)
    data = await _snmp_exchange(c, rx, ev, apdu)
    await c.disconnect()
    if not data:
        print("no response to authenticated GET (wrong keys, or write/read gated?)"); return
    try:
        r = snmpv3.parse_secured_response(data, auth_key=ak, priv_key=pk)
    except Exception as e:
        print(f"response failed to verify/decrypt: {e}");
        if verbose: print("  raw:", data.hex())
        return
    from . import config_oids
    label = config_oids.describe(config_oids.resolve(dotted_oid))
    tag = f"{label['label']} [{label['name']}]" if label.get("known") else dotted_oid
    for vb in r["varbinds"]:
        print(f"{tag} = {vb['value'].hex() if vb['value'] else '<empty>'}")
    if verbose:
        print(f"  (engineBoots={r['engine_boots']} engineTime={r['engine_time']})")


async def cmd_config_set(mac, dotted_oid, value_hex, auth_key, priv_key, user, verbose=False):
    """Authenticated config WRITE: SNMPv3 SET with your reader's keys. DANGER --
    this changes reader configuration; only run against a reader you own and
    understand the OID/value for."""
    from . import oid as oidmod
    ak, pk = bytes.fromhex(auth_key), bytes.fromhex(priv_key)
    c, rx, ev, disc = await _connect(mac)
    await _drain(rx, ev, 1.5)
    rep = await _discover_engine(c, rx, ev, verbose)
    if not rep:
        await c.disconnect(); print("discovery failed"); return
    msg = snmpv3.build_set(_oid_bytes(dotted_oid), bytes.fromhex(value_hex),
                           engine_id=bytes.fromhex(rep["engine_id"]), user_name=user.encode(),
                           engine_boots=rep["engine_boots"], engine_time=rep["engine_time"],
                           auth_key=ak, priv_key=pk)
    apdu = framing.build_apdu(framing.INS_PUT_DATA, msg)
    data = await _snmp_exchange(c, rx, ev, apdu)
    await c.disconnect()
    if not data:
        print("no response to authenticated SET"); return
    try:
        r = snmpv3.parse_secured_response(data, auth_key=ak, priv_key=pk)
        print(f"SET acknowledged for {dotted_oid}")
        if verbose:
            for vb in r["varbinds"]:
                print(f"  {vb['oid']} = {vb['value'].hex() if vb['value'] else '<empty>'}")
    except Exception as e:
        print(f"response failed to verify/decrypt: {e}")
        if verbose: print("  raw:", data.hex())


async def cmd_config_apply(mac, msgfile, write=True, verbose=False):
    """Replay a list of pre-built SNMPv3 messages to the reader -- exactly what
    the app's WriteConfigurationItemsAsync / WriteDCIDConfigurationItemsAsync do:
    they transmit cloud-generated (Origo/config-card) authenticated SNMP messages
    over BLE; the app never builds the crypto itself. So if you capture the
    config package for YOUR reader (from Origo when you generate a config, or off
    your config card), this applies it with no app and no key derivation.

    `msgfile`: one hex SNMP message per line (# comments allowed). NOTE: SNMPv3
    has an engineBoots/engineTime freshness window (~150s), so messages built for
    a *different* session may be rejected as stale -- capture and replay in the
    same window, or use config-set (with keys) which builds fresh each time."""
    msgs = []
    for line in open(msgfile):
        line = line.strip()
        if line and not line.startswith("#"):
            msgs.append(bytes.fromhex(line.replace(" ", "")))
    if not msgs:
        print("no messages in file"); return
    ins = framing.INS_PUT_DATA if write else INS
    c, rx, ev, disc = await _connect(mac)
    await _drain(rx, ev, 1.5)
    if verbose:
        await _discover_engine(c, rx, ev, verbose=True)
    ok = 0
    for i, m in enumerate(msgs):
        apdu = framing.build_apdu(ins, m)
        data = await _snmp_exchange(c, rx, ev, apdu)
        status = "no reply"
        if data:
            try:
                r = snmpv3.parse_secured_response(data, verify=False)
                status = "reply (" + ("value" if any(v["value"] for v in r["varbinds"]) else "report/ack") + ")"
                ok += 1
            except Exception:
                status = f"reply {len(data)}B (unparsed)"; ok += 1
        print(f"  msg {i+1}/{len(msgs)}: {status}")
        if verbose and data:
            print("    <", data.hex())
    await c.disconnect()
    print(f"applied {ok}/{len(msgs)} messages (reader responded)")


async def cmd_config_probe(mac, dotted_oid, verbose=False):
    """Keyless probe: send a noAuthNoPriv SNMPv3 GET for an OID and report what
    the reader does -- maps the boundary of what config is readable WITHOUT the
    Origo-issued keys. Most config OIDs return a Report/authorizationError; any
    that return a value are readable unauthenticated."""
    from . import oid as oidmod
    c, rx, ev, disc = await _connect(mac)
    await _drain(rx, ev, 1.5)
    rep = await _discover_engine(c, rx, ev, verbose)
    if not rep:
        await c.disconnect(); print("discovery failed"); return
    msg = snmpv3.build_get(_oid_bytes(dotted_oid), engine_id=bytes.fromhex(rep["engine_id"]),
                           user_name=b"", engine_boots=rep["engine_boots"],
                           engine_time=rep["engine_time"])  # no keys -> noAuthNoPriv
    apdu = framing.build_apdu(framing.INS_GET_DATA, msg)
    data = await _snmp_exchange(c, rx, ev, apdu)
    await c.disconnect()
    if not data:
        print(f"{dotted_oid}: no response (reader ignored the unauthenticated GET)"); return
    # Try to interpret: a Report PDU (0xA8) = refused/needs auth; a Response with a value = readable.
    try:
        r = snmpv3.parse_secured_response(data, verify=False)
        vbs = r["varbinds"]
        if vbs and any(vb["value"] for vb in vbs):
            print(f"{dotted_oid}: READABLE without keys ->",
                  ", ".join(vb["value"].hex() for vb in vbs if vb["value"]))
        else:
            print(f"{dotted_oid}: reader answered but returned no value (likely refused / needs auth)")
    except Exception:
        # likely a Report PDU (engine params only) -> refused
        print(f"{dotted_oid}: refused unauthenticated (reader replied with a Report/error, needs keys)")
    if verbose:
        print("  raw response:", data.hex())


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
    elif cmd == "tech":
        import json
        from . import technology
        rep = json.load(open(a[0]))
        print(technology.render(rep, verbose=verbose))
    elif cmd == "settings":
        from . import config_oids
        print(config_oids.render_catalog(a[0] if a else None))
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
    elif cmd == "config-get":
        # config-get <MAC> <dotted-oid> <auth_key_hex> <priv_key_hex> <user>
        asyncio.run(cmd_config_get(a[0], a[1], a[2], a[3], a[4], verbose=verbose))
    elif cmd == "config-set":
        # config-set <MAC> <dotted-oid> <value_hex> <auth_key_hex> <priv_key_hex> <user>
        asyncio.run(cmd_config_set(a[0], a[1], a[2], a[3], a[4], a[5], verbose=verbose))
    elif cmd == "config-probe":
        # config-probe <MAC> <dotted-oid>  (keyless noAuthNoPriv read attempt)
        asyncio.run(cmd_config_probe(a[0], a[1], verbose=verbose))
    elif cmd == "config-apply":
        # config-apply <MAC> <msgfile> [read]   replay pre-built SNMP messages
        asyncio.run(cmd_config_apply(a[0], a[1], write=(len(a) < 3 or a[2] != "read"), verbose=verbose))
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
