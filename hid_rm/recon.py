"""Unified reconnaissance: everything hid_rm can collect from a reader in one pass.

Sections, each explicitly marked with what's proven to work vs. proven blocked
(see PROTOCOL.md for the live evidence behind every claim below):

  1. BLE identity      -- address, advertised name, RSSI, advertised service UUIDs
  2. GATT surface       -- every service/characteristic/descriptor the reader exposes
  3. Spontaneous frames -- what it says unprompted on connect
  4. Config leak         -- PROVEN: configured PACS/SEOS credential OIDs + mode AIDs
                            (no auth needed; see leak.py)
  5. Artemis core reads  -- PROVEN BLOCKED unauthenticated (kept here so a future
                            run against a DIFFERENT reader/firmware, or one where
                            you hold real session keys, shows real data instead of
                            "no response")
  6. SNMP discovery       -- PROVEN BLOCKED unauthenticated, same reasons as #5
"""
import asyncio, time
from . import framing, artemis, snmpv3, seos, leak, DATA_CHAR_UUID


async def gatt_dump(client) -> list:
    out = []
    for svc in client.services:
        s = {"uuid": str(svc.uuid), "characteristics": []}
        for ch in svc.characteristics:
            s["characteristics"].append({
                "uuid": str(ch.uuid), "properties": list(ch.properties),
                "handle": ch.handle, "descriptors": [str(d.uuid) for d in ch.descriptors],
            })
        out.append(s)
    return out


async def probe_gated_channel(client, rx, ev, label, apdu_payload) -> dict:
    """Try one Artemis/SNMP GET_DATA request; report whether it got real data back
    or was ignored (per PROTOCOL.md §9, expect the latter unauthenticated)."""
    async def drain(t=2.0):
        try:
            await asyncio.wait_for(ev.wait(), timeout=t)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.4)
        frames = list(rx); rx.clear(); ev.clear()
        return frames

    frame = framing.frame(framing.build_apdu(framing.INS_GET_DATA, apdu_payload))
    for fr in framing.ble_fragment(frame):
        await client.write_gatt_char(DATA_CHAR_UUID, fr, response=False)
        await asyncio.sleep(0.05)
    got = await drain()
    buf = framing.ble_reassemble(got)
    # Does the reassembled reply look like an Artemis Payload response (tag 29) or
    # is it the reader just re-running its own unrelated SELECT sequence?
    is_real_response = bool(buf) and buf[:1] not in (b"\x00", b"\x81")  # crude: our
    # requests always get either silence, an EOT status, or a re-SELECT (0x00 A4...)
    return {
        "label": label, "sent": frame.hex(),
        "raw_frames_back": [f.hex() for f in got],
        "ignored": (not is_real_response),
        "note": "reader replayed its own unrelated SELECT/EOT -- request was not "
                "parsed as Artemis/SNMP (expected, unauthenticated)" if not is_real_response
                else "got a response distinct from the usual SELECT replay -- inspect raw_frames_back",
    }


async def enumerate_reader(mac: str, cooldown: float = 0.0) -> dict:
    from bleak import BleakClient, BleakScanner

    report = {"target": mac, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}

    if cooldown:
        await asyncio.sleep(cooldown)

    # 1. BLE identity (short scan)
    adv_info = {}
    devs = await BleakScanner.discover(timeout=5.0, return_adv=True)
    if mac in devs:
        d, adv = devs[mac]
        adv_info = {"name": adv.local_name or d.name, "rssi": adv.rssi,
                    "advertised_service_uuids": list(adv.service_uuids or [])}
    report["ble_identity"] = adv_info

    rx, ev = [], asyncio.Event()

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

    async with BleakClient(mac) as c:
        # 2. GATT surface
        report["gatt"] = await gatt_dump(c)

        await c.start_notify(DATA_CHAR_UUID, on_notify)

        # 3. Spontaneous frames
        spontaneous = await drain(3.5)
        report["spontaneous_frames"] = [f.hex() for f in spontaneous]

    # 4. Config leak (fresh connection -- leak.run_leak manages its own connect)
    collector = await leak.run_leak(mac, cooldown=1.0)
    report["config_leak"] = collector.report()
    report["config_leak_text"] = collector.render_text()

    # 5 & 6. Gated-channel probes (expected to show "ignored") -- fresh connection
    await asyncio.sleep(1.0)
    gated_results = []
    async with BleakClient(mac) as c:
        rx.clear(); ev.clear()
        await c.start_notify(DATA_CHAR_UUID, on_notify)
        await drain(3.0)  # discard spontaneous
        for label, payload in [
            ("core.get_version_info", artemis.CORE["get_version_info"]),
            ("core.get_reader_info", artemis.CORE["get_reader_info"]),
            ("snmp.discovery", snmpv3.build_discovery()),
        ]:
            gated_results.append(await probe_gated_channel(c, rx, ev, label, payload))
            await asyncio.sleep(0.3)
    report["gated_channel_probes"] = gated_results

    return report


def render_summary(report: dict, verbose: bool = False) -> str:
    """Concise, plain-language summary by default; verbose=True adds the full
    GATT dump, raw frames, raw OIDs/AIDs, and probe request/response bytes."""
    from . import oid_db, leak as leak_mod

    bi = report["ble_identity"]
    cl = report["config_leak"]
    summary = oid_db.summarize([o["raw"] for o in cl["oids"]])
    admin_aids = [a for a in cl["aids"] if "ADMIN" in a["name"] or "OPERATION_SELECTOR" in a["name"]]
    gloss = leak_mod.LeakCollector.STATUS_GLOSS.get(cl["final_status"], cl["final_status"])
    blocked = sum(1 for g in report["gated_channel_probes"] if g["ignored"])
    total_probes = len(report["gated_channel_probes"])

    lines = [f"HID Reader: {bi.get('name') or '(unnamed)'}  [{report['target']}]  "
             f"signal: {bi.get('rssi')} dBm", ""]

    total = summary["standard_count"] + summary["custom_count"]
    lines.append(f"Credential profiles configured: {total}")
    if summary["standard"]:
        lines.append(f"  - {len(summary['standard'])} standard HID default")
    for c in summary["custom"]:
        lines.append(f"  - {c}  (customer-specific, not a HID default)")
    lines.append("")
    lines.append(f"Admin/management mode present: {'yes' if admin_aids else 'not observed'}")
    lines.append(f"Configuration access: {'BLOCKED' if blocked else 'PARTIAL/OPEN'} "
                 f"({blocked}/{total_probes} authenticated-only requests were ignored, as expected "
                 f"without HID Elite-tier cloud credentials)")
    lines.append(f"Credential-read result: {gloss}")

    if not verbose:
        lines.append("")
        lines.append("(run with --verbose for the GATT dump, raw frames, and per-probe detail)")
        return "\n".join(lines)

    lines.append("")
    lines.append("-" * 72)
    lines.append("VERBOSE DETAIL")
    lines.append("-" * 72)
    lines.append(f"generated: {report['generated_at']}")
    lines.append(f"advertised services: {bi.get('advertised_service_uuids')}")
    lines.append(f"\nGATT surface: {len(report['gatt'])} service(s)")
    for s in report["gatt"]:
        lines.append(f"    service {s['uuid']}")
        for ch in s["characteristics"]:
            lines.append(f"      char {ch['uuid']}  {ch['properties']}")
    lines.append(f"\nSpontaneous frames on connect: {len(report['spontaneous_frames'])}")
    for f in report["spontaneous_frames"]:
        lines.append(f"      {f}")
    lines.append(f"\nRaw OIDs offered ({len(cl['oids'])}):")
    for o in cl["oids"]:
        lines.append(f"      {o['raw']}  [{o['kind']}]")
    lines.append(f"\nRaw AIDs tried ({len(cl['aids'])}):")
    for a in cl["aids"]:
        lines.append(f"      {a['name']:30} {a['hex']}")
    lines.append(f"\nGated-channel probes (request/response bytes):")
    for g in report["gated_channel_probes"]:
        verdict = "IGNORED (blocked)" if g["ignored"] else "** GOT SOMETHING -- INSPECT **"
        lines.append(f"      {g['label']:24} {verdict}")
        lines.append(f"        sent: {g['sent']}")
        for f in g["raw_frames_back"]:
            lines.append(f"        recv: {f}")
    return "\n".join(lines)
