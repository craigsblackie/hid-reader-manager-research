"""End-to-end decoder for a captured phone<->reader BLE management session.

Supersedes the ad-hoc kind-tagging in btsnoop._decode_message for full sessions.
It models the three real layers observed on the wire (see PROTOCOL.md §30-32):

  1. ISO7816 poll loop. The reader is the TERMINAL: it drives the exchange by
     issuing SELECT (a4) to pick an application, GET_DATA (ca) to pull "the next
     command" from the phone, and PUT_DATA (da) to hand back a result. The phone
     answers as a card: a status word (9000 / 6a82) or, to a GET_DATA poll, an
     injected Artemis command wrapped `44 <id> 44 00 00 00 <cmd> 90 00`.

  2. Artemis/CORE layer. Injected commands and PUT_DATA results are custom BER:
     a5=CORE, a0=GET, a3=SET, plus response wrapper `bd` carrying version strings
     (`ab`/`ac` -> ASCII), status ints, and the SNMP tunnel tag `8a`.

  3. SNMPv3 (RFC 3412 framing, HID's custom USM, security model 257). Crucially,
     in the observed session every message is **noAuthNoPriv (msgFlags 00 00)**:
     the scoped PDU is cleartext, so the reader's whole configuration is read in
     the clear with no key. parse_snmp() returns the varbinds when cleartext and
     flags the message ENCRYPTED only if the scoped data is an OCTET STRING.

Feed it the reassembled per-direction messages (dir, body_hex); get back a list
of labelled events and, via config_report(), the resolved config table.
"""
from . import framing, config_oids


# ---- generic BER walk -------------------------------------------------------
def _tlv(b, i):
    t = b[i]; l = b[i + 1]; j = i + 2
    if l == 0x82:
        l = (b[j] << 8) | b[j + 1]; j += 2
    elif l == 0x81:
        l = b[j]; j += 1
    return t, b[j:j + l], j + l


def _snmp_from(body: bytes):
    """Locate an embedded SNMPv3 message (30 82 .. 02 01 03) in a blob."""
    k = body.find(b"\x02\x01\x03")
    if k < 0:
        return None
    p = body.rfind(b"\x30\x82", 0, k)
    return body[p:] if p >= 0 else None


def parse_snmp(m: bytes) -> dict:
    """Parse one HID-USM SNMPv3 message. Returns flags/security-model/engine
    fields and, when noAuthNoPriv, the decoded cleartext varbinds."""
    out = {}
    _, seq, _ = _tlv(m, 0)
    i = 0
    _, ver, i = _tlv(seq, i)                 # 02 01 03
    _, gd, i = _tlv(seq, i)                  # msgGlobalData
    gi = 0
    _, mid, gi = _tlv(gd, gi); _, mx, gi = _tlv(gd, gi)
    _, flags, gi = _tlv(gd, gi); _, smodel, gi = _tlv(gd, gi)
    _, sp, i = _tlv(seq, i)                   # msgSecurityParameters (OCTET STRING)
    rest = seq[i:]
    out["msg_id"] = mid.hex()
    out["flags"] = flags.hex()
    out["auth"] = bool(flags and flags[-1] & 0x01)
    out["priv"] = bool(flags and flags[-1] & 0x02)
    out["security_model"] = int.from_bytes(smodel, "big")
    try:
        _, usm, _ = _tlv(sp, 0); ui = 0
        _, eid, ui = _tlv(usm, ui); _, eb, ui = _tlv(usm, ui); _, et, ui = _tlv(usm, ui)
        _, un, ui = _tlv(usm, ui)
        out["engine_id"] = eid.hex(); out["engine_boots"] = int.from_bytes(eb, "big")
        out["engine_time"] = int.from_bytes(et, "big"); out["user"] = un.hex()
    except Exception:
        pass
    if rest and rest[0] == 0x30:             # cleartext scoped PDU
        out["encrypted"] = False
        try:
            _, sc, _ = _tlv(rest, 0); si = 0
            _, _, si = _tlv(sc, si); _, _, si = _tlv(sc, si)   # ctxEngineID, ctxName
            pdu_t, pdu, si = _tlv(sc, si)
            out["pdu_type"] = pdu_t
            pi = 0
            _, rid, pi = _tlv(pdu, pi); _, es, pi = _tlv(pdu, pi); _, ei, pi = _tlv(pdu, pi)
            _, vbl, pi = _tlv(pdu, pi)
            vbs = []; vi = 0
            while vi < len(vbl):
                _, vb, vi = _tlv(vbl, vi); bi = 0
                _, o, bi = _tlv(vb, bi); _, val, bi = _tlv(vb, bi)
                vbs.append((o.hex(), val.hex()))
            out["varbinds"] = vbs
        except Exception as e:
            out["parse_error"] = str(e)
    elif rest and rest[0] == 0x04:           # encrypted scoped PDU
        out["encrypted"] = True; out["enc_len"] = len(rest)
    return out


# ---- ISO7816 / Artemis layer ------------------------------------------------
def _ascii_versions(body: bytes):
    """Pull ASCII version strings carried under ab/ac tags in a `bd` result."""
    out = []
    for i in range(len(body) - 2):
        if body[i] in (0xab, 0xac) and body[i + 1] == 0x06:
            seg = body[i + 2:i + 8]
            txt = "".join(chr(c) for c in seg if 32 <= c < 127)
            if txt:
                out.append(txt)
    return out


def classify(direction: str, body: bytes) -> dict:
    """Classify one reassembled message. direction: 'rx'=reader->phone (terminal
    command / result), 'tx'=phone->reader (card response / injected command)."""
    ev = {"dir": direction, "raw": body.hex()}
    if not body:
        ev["kind"] = "empty"; return ev
    if direction == "rx":                     # reader is the terminal
        ins = body[1] if len(body) > 1 else None
        if ins == 0xa4 and len(body) >= 5:
            aid = body[5:5 + body[4]]
            ev["kind"] = "SELECT"; ev["aid"] = aid.hex()
        elif ins == 0xca:
            ev["kind"] = "GET_DATA (poll: next command?)"
        elif ins == 0xda:
            ev["kind"] = "PUT_DATA (result)"
            data = body[7:] if len(body) > 7 and body[4] == 0 else body[5:]
            snmp = _snmp_from(data)
            if snmp:
                ev["kind"] = "PUT_DATA (SNMP)"; ev["snmp"] = parse_snmp(snmp)
            else:
                vs = _ascii_versions(data)
                if vs:
                    ev["version"] = vs[0]
        else:
            ev["kind"] = f"apdu(ins={ins:02x})" if ins is not None else "data"
    else:                                     # phone answering as a card
        if body in (b"\x90\x00",) or (len(body) == 2 and body[0] in (0x6a, 0x90)):
            ev["kind"] = "SW " + body.hex()
        elif body[:2] == b"\x44\x01" or (len(body) > 6 and body[0] == 0x44):
            # injected command: 44 id 44 00 00 00 <cmd> 90 00
            cmd = body[6:-2] if body[-2:] == b"\x90\x00" else body[6:]
            ev["kind"] = "INJECT CMD"; ev["cmd"] = cmd.hex()
            snmp = _snmp_from(cmd)
            if snmp:
                ev["snmp"] = parse_snmp(snmp)
        else:
            ev["kind"] = "response"; ev["data"] = body.hex()
    return ev


def decode_events(messages):
    """messages: iterable of (direction, body_bytes). Returns labelled events."""
    return [classify(d, b) for d, b in messages]


def config_report(events) -> dict:
    """Collect every cleartext SNMP varbind seen into an OID->value map with
    names resolved. Also flags whether ANY message was encrypted."""
    cfg = {}; any_enc = False; any_clear = False
    for e in events:
        s = e.get("snmp")
        if not s:
            continue
        if s.get("encrypted"):
            any_enc = True
        for oidhex, val in s.get("varbinds", []):
            any_clear = True
            cfg.setdefault(oidhex, val)
    rows = []
    for oidhex, val in cfg.items():
        info = config_oids.CONFIG_OIDS.get(oidhex.upper())
        rows.append({
            "oid": oidhex,
            "name": info[0] if info else "?",
            "label": info[1] if info else "(unmapped)",
            "dangerous": bool(info and info[3]),
            "value": val,
        })
    return {"any_encrypted": any_enc, "any_cleartext": any_clear, "items": rows}


def render_config(report: dict) -> str:
    lines = []
    mode = ("CLEARTEXT (no encryption on the wire)" if report["any_cleartext"]
            and not report["any_encrypted"] else
            "MIXED" if report["any_cleartext"] else "ENCRYPTED")
    lines.append(f"Reader config read — transport confidentiality: {mode}")
    lines.append("")
    for r in sorted(report["items"], key=lambda x: x["name"]):
        dang = "  [DANGEROUS]" if r["dangerous"] else ""
        lines.append(f"{r['name']:30} {r['oid']:14}{dang}")
        lines.append(f"    {r['label']}")
        lines.append(f"    value: {r['value']}")
        lines.append("")
    return "\n".join(lines)
