"""Render a raw config-item value into a human-readable setting.

Structures below are grounded in HID's own decompiled code
(HidGlobal.ArtemisManager -- MediaOutputConfiguration, OSDPConfiguration,
UARTConfiguration), byte-verified against real values read live off the
reader (PROTOCOL.md sec:33). Where no confirmed struct exists, `render()`
falls back to a general BER tree-print (`ber_tree`) so every value still
becomes *something* readable rather than a bare hex blob -- printable ASCII
runs, small integers, and any embedded OID matching our catalog or the HID
enterprise arc (1.3.6.1.4.1.33592, hex prefix 2b0601040181e438) get labelled;
anything left over is shown as hex, honestly, rather than guessed at.
"""
from . import config_oids, artemis, emulate

_LED_NAMES = {v: k for k, v in artemis.LED_COLORS.items()}

# HidGlobal.ArtemisManager.MediaOutputConfiguration.MediaOutput (decompiled, verified)
_MEDIA_OUTPUT_BITS = [
    (0x01, "Wiegand"), (0x02, "ClockAndData"), (0x04, "ExternalUart"),
    (0x08, "I2C"), (0x10, "OSDP"),
]

# HidGlobal.ArtemisManager.OSDPSpecVersion / Parity / StopBit (decompiled, verified)
_OSDP_VERSION = {1: "V1", 2: "V2"}
_PARITY = {1: "None", 2: "Even", 3: "Odd"}
_STOPBIT = {1: "One", 2: "Two"}


def _ascii_runs(b: bytes, min_len=3):
    out, cur = [], b""
    for c in b:
        if 32 <= c < 127:
            cur += bytes([c])
        else:
            if len(cur) >= min_len:
                out.append(cur.decode())
            cur = b""
    if len(cur) >= min_len:
        out.append(cur.decode())
    return out


def _media_output(v: bytes) -> str:
    if len(v) != 1:
        return f"(unexpected length {len(v)}, expected 1B): {v.hex()}"
    n = v[0]
    on = [name for bit, name in _MEDIA_OUTPUT_BITS if n & bit]
    return f"{', '.join(on) if on else 'None'}  (raw=0x{n:02x})"


def _osdp_configuration(v: bytes) -> str:
    # HidGlobal.ArtemisManager.OSDPConfiguration.Properties(string) ctor:
    # [0]=Address [1]=IsInstallMode [2]=AccessDataTimeout [3]=KeypadDataTimeout
    # [4]=IsSecureModeOnly [5]=IsEnabled [6]=Version [7]=ProcessingTimeout
    if len(v) < 8:
        return f"(too short, expected >=8B): {v.hex()}"
    addr, install, access_to, keypad_to, secure_only, enabled, ver, proc_to = v[:8]
    parts = [
        f"enabled={'yes' if enabled else 'no'}",
        f"address={addr}",
        f"version={_OSDP_VERSION.get(ver, f'{ver}(?)')}",
        f"installMode={'yes' if install else 'no'}",
        f"secureModeOnly={'yes' if secure_only else 'no'}",
        f"accessDataTimeout={access_to}",
        f"keypadDataTimeout={keypad_to}",
        f"processingTimeout={proc_to}",
    ]
    if len(v) > 8:
        parts.append(f"reserved={v[8:].hex()}")
    return ", ".join(parts)


def _uart_configuration(v: bytes) -> str:
    # HidGlobal.ArtemisManager.UARTConfiguration.Properties parse order:
    # [0:4]=BaudRate (u32 BE) [4]=StopBit [5]=Parity
    if len(v) < 6:
        return f"(too short, expected >=6B): {v.hex()}"
    baud = int.from_bytes(v[0:4], "big")
    stop, parity = v[4], v[5]
    parts = [f"baud={baud}", f"stopBits={_STOPBIT.get(stop, f'{stop}(?)')}",
             f"parity={_PARITY.get(parity, f'{parity}(?)')}"]
    if len(v) > 6:
        parts.append(f"trailing={v[6:].hex()}")
    return ", ".join(parts)


def _led_color(v: bytes) -> str:
    if len(v) != 1:
        return f"(unexpected length {len(v)}): {v.hex()}"
    return _LED_NAMES.get(v[0], f"0x{v[0]:02x}(?)")


def _ice_number(v: bytes) -> str:
    if not any(v):
        return "not provisioned (all-zero)"
    txt = "".join(chr(c) if 32 <= c < 127 else "." for c in v)
    return f"{v.hex()}  ('{txt}')"


def _timeout_uint(v: bytes, unit="") -> str:
    n = int.from_bytes(v, "big")
    if n == 0:
        return "0 (disabled/no timeout)"
    return f"{n}{(' ' + unit) if unit else ''}"


def _aid_list(v: bytes) -> str:
    """SEOS_AIDS_ORDERED_LIST: repeated [2-byte pad?][1-byte len][AID bytes]."""
    out = []
    i = 0
    while i + 3 <= len(v):
        if v[i] == 0 and v[i + 1] == 0:
            ln = v[i + 2]
            aid = v[i + 3:i + 3 + ln]
            if len(aid) == ln and ln > 0:
                out.append(f"{emulate.classify_aid(aid)} ({aid.hex()})")
                i += 3 + ln
                continue
        i += 1
    return "; ".join(out) if out else f"(unparsed): {v.hex()}"


_HID_ARC = bytes.fromhex("2b0601040181e438")  # 1.3.6.1.4.1.33592 (HID enterprise arc)


def _hid_record_list(v: bytes) -> str:
    """SEOS_PACS_CONFIG / SEOS_ADMIN_CARD_APP: mostly a flat list of Pascal-style
    records -- a single length byte followed by that many content bytes, most
    opening with the HID enterprise OID (1.3.6.1.4.1.33592, hex
    2b0601040181e438) followed by small integer sub-fields whose exact names
    aren't in the decompiled surface we have (likely a native/ASN.1 definition
    not present in this dump) -- shown positionally rather than guessed.
    Interspersed short BER-looking markers (e.g. between key-set entries) don't
    fit that shape; rather than stop, we skip to the next recognisable HID
    record and label the gap honestly as an unrecognised marker.
    Verified against real multi-round captures (PROTOCOL.md sec:33)."""
    out = []
    i = 0
    n = 0
    while i < len(v):
        ln = v[i]
        content = v[i + 1:i + 1 + ln]
        if ln and len(content) == ln:
            n += 1
            if content[:8] == _HID_ARC:
                out.append(f"[{n}] HID SEOS credential record: enterprise-OID + fields {content[8:].hex()}")
            else:
                ascii_runs = _ascii_runs(content)
                tag = f" '{ascii_runs[0]}'" if ascii_runs else ""
                out.append(f"[{n}] record ({ln}B): {content.hex()}{tag}")
            i += 1 + ln
            continue
        # doesn't parse as a record here -- find the next HID-prefixed record
        # and show what's between as an unrecognised marker/separator.
        nxt = v.find(_HID_ARC, i + 1)
        if nxt < 0:
            out.append(f"[trailer, {len(v) - i}B, unrecognised]: {v[i:].hex()}")
            break
        start = max(i, nxt - 1)  # the length byte precedes the OID
        if start > i:
            out.append(f"[marker/separator, {start - i}B, unrecognised]: {v[i:start].hex()}")
        i = start
    return "\n      " + "\n      ".join(out)


def ber_tree(v: bytes, indent: int = 0) -> list:
    """Best-effort generic BER pretty-print: walk TLVs, label recognised OID
    prefixes/catalog OIDs, show printable ASCII, else hex. Always terminates
    (falls back to a hex line) even on non-BER data."""
    lines = []
    i = 0
    pad = "  " * indent
    while i < len(v):
        if i + 2 > len(v):
            lines.append(f"{pad}(trailing junk): {v[i:].hex()}")
            break
        tag = v[i]
        ln = v[i + 1]
        j = i + 2
        if ln == 0x82:
            if j + 2 > len(v):
                break
            ln = (v[j] << 8) | v[j + 1]; j += 2
        elif ln == 0x81:
            ln = v[j]; j += 1
        content = v[j:j + ln]
        if len(content) != ln:
            lines.append(f"{pad}(not standard BER from here -- shown as hex): {v[i:].hex()}")
            break
        label = ""
        if content[:8] == _HID_ARC:
            label = "  [HID enterprise OID: 1.3.6.1.4.1.33592...]"
        else:
            oid_hex = content.hex().upper()
            info = config_oids.CONFIG_OIDS.get(oid_hex)
            if info:
                label = f"  [= {info[0]}]"
        constructed = bool(tag & 0x20) or (0xA0 <= tag <= 0xBF)
        if constructed and content:
            lines.append(f"{pad}tag 0x{tag:02x} ({ln}B):{label}")
            lines.extend(ber_tree(content, indent + 1))
        else:
            ascii_runs = _ascii_runs(content)
            extra = f"  '{ascii_runs[0]}'" if ascii_runs else ""
            if not extra and len(content) <= 4 and content:
                extra = f"  (int={int.from_bytes(content, 'big')})"
            lines.append(f"{pad}tag 0x{tag:02x} ({ln}B): {content.hex()}{extra}{label}")
        i = j + ln
    return lines


_RENDERERS = {
    "MEDIA_OUTPUT": _media_output,
    "OSDP_CONFIGURATION": _osdp_configuration,
    "EXTERNAL_UART_CONFIGURATION": _uart_configuration,
    "SIGNO_UART_CONFIGURATION": _uart_configuration,
    "LED_COLOR": _led_color,
    "SLAVE_MODE_RF_ACTIVITY_LED_COLOR": _led_color,
    "ICE_NUMBER": _ice_number,
    "CONFIG_CARD_TIMEOUT": lambda v: _timeout_uint(v),
    "SEOS_AIDS_ORDERED_LIST": _aid_list,
    "SEOS_PACS_CONFIG": _hid_record_list,
    "SEOS_ADMIN_CARD_APP": _hid_record_list,
}


def _mostly_printable(b: bytes, min_len=3) -> bool:
    if len(b) < min_len:
        return False
    printable = sum(1 for c in b if 32 <= c < 127 or c == 0)
    return printable / len(b) >= 0.85 and sum(1 for c in b if 32 <= c < 127) >= min_len


def _as_string(v: bytes) -> str:
    txt = v.rstrip(b"\x00").decode("latin1", "replace")
    pad = len(v) - len(v.rstrip(b"\x00"))
    return f"'{txt}'" + (f"  (+{pad} zero-byte pad)" if pad else "")


def render(name: str, value: bytes) -> str:
    """Human-readable rendering of one config item's value. Uses a grounded
    decoder where the structure is confirmed from decompiled source; a
    printable-ASCII value (a serial number, a BLE device name, ...) is shown
    as a string; anything else falls back to a labelled BER tree-print."""
    if not value:
        return "(empty)"
    fn = _RENDERERS.get(name)
    if fn:
        try:
            return fn(value)
        except Exception as e:
            return f"(decode error: {e}) raw={value.hex()}"
    if _mostly_printable(value):
        return _as_string(value)
    if len(value) > 1 and _mostly_printable(value[1:]) and value[0] in (len(value) - 1, len(value.rstrip(b"\x00")) - 1):
        return _as_string(value[1:]) + f"  (1-byte length prefix 0x{value[0]:02x})"
    tree = ber_tree(value)
    if len(tree) == 1 and ":" in tree[0] and tree[0].count("\n") == 0 and not tree[0].strip().startswith("tag"):
        return tree[0]
    return "\n      " + "\n      ".join(tree) if tree else value.hex()
