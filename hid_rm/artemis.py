"""Artemis reader messaging (BinaryNotes/BER `Payload` CHOICE).

Core/HF/LF/firmware operations are BER-encoded `Payload` messages (schema
HidGlobal.Asn1.Messaging.Artemis). All CORE byte templates below were produced by
running the app's own BinaryNotes.NET encoder against the shipped message assembly
(ground truth), so they are exact.

Payload module tags: sam=0 hf=1 contact=2 wiegand=3 clockAndData=4 core=5 hwio=6
lf=7 ... bleModule=21 response=29 errorResponse=30 upgrade=33 ...

CoreCommand sub-tags (reads unless noted): getPendingCommand=0 getSamFirmware=1
reset=2(!) resetSam=5(!) getVersionInfo=6 getTamperState=7 shutdown=11(!)
getSecureElementMode=19 getBoardRevision=23 getChipUid=26 getDeviceId=27
getDeviceInfo=33 getReaderInfo=35 exitArtemisMode=34(!) delayedReset=14(!)
"""

# Ground-truth Payload bytes (from the app's BinaryNotes encoder).
CORE = {
    # ---- read / query (safe) ----
    "get_pending_command":  bytes.fromhex("a5028000"),
    "get_sam_firmware":     bytes.fromhex("a5028100"),
    "get_version_info":     bytes.fromhex("a5028600"),
    "get_tamper_state":     bytes.fromhex("a5028700"),
    "get_secure_element_mode": bytes.fromhex("a5029300"),
    "get_board_revision":   bytes.fromhex("a5029700"),
    "get_chip_uid":         bytes.fromhex("a5029a00"),
    "get_device_id":        bytes.fromhex("a5029b00"),
    "get_device_info":      bytes.fromhex("a5039f2100"),
    "get_reader_info":      bytes.fromhex("a5039f2300"),
    "get_peripheral_firmware": bytes.fromhex("a508aa06800100810100"),
    # ---- state-changing (require a session; DANGER: reboot/mode change) ----
    "reset":                bytes.fromhex("a5028200"),   # PerformCoreResetAsync
    "reset_sam":            bytes.fromhex("a5028500"),
    "shutdown":             bytes.fromhex("a5028b00"),
    "delayed_reset":        bytes.fromhex("a5038e0100"), # arg=1
    "exit_artemis_mode":    bytes.fromhex("a5039f2200"),
}

# Human-readable field maps for decoding responses (from CoreVersionInfo /
# CoreDeviceInfo ASN.1). Keyed by (context) tag within the info structure.
DEVICE_INFO_FIELDS = {0: "version", 1: "firmwareId", 2: "coreCPUType",
                      3: "boardType", 4: "boardRev", 5: "modelIdent"}
VERSION_INFO_FIELDS = {0: "version", 1: "firmwareId", 2: "coreCPUType", 3: "boardType"}


def core_payload(name: str) -> bytes:
    return CORE[name]


def is_dangerous(name: str) -> bool:
    return name in {"reset", "reset_sam", "shutdown", "delayed_reset", "exit_artemis_mode"}


# ---- minimal BER reader for decoding responses -----------------------------
def ber_parse(data: bytes, _pos=0, _end=None):
    if _end is None:
        _end = len(data)
    out, p = [], _pos
    while p < _end:
        first = data[p]; p += 1
        constructed = bool(first & 0x20)
        tagnum = first & 0x1F
        if tagnum == 0x1F:
            tagnum = 0
            while True:
                b = data[p]; p += 1
                tagnum = (tagnum << 7) | (b & 0x7F)
                if not (b & 0x80):
                    break
        ln = data[p]; p += 1
        if ln & 0x80:
            nb = ln & 0x7F
            ln = int.from_bytes(data[p:p + nb], "big"); p += nb
        val = data[p:p + ln]; p += ln
        out.append({"class": first >> 6, "constructed": constructed, "tag": tagnum,
                    "children": ber_parse(val, 0, len(val)) if constructed else None,
                    "value": None if constructed else val})
    return out


def decode_response(payload: bytes):
    """Best-effort pretty decode of an Artemis Payload response.
    Path: Payload[response=29] -> coreResponse[2] -> <info>[tag] -> fields."""
    tree = ber_parse(payload)
    lines = []

    def walk(nodes, depth=0, hint=None):
        for n in nodes:
            name = None
            if depth == 2 and hint == "core":
                name = {6: "versionInfo", 33: "deviceInfo?", 35: "readerInfo"}.get(n["tag"])
            if n["constructed"]:
                lines.append("  " * depth + f"[{n['tag']}]{' ' + name if name else ''}")
                nh = "core" if (depth == 0 and n["tag"] == 29) or (depth == 1 and n["tag"] == 2) else hint
                walk(n["children"], depth + 1, nh)
            else:
                fld = ""
                if depth >= 3:
                    fld = DEVICE_INFO_FIELDS.get(n["tag"], "")
                v = n["value"]
                txt = v.hex()
                if v and all(32 <= c < 127 for c in v):
                    txt += f'  "{v.decode()}"'
                lines.append("  " * depth + f"[{n['tag']}] {fld}: {txt}")
    walk(tree)
    return "\n".join(lines)
