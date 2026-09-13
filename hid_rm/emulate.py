"""Card-emulation responder + AID/state model for the reader's BLE polling loop.

CORRECTION to earlier notes: the values the reader sends via SELECT-AID during its
autonomous BLE poll (`a000000382002d000101`, `a000000382002f000101`, ...) are NOT an
incrementing nonce/counter. They are REAL, FIXED, hardcoded application AIDs from
HidGlobal.ArtemisManager `Constants.AID` (decompiled), used by the app's own
`ReaderStateAnalyzer.AnalyseAID()` to classify what kind of session the reader is
offering. The reader tries them in a fixed discovery order on every connection,
interleaved with SEOS credential-ADF candidates (OID list under 1.3.6.1.4.1.29240...).

    AID (hex)                       name                         -> ReaderState
    a0000003820028000101            SAM_UPDATER                  -> MobileSeosAdminCardOperation
    a0000003820029000101            BLE_CORE_UPDATER              -> MobileSeosAdminCardOperationPostReset
    a0000003820021000101            NFC_CORE_UPDATER              -> NfcCoreBootloadMode
    a0000003820025000101            NFC_OEM_CORE_UPDATER          -> NfcCoreBootloadMode
    a000000382002b000101            DOTNETAPP_ADMIN               -> (app-side "is this me")
    a000000382002c000101            PASSTHROUGH                   -> BleUartPassThrough / NfcPassThrough
    a000000382002d000101            MOBILE_SEOS_ADMIN_CARD        -> MobileSeosAdminCardAuthentication
    a000000382002f000101            OPERATION_SELECTOR            -> (mode-select AID)
    a0000003820031000101            OPERATION_SELECTOR_POST_RESET -> ...PostReset
    a0000003820030000101            LEGACY_PASSTHROUGH            -> BleUartLegacyPassThrough
    a0000004400001010001            STANDARD_SEOS                 -> StandardSeosAuthentication
                                                                      (this is what the reader
                                                                       auto-selects/offers by
                                                                       default -- normal
                                                                       credential/door mode)

Practical meaning: on a plain BLE connect, the reader is running in
STANDARD_SEOS (door-credential) mode, and its polling loop tries the admin/updater/
passthrough AIDs too as part of a fixed discovery routine -- it is not "waiting" for
the phone to claim one, and in live testing (see AAMK.md) simply ACK'ing (SW=9000) or
even echoing a plausible FCI for the admin AID did not shift the reader into a
command-accepting mode; it continued down its own candidate list and then rejected
(SAM_REJECTED). Whatever actually flips the reader into MobileSeosAdminCardOperation
in the field (a magnetic/admin card tap, a specific certificate-backed AKE exchange,
or firmware-side state outside what a passive BLE central can drive) has not been
isolated from the app source alone -- this is the next thing to instrument if you
want to keep pushing (see AAMK.md open items).
"""

AID = {
    "SAM_UPDATER":                  bytes.fromhex("a0000003820028000101"),
    "BLE_CORE_UPDATER":             bytes.fromhex("a0000003820029000101"),
    "NFC_CORE_UPDATER":             bytes.fromhex("a0000003820021000101"),
    "NFC_OEM_CORE_UPDATER":         bytes.fromhex("a0000003820025000101"),
    "DOTNETAPP_ADMIN":              bytes.fromhex("a000000382002b000101"),
    "PASSTHROUGH":                  bytes.fromhex("a000000382002c000101"),
    "MOBILE_SEOS_ADMIN_CARD":       bytes.fromhex("a000000382002d000101"),
    "OPERATION_SELECTOR":           bytes.fromhex("a000000382002f000101"),
    "OPERATION_SELECTOR_POST_RESET":bytes.fromhex("a0000003820031000101"),
    "LEGACY_PASSTHROUGH":           bytes.fromhex("a0000003820030000101"),
    "STANDARD_SEOS":                bytes.fromhex("a0000004400001010001"),
}
AID_BY_BYTES = {v: k for k, v in AID.items()}


def classify_aid(aid: bytes) -> str:
    """Exact match against the known 10-byte AIDs, falling back to a prefix match
    since the reader's actual on-wire SELECT for STANDARD_SEOS is 16 bytes (the
    10-byte base + a 6-byte qualifier `00 00 47 05 2B 03` -- see seos.SEOS_AID)."""
    if aid in AID_BY_BYTES:
        return AID_BY_BYTES[aid]
    for name, base in AID.items():
        if aid.startswith(base) and len(aid) > len(base):
            return f"{name}+qualifier({aid[len(base):].hex()})"
    return f"UNKNOWN({aid.hex()})"


def find_aid_in(buf: bytes):
    """Return (name, aid_bytes) if any known AID appears in buf, else None."""
    for name, val in AID.items():
        if val in buf:
            return name, val
    return None


def fci_echo(aid: bytes, extra: bytes = bytes.fromhex("a5024000")) -> bytes:
    """Minimal plausible SELECT response FCI: 6F template { 84 AID, A5 <extra> }."""
    body = bytes([0x84, len(aid)]) + aid + extra
    return bytes([0x6F, len(body)]) + body


class CardEmulationResponder:
    """Reply strategy for the reader's autonomous PCD-role polling loop.

    The reader always initiates (it is the terminal); the connected BLE central
    only supplies ISO7816 status words (and optional FCI data) in response.
    Feed it each reassembled reader->phone APDU via .reply_for(); it returns the
    bytes to write back (NOT yet fragmented -- pass through framing.ble_fragment
    or wrap with 0xC0 for short replies).
    """

    def __init__(self, fci_for_known_aids: bool = True):
        self.fci_for_known_aids = fci_for_known_aids
        self.log = []

    def reply_for(self, apdu: bytes) -> bytes:
        hit = find_aid_in(apdu) if self.fci_for_known_aids else None
        if hit:
            name, aid = hit
            reply = fci_echo(aid) + bytes.fromhex("9000")
            self.log.append((name, "fci"))
        else:
            reply = bytes.fromhex("9000")
            self.log.append((classify_aid(apdu[5:5+apdu[4]]) if len(apdu) > 5 else "?", "9000"))
        return reply
