"""SNMPv3 layer for the HID reader config MIB.

The reader configuration (enabled card technologies, keys-by-reference, Wiegand/OSDP
output, LED/sound, etc.) is an SNMP MIB under the HID enterprise OID
  1.3.6.1.4.1.24632  (PEN 24632 -> encoded 2B 06 01 04 01 81 E4 38)

Two message types (both reverse-engineered from HidGlobal.SDI.SnmpV3 +
HidGlobal.ArtemisManager):

1. DISCOVERY  -- unauthenticated (noAuthNoPriv).  `build_discovery()` below is
   byte-for-byte identical to the app's BuildDiscoveryMessage() output.  Send it,
   and the reader replies with a Report PDU carrying its authoritative engineId,
   engineBoots and engineTime.  This is the ONE config-plane exchange that needs
   no keys.

2. SECURED GET/PUT -- authNoPriv/authPriv.  Requires a USM auth key + priv key.
   *** These keys are NOT in the app. *** They are computed server-side by HID's
   cloud (SDS/SDI micro-service: UpdateCredential/FetchELITEConfiguration/
   iCLASSKeyManagement/KeyRoll...) and released only to an authenticated user for
   their own org's readers.  Genesis (factory) engineIds/usernames for some
   families are embedded (see GENESIS_IDENTITIES) but the matching auth/priv keys
   are not.

   HID's USM is CUSTOM, not stock RFC 3414:
       auth = SMAC  (SHA-1 based MAC)   [AuthFactory algo 0]  (OMAC/CMAC-AES = 1)
       priv = AES-128-CBC, "MsCrypto" padding   [ConfFactory algo 1]
   so a stock pysnmp agent will NOT interoperate; a faithful secured client must
   reimplement AuthSMAC / ConfAES from the decompiled source.
"""

HID_PEN_OID = "1.3.6.1.4.1.24632"           # 2B0601040181E438

# Hardcoded (Genesis / factory) SNMP identities recovered by running the app's
# SnmpIdentityProvider (OID-encoded engineId / username hex). Other reader
# families (RevE, Stingray, Raptor, ...) require the cloud AppSettings.xml.
GENESIS_IDENTITIES = {
    "OmnikeyReaderCoreHID": {
        "genesis_engine_id": "2B0601040181E43801010305290101",
        "genesis_username":  "2B0601040181E43801010408270101",
        "hid_admin_engine_id":"2B0601040181E438010103052A01",
        "hid_admin_username": "2B0601040181E438010104082801",
    },
    "OmnikeyReaderCoreAA": {
        "genesis_engine_id": "2B0601040181E438010103052B0101",
        "genesis_username":  "2B0601040181E43801010408290101",
    },
    "CredentialRoller": {
        "genesis_engine_id": "2B0601040181E438010103052D01",
        "genesis_username":  "2B0601040181E438010104082B01",
    },
}

# --- tiny DER helpers -------------------------------------------------------
def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def _tlv(tag, val):
    return bytes([tag]) + _len(len(val)) + val

def _int(n):
    if n == 0:
        return _tlv(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return _tlv(0x02, b)

def _octet(b=b""):
    return _tlv(0x04, b)

def _seq(*parts):
    return _tlv(0x30, b"".join(parts))


def build_discovery(msg_id=1, request_id=1, max_size=756) -> bytes:
    """SNMPv3 engine-discovery message (noAuthNoPriv). Matches the app exactly."""
    global_data = _seq(_int(msg_id), _int(max_size), _octet(b"\x04"), _int(3))
    usm = _octet(_seq(_octet(), _int(0), _int(0), _octet(), _octet(), _octet()))
    get_request = _tlv(0xA0, _int(request_id) + _int(0) + _int(0) + _seq())
    scoped = _seq(_octet(), _octet(), get_request)
    return _seq(_int(3), global_data, usm, scoped)


def parse_report(msg: bytes):
    """Extract authoritative engineId/boots/time from a reader's Report response."""
    from .artemis import ber_parse
    top = ber_parse(msg)[0]["children"]          # version, globalData, usm(octet), scoped
    usm = ber_parse(top[2]["value"])[0]["children"]
    return {
        "engine_id": usm[0]["value"].hex(),
        "engine_boots": int.from_bytes(usm[1]["value"], "big"),
        "engine_time": int.from_bytes(usm[2]["value"], "big"),
        "user_name": usm[3]["value"],
    }


if __name__ == "__main__":
    GT = "3037020103300D020101020202F40401040201030410300E0400020100020100040004000400301104000400A00B0201010201000201003000"
    got = build_discovery().hex().upper()
    print("discovery ok:", got == GT)
    if got != GT:
        print("want", GT)
        print("got ", got)
