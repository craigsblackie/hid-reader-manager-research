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


# =============================================================================
# AUTHENTICATED read/write (authPriv) -- reimplemented from HidGlobal.SDI.SnmpV3
# (decompiled). The reader's USM is CUSTOM in two ways vs RFC 3414/3826:
#   - security model number is 257 (0x101) or 258 (0x102), not 3
#   - privacy is AES-128-*CBC* (not CFB), zero-padded, IV = boots||time||salt
# Auth is standard HMAC-SHA1-96 over the whole message with the 12-byte
# msgAuthenticationParameters field zeroed, then the first 12 HMAC bytes patched
# back in. Keys are used as RAW BYTES -- the reader's auth/priv keys are issued
# by HID's Origo cloud per reader (FetchELITEConfiguration), NOT derivable
# offline (see PROTOCOL.md §3/§6). Supply them yourself for a reader you own.
# =============================================================================
import os as _os
import hmac as _hmac
import hashlib as _hashlib

# PDU tags
GET_REQUEST = 0xA0
SET_REQUEST = 0xA3
# msgFlags bits
_F_AUTH, _F_PRIV, _F_REPORTABLE = 0x01, 0x02, 0x04
_AUTH_PLACEHOLDER = b"\x00" * 12


def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    pad = (-len(data)) % 16
    data = data + b"\x00" * pad                     # zero padding (matches ConfAES)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def _hmac_sha1_96(key: bytes, msg: bytes) -> bytes:
    return _hmac.new(key, msg, _hashlib.sha1).digest()[:12]


def _priv_iv(engine_boots: int, engine_time: int, salt: bytes) -> bytes:
    return engine_boots.to_bytes(4, "big") + engine_time.to_bytes(4, "big") + salt


def build_message(request_type: int, oid: bytes = b"", value: bytes | None = None, *,
                  engine_id: bytes, user_name: bytes, engine_boots: int, engine_time: int,
                  auth_key: bytes | None = None, priv_key: bytes | None = None,
                  msg_id: int = 1, request_id: int = 1, security_model: int = 257,
                  max_size: int = 756, context_engine_id: bytes = b"", context_name: bytes = b"",
                  salt: bytes | None = None) -> bytes:
    """Build a full SNMPv3 GET/SET for the reader's config MIB.

    `oid` is DER OID *content* bytes (from oid.encode, without the 06 tag) or the
    full 06-TLV -- pass the content bytes; we wrap them. `value` is the SET value
    (octet-string content); None -> empty (for GET). auth_key/priv_key raw bytes;
    omit for lower security levels.
    """
    auth = auth_key is not None
    priv = priv_key is not None
    flags = _F_REPORTABLE | (_F_AUTH if auth else 0) | (_F_PRIV if priv else 0)

    # varbind: SEQ( OID, OCTET value )
    oid_tlv = _tlv(0x06, oid)
    var_bind = _seq(oid_tlv, _octet(value or b"")) if oid else b""
    pdu = _tlv(request_type, _int(request_id) + _int(0) + _int(0) + _seq(var_bind))
    scoped = _seq(_octet(context_engine_id), _octet(context_name), pdu)

    if priv:
        if salt is None:
            salt = _os.urandom(8)
        iv = _priv_iv(engine_boots, engine_time, salt)
        scoped_field = _octet(_aes_cbc_encrypt(priv_key, iv, scoped))
        priv_params = salt
    else:
        scoped_field = scoped
        priv_params = b""

    auth_params = _AUTH_PLACEHOLDER if auth else b""
    usm = _octet(_seq(_octet(engine_id), _int(engine_boots), _int(engine_time),
                      _octet(user_name), _octet(auth_params), _octet(priv_params)))
    global_data = _seq(_int(msg_id), _int(max_size), _octet(bytes([flags])), _int(security_model))
    msg = _seq(_int(3), global_data, usm, scoped_field)

    if auth:
        if msg.count(_AUTH_PLACEHOLDER) != 1:
            raise ValueError("auth placeholder not uniquely locatable; rebuild with a different salt")
        mac = _hmac_sha1_96(auth_key, msg)
        idx = msg.find(_AUTH_PLACEHOLDER)
        msg = msg[:idx] + mac + msg[idx + 12:]
    return msg


def build_get(oid: bytes, **kw) -> bytes:
    return build_message(GET_REQUEST, oid, None, **kw)


def build_set(oid: bytes, value: bytes, **kw) -> bytes:
    return build_message(SET_REQUEST, oid, value, **kw)


def parse_secured_response(msg: bytes, *, auth_key: bytes | None = None,
                           priv_key: bytes | None = None, verify: bool = True):
    """Verify (auth) + decrypt (priv) a reader response; return {oid, value, ...}.
    Mirrors HidGlobal.SDI.SnmpV3.ExtractData."""
    from .artemis import ber_parse
    top = ber_parse(msg)[0]["children"]                 # ver, global, usm-octet, scoped
    usm = ber_parse(top[2]["value"])[0]["children"]
    engine_id = usm[0]["value"]
    engine_boots = int.from_bytes(usm[1]["value"], "big")
    engine_time = int.from_bytes(usm[2]["value"], "big")
    auth_params = usm[4]["value"]
    priv_params = usm[5]["value"]

    if auth_key is not None and verify:
        # recompute over the message with the received MAC zeroed
        idx = msg.find(auth_params) if auth_params else -1
        zeroed = msg.replace(auth_params, _AUTH_PLACEHOLDER, 1) if auth_params else msg
        if _hmac_sha1_96(auth_key, zeroed) != auth_params:
            raise ValueError("SNMP auth (HMAC-SHA1-96) verification failed")

    scoped_raw = top[3]
    if priv_key is not None:
        iv = _priv_iv(engine_boots, engine_time, priv_params)
        scoped = _aes_cbc_decrypt(priv_key, iv, scoped_raw["value"])
    else:
        scoped = scoped_raw["value"] if scoped_raw["value"] is not None else b""
    # scoped = SEQ( ctxEngineId, ctxName, PDU{ reqId, err, erridx, varbindlist{ SEQ{oid,val} } } )
    sc = ber_parse(scoped)[0]["children"]
    pdu = sc[2]["children"]
    vbl = pdu[3]["children"]
    out = {"engine_id": engine_id.hex(), "engine_boots": engine_boots,
           "engine_time": engine_time, "varbinds": []}
    for vb in vbl:
        kids = vb["children"]
        out["varbinds"].append({"oid": kids[0]["value"].hex() if kids[0]["value"] else None,
                                "value": kids[1]["value"]})
    return out


if __name__ == "__main__":
    GT = "3037020103300D020101020202F40401040201030410300E0400020100020100040004000400301104000400A00B0201010201000201003000"
    got = build_discovery().hex().upper()
    print("discovery ok:", got == GT)
    if got != GT:
        print("want", GT)
        print("got ", got)
