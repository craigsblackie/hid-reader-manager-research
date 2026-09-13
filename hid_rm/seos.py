"""SEOS applet framing that the reader speaks on the BLE data characteristic.

On connect the reader auto-selects the SEOS applet and speaks a 1-byte-header
BLE framing (observed live + BleMessages in HidGlobal.ArtemisManager):

  reader->phone : 0x81 <SELECT-AID apdu>   (reader auto-selects SEOS)
                  0x40 <FCI/select-result TLV>
                  0xC0 <select-AID response>
                  0xE1 <status>   (EOT: 0xE0|1; 2nd byte 1=SUCCESS 2=SAM_REJECTED
                                    3=ANTIPASSBACK 4=CON_TIMEOUT 5=FRAG_TIMEOUT
                                    6=MSG_TIMEOUT 7=LEN_ERR 8=DFU 9=FLASH 10=CFG_FORBIDDEN)
  phone->reader : 0x40                      (poll/read)
                  0x84 00 / 0x8C 00         (GET_PROPERTIES / _2)
                  0xE5 <fragment>           (CONFIGURATION fragment)

SEOS applet AID (from live capture): A0000004400001010001 (+ 00 00 47 05 tail).

UNAUTHENTICATED read path (SeosConnection.readAlgorithmInfo, decompiled):
  SELECT SEOS by AID -> selectGdfWithPrivacy(GenesisPrivacyKeyset) -> algorithmInfo()
The Genesis privacy keyset is the SEOS factory-DEFAULT keyset (embedded in the app,
diversified in obfuscated AAMK code). With it you can select the GDF and read
AlgorithmInfo (SEOS id + supported crypto) with NO cloud auth. Reading ADF config
data additionally needs an AUTHENTICATION keyset (SessionParameters.authenticationKeyset),
which for reader-management is cloud-provisioned -- that is the wall for full config.
"""

# SEOS_AID_BASE matches Constants.AID.STANDARD_SEOS exactly (10 bytes).
# SEOS_AID is the FULL on-wire AID the reader actually SELECTs (16 bytes, Lc=0x10) --
# recomputed precisely from a live capture using the APDU's own Lc field (earlier
# notes, from both agents, undercounted this by 2 bytes: "...004705" without the
# trailing "2b03"). Verified: CLA=00 INS=A4 P1=04 P2=00 Lc=16 <16-byte AID> Le=00.
SEOS_AID_BASE = bytes.fromhex("A0000004400001010001")                       # 10 bytes
SEOS_AID = bytes.fromhex("A0000004400001010001000047052B03")                # 16 bytes (live-verified)
SELECT_SEOS_16 = bytes([0x00, 0xA4, 0x04, 0x00, len(SEOS_AID)]) + SEOS_AID + bytes([0x00])  # + Le
SELECT_SEOS_10 = bytes([0x00, 0xA4, 0x04, 0x00, len(SEOS_AID_BASE)]) + SEOS_AID_BASE

# 1-byte BLE headers (EXTENSION_TYPE=7 -> 0xE0 base)
HDR_SELECT   = 0x81
HDR_FCI      = 0x40
HDR_RESP     = 0xC0
HDR_EOT      = 0xE1
EOT_STATUS = {1: "SUCCESS", 2: "SAM_REJECTED", 3: "ANTIPASSBACK", 4: "CON_TIMEOUT",
              5: "FRAG_TIMEOUT", 6: "MSG_TIMEOUT", 7: "LEN_ERROR", 8: "DFU_ERROR",
              9: "FLASH_ERROR", 10: "CONFIG_FORBIDDEN"}
GET_PROPERTIES  = bytes([0x84, 0x00])
GET_PROPERTIES2 = bytes([0x8C, 0x00])
POLL            = bytes([0x40])


def describe(frame: bytes) -> str:
    if not frame:
        return "(empty)"
    h = frame[0]
    if h == HDR_EOT and len(frame) >= 2:
        return f"EOT status={EOT_STATUS.get(frame[1], frame[1])}"
    names = {HDR_SELECT: "SELECT", HDR_FCI: "FCI/poll", HDR_RESP: "SELECT-RESP"}
    return f"{names.get(h, hex(h))}: {frame.hex()}"


# =============================================================================
# AAMK deep-dive results (static, from classes.dex bytecode -- no Frida)
# =============================================================================

# CONFIRMED from raw bytecode of GenesisPrivacyKeyset$GenesisSymmetricKey.<init>:
#   EncryptionAlgorithm.AES_128; new byte[blockSize()=16]; super(AES_128, zeros)
# -> the SEOS Genesis (factory-default) PRIVACY key is 16 zero bytes, AES-128,
#    with NO diversification. encrypt() returns empty, so Genesis "privacy" is
#    effectively plaintext (a factory reader has no transport-privacy protection).
GENESIS_PRIVACY_KEY = bytes(16)          # 00*16, AES-128
GENESIS_PRIVACY_KEYREF = 0x00

# SEOS applet + APDU set (from com.assaabloy.seos.access.apdu.SeosApduFactory).
# CLA: 0x00 standard, 0x80 proprietary.
INS_SELECT_AID          = 0xA4
INS_SELECT_ADF          = 0xA5
INS_CORE_ADMINISTRATION = 0x15
INS_AUTHENTICATE        = 0x87   # GET_CHALLENGE / MUTUAL_AUTH (AKE)
INS_GET_DATA_SEOS       = 0xCB
INS_PUT_DATA_SEOS       = 0xDB
INS_FS_OPS              = 0xE6
INS_GEN_KEYPAIR         = 0x47
INS_AMR                 = 0x41

def seos_select_aid(aid: bytes = SEOS_AID) -> bytes:
    return bytes([0x00, INS_SELECT_AID, 0x04, 0x00, len(aid)]) + aid

def seos_select_gdf(keyref: int = 0) -> bytes:
    # selectGlobalAdf: 80 A5 07 <keyref>  (P1 = SELECT_GLOBAL_P1 = 7)
    return bytes([0x80, INS_SELECT_ADF, 0x07, keyref & 0xFF])

def seos_read_all_metadata(secure=False, priv=False) -> bytes:
    # 80 15 01 <flags> 06 00   -- reads object/ADF metadata (unauth on factory)
    flags = (1 if secure else 0) | (2 if priv else 0)
    return bytes([0x80, INS_CORE_ADMINISTRATION, 0x01, flags, 0x06, 0x00])

def seos_get_challenge(keyref: int, data: bytes = b"") -> bytes:
    # 00 87 00 <keyref> <data>  -- starts the AKE; needs an auth keyset to finish
    return bytes([0x00, INS_AUTHENTICATE, 0x00, keyref & 0xFF, len(data)]) + data

# NOTE on layering: against a reader these SEOS APDUs travel inside the reader's
# SEOS session over the 1-byte-header BLE framing above. With the Genesis zero
# privacy key you can SELECT the GDF and read AlgorithmInfo / metadata (no cloud
# auth). Reading ADF *data* needs an AUTHENTICATION keyset (symmetric master key
# or asymmetric ECC keypair) which is caller/cloud-provided -- NOT in the app.
# Reader *config* is a separate SNMPv3-gated MIB (see snmpv3.py) either way.


# =============================================================================
# BLE "Extension" frames (BleMessages, HidGlobal.ArtemisManager -- decompiled)
# Same 1-byte-header scheme as ProtocolV1Fragment but in the 0xE0-0xFF range:
# header = (EXTENSION_TYPE=7 << 5) | message_type. This is a THIRD sub-protocol
# on the same characteristic, distinct from both the ISO7816 credential-read
# exchange and the [len][APDU][CRC]-framed Artemis/SNMP GET_DATA channel.
# We've received 0xE1 (END_OF_TRANSACTION/status) FROM the reader throughout
# this research but never tried SENDING an extension frame ourselves -- untested
# until now (see PROTOCOL.md §11).
# =============================================================================
EXT_END_OF_TRANSACTION = 0xE0 | 1   # 0xE1 -- status (already reverse-engineered, EOT_STATUS above)
EXT_FW_UPDATE           = 0xE0 | 2  # 0xE2
EXT_CONFIGURATION       = 0xE0 | 5  # 0xE5

REQUEST_GET_PROPERTIES  = bytes([0x84, 0x00])
REQUEST_GET_PROPERTIES2 = bytes([0x8C, 0x00])
REQUEST_INIT_FLASH      = bytes([0x84, 0x00])       # same bytes, different context (FW_UPDATE frame)
REQUEST_INIT_FLASH_ACK  = bytes([0x84, 0x82, 0x00, 0x00])


def ext_frame(msg_type: int, payload: bytes) -> bytes:
    """One BLE write for an Extension-type message (single-fragment; payload
    must fit the negotiated MTU minus 4 bytes for ATT/header overhead)."""
    return bytes([0xE0 | msg_type]) + payload
