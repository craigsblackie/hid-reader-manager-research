"""Decode reader config-item VALUES into labelled fields.

The credential-technology config items (DESFire/Mifare) carry BER-encoded
structures; this module holds their enums and field maps (extracted 1:1 from
HidGlobal.Asn1.ConfigurationItems, decompiled) and decodes a value blob into
named fields, resolving enum codes to names. Pairs with config_oids.py (which
names the OIDs) so `config-get` can show, e.g., a DESFIRE_EV3 value as
"version=desfireEV3, applicationType=..., readKeyOid=...".

Correct-by-construction from the schema; validate against live config data once
you have your reader's keys (see PROTOCOL.md §23-24).
"""
from . import artemis

# ---- enums (value code -> name) --------------------------------------------
ENUMS = {
    "DESFireApplicationKeyType": {0: "unknown", 2: "tdes2k", 4: "tdes3k", 9: "aes128"},
    "DESFireCommunicationSettings": {0: "plain", 1: "mac", 3: "encrypt", 255: "unknown"},
    "DESFireVersion": {0: "desfire06", 1: "desfireEV1", 2: "desfireEV2", 3: "desfireEV3", 255: "unknown"},
    "DivInputType": {1: "inputEngineDependent", 2: "csn", 3: "leafish1", 4: "leafish2", 5: "uidCustom"},
    "MifareAuthenticationKeyType": {0: "keyA", 1: "keyB", 2: "switchSL2", 3: "switchSL3"},
    "ApduResponseParserType": {0: "offset"},
}

# ---- sequence field maps: struct -> {context tag: (field_name, enum_or_None)}
SEQUENCES = {
    "DESFireCredentialStructure": {
        0: ("version", "DESFireVersion"), 1: ("applicationType", None),
        2: ("hidIsoAid", None), 3: ("staticKeyId", None), 4: ("staticKeyOid", None),
        5: ("readKeyId", None), 6: ("readKeyOid", None), 7: ("writeKeyId", None),
        8: ("writeKeyOid", None), 9: ("fileId", None), 10: ("fileOffset", None),
        11: ("readLength", None), 12: ("communicationSettings", "DESFireCommunicationSettings"),
        13: ("applicationKeyType", "DESFireApplicationKeyType"),
    },
    "MifareParams": {
        0: ("startBlock", None), 1: ("mifareAuthenticationKeyType", "MifareAuthenticationKeyType"),
        2: ("authenticationKeyOid", None),
    },
    "MifareSioConfig": {0: ("version", None), 1: ("mifareConfig", None)},
    "DiversificationConfig": {
        0: ("version", None), 1: ("type", "DivInputType"), 2: ("systemId", None),
        3: ("customData", None),
    },
    "MifareBioParams": {
        0: ("startSector", None), 1: ("maxAmountOfBlock", None),
        2: ("keyAOid", None), 3: ("keyBOid", None),
    },
}

# ---- which config OID carries which value structure (best-effort) -----------
OID_STRUCTURE = {
    "0301070140": "DESFireCredentialStructure",   # DESFIRE_EV3
    "030107020F00": "DESFireCredentialStructure",  # DESFIRE_SIO_FILE_SETTINGS (DESFire SIO)
}


def _to_int(b):
    return int.from_bytes(b, "big") if b else 0


def decode_value(structure: str, value: bytes) -> dict:
    """BER-decode a config value against a known structure; return labelled
    fields with enum names resolved. Unknown tags are kept as raw hex."""
    fields = SEQUENCES.get(structure)
    if not fields:
        return {"structure": structure or "?", "raw": value.hex(), "decoded": None}
    try:
        nodes = artemis.ber_parse(value)
        # value may be a SEQUENCE wrapping the fields, or the fields directly
        if len(nodes) == 1 and nodes[0]["constructed"] and nodes[0]["children"]:
            nodes = nodes[0]["children"]
    except Exception:
        return {"structure": structure, "raw": value.hex(), "decoded": None}
    out = {}
    for n in nodes:
        tag = n["tag"]
        fname, enum = fields.get(tag, (f"tag{tag}", None))
        v = n["value"]
        if v is None:
            out[fname] = "{...}"  # constructed sub-structure
        elif enum:
            out[fname] = ENUMS.get(enum, {}).get(_to_int(v), f"{_to_int(v)}(?)")
        else:
            out[fname] = v.hex()
    return {"structure": structure, "raw": value.hex(), "decoded": out}


def decode_for_oid(hex_oid: str, value: bytes) -> dict:
    return decode_value(OID_STRUCTURE.get(hex_oid.lower(), None), value)


def render(hex_oid: str, value: bytes) -> str:
    d = decode_for_oid(hex_oid, value)
    if not d["decoded"]:
        return f"value: {value.hex()}"
    parts = ", ".join(f"{k}={v}" for k, v in d["decoded"].items())
    return f"{d['structure']}: {parts}"
