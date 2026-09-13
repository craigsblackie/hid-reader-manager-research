"""Named-OID database extracted from HidGlobal.ArtemisManager `Constants` classes
(decompiled), plus a human-readable describer for OIDs seen on the wire.

All 30 hex constants in the app that decode as valid OIDs live under the same
enterprise arc: 1.3.6.1.4.1.29240 (see oid.py for the PEN-29240 correction).
They fall into three families:
  1.1.2.1.24.1...   PACS/SEOS credential ADF addressing (STANDARD_PACS_ADF_OID
                     and, empirically, per-deployment non-standard SIO objects)
  1.1.3.5....        SNMPv3 USM engineId identities (Genesis/HidAdmin/SnmpLoader,
                      per reader family: RevE/SLE88, ST33J, Stingray, ...)
  1.1.4.8....        SNMPv3 USM usernames (same families)
"""
from . import oid

PACS_ADF_BASE = "1.3.6.1.4.1.29240.1.1.2.1.24.1"

# name -> dotted OID (extracted 1:1 from decompiled `public const string X = "<hex>"`)
NAMED_OIDS = {
    "STANDARD_PACS_ADF_OID":            "1.3.6.1.4.1.29240.1.1.2.1.24.1.1.2.2",
    # SNMPv3 engineId identities (SnmpIdentityValueType.GenesisEngineId / HidAdminEngineId)
    "SnmpLoaderRootEngineId(CCM/candidate1)": "1.3.6.1.4.1.29240.1.1.3.5.12.10.1",
    "SnmpLoaderRootEngineId(CCM/candidate2)": "1.3.6.1.4.1.29240.1.1.3.5.12.11.1",
    "SnmpLoaderRootEngineId(CCM/candidate3)": "1.3.6.1.4.1.29240.1.1.3.5.12.12",
    "SLE88_GENESIS_ENGINEID_RAPTOR":    "1.3.6.1.4.1.29240.1.1.3.5.20.1",
    "ST33J_GENESIS_ENGINEID":           "1.3.6.1.4.1.29240.1.1.3.5.29.1",
    "GenesisEngineId(OmnikeyReaderCoreHID)": "1.3.6.1.4.1.29240.1.1.3.5.41.1.1",
    "HidAdminEngineId(OmnikeyReaderCoreHID)":"1.3.6.1.4.1.29240.1.1.3.5.42.1",
    "GenesisEngineId(OmnikeyReaderCoreAA)":  "1.3.6.1.4.1.29240.1.1.3.5.43.1.1",
    "HidAdminEngineId(OmnikeyReaderCoreAA)": "1.3.6.1.4.1.29240.1.1.3.5.44.1",
    "GenesisEngineId(CredentialRoller)":     "1.3.6.1.4.1.29240.1.1.3.5.45.1",
    "HidAdminEngineId(CredentialRoller)":    "1.3.6.1.4.1.29240.1.1.3.5.46",
    "SLE88_GENESIS_ENGINEID":           "1.3.6.1.4.1.29240.1.1.3.5.6.1",
    # SNMPv3 USM usernames
    "SnmpLoaderRootUsername(cand1)":    "1.3.6.1.4.1.29240.1.1.4.8.13.10",
    "SnmpLoaderRootUsername(cand2)":    "1.3.6.1.4.1.29240.1.1.4.8.13.8.1",
    "SnmpLoaderRootUsername(cand3)":    "1.3.6.1.4.1.29240.1.1.4.8.13.9.1",
    "HID_ADMIN_USERNAME":               "1.3.6.1.4.1.29240.1.1.4.8.15",
    "HID_ADMIN_USERNAME_V2":            "1.3.6.1.4.1.29240.1.1.4.8.15.5",
    "SLE88_GENESIS_USERNAME_RAPTOR":    "1.3.6.1.4.1.29240.1.1.4.8.19.1",
    "HID_ADMIN_USERNAME_RAPTOR":        "1.3.6.1.4.1.29240.1.1.4.8.20",
    "HID_ADMIN_ENGINEID_STINGRAY":      "1.3.6.1.4.1.29240.1.1.4.8.21",
    "ST33J_GENESIS_USERNAME":           "1.3.6.1.4.1.29240.1.1.4.8.21.1",
    "HID_ADMIN_USERNAME_STINGRAY":      "1.3.6.1.4.1.29240.1.1.4.8.22",
    "GenesisUsername(OmnikeyReaderCoreHID)": "1.3.6.1.4.1.29240.1.1.4.8.39.1.1",
    "SLE88_GENESIS_USERNAME":           "1.3.6.1.4.1.29240.1.1.4.8.4",
    "HidAdminUsername(OmnikeyReaderCoreHID)":"1.3.6.1.4.1.29240.1.1.4.8.40.1",
    "GenesisUsername(OmnikeyReaderCoreAA)":  "1.3.6.1.4.1.29240.1.1.4.8.41.1.1",
    "HidAdminUsername(OmnikeyReaderCoreAA)": "1.3.6.1.4.1.29240.1.1.4.8.42.1",
    "GenesisUsername(CredentialRoller)":     "1.3.6.1.4.1.29240.1.1.4.8.43.1",
    "HidAdminUsername(CredentialRoller)":    "1.3.6.1.4.1.29240.1.1.4.8.44",
}
OID_TO_NAME = {v: k for k, v in NAMED_OIDS.items()}


def describe(dotted_or_bytes) -> dict:
    """Human-readable description of one OID. Accepts a dotted string or raw bytes."""
    dotted = dotted_or_bytes if isinstance(dotted_or_bytes, str) else oid.try_decode(dotted_or_bytes)
    if dotted is None:
        return {"oid": None, "raw": dotted_or_bytes.hex() if isinstance(dotted_or_bytes, bytes) else None,
                "kind": "undecodable", "description": "not a valid DER OID"}

    if dotted in OID_TO_NAME:
        return {"oid": dotted, "kind": "known", "name": OID_TO_NAME[dotted],
                "description": f"known constant: {OID_TO_NAME[dotted]}"}

    if dotted.startswith(PACS_ADF_BASE + "."):
        suffix = dotted[len(PACS_ADF_BASE) + 1:]
        parts = suffix.split(".")
        subtype = parts[0] if parts else "?"
        object_id = ".".join(parts[1:-1]) if len(parts) > 2 else (parts[1] if len(parts) > 1 else "?")
        variant = parts[-1] if len(parts) > 1 else "?"
        subtype_note = {"1": "standard PACS subtype", "6": "subtype 6 (uncommon -- seen once live)"}
        return {
            "oid": dotted, "kind": "pacs_adf_candidate",
            "base": PACS_ADF_BASE, "subtype": subtype, "object_id": object_id, "variant": variant,
            "description": (
                f"SEOS PACS ADF candidate under STANDARD_PACS_ADF_OID's tree "
                f"(subtype={subtype} [{subtype_note.get(subtype, 'unrecognised subtype')}], "
                f"object_id={object_id}, variant={variant}). "
                + ("Matches no built-in app constant -> this is a customer/deployment-specific "
                   "SIO object configured on THIS reader, not a generic HID default."
                   if object_id not in ("2",) else "This is the generic/standard PACS object.")
            ),
        }

    if dotted.startswith("1.3.6.1.4.1.29240."):
        # unknown OID under HID's enterprise arc -- find nearest known prefix for context
        best = None
        for name, val in NAMED_OIDS.items():
            if dotted.startswith(val.rsplit(".", 1)[0] + "."):
                if best is None or len(val) > len(best[1]):
                    best = (name, val)
        note = f" (near {best[0]}: {best[1]})" if best else ""
        return {"oid": dotted, "kind": "hid_enterprise_unknown",
                "description": f"under HID's enterprise OID arc (29240) but not a known named constant{note}"}

    return {"oid": dotted, "kind": "unrelated",
            "description": "not under HID's enterprise OID arc (1.3.6.1.4.1.29240)"}


def summarize(dotted_oids: list) -> dict:
    """Group a list of OIDs into a plain-language summary: how many are HID
    standard defaults vs. non-standard/customer-specific, and group the latter
    by object_id (merging variants like 11571.1/2/7 into one entry)."""
    standard, custom = [], {}
    for d in dotted_oids:
        info = describe(d)
        if info["kind"] == "known":
            standard.append(info["name"])
        elif info["kind"] == "pacs_adf_candidate" and info.get("object_id") not in ("2",):
            custom.setdefault(info["object_id"], []).append(info.get("variant"))
        else:
            custom.setdefault(d, []).append(None)
    custom_lines = []
    for obj_id, variants in custom.items():
        vs = sorted(v for v in variants if v is not None)
        custom_lines.append(f"object {obj_id}" + (f" (variants: {', '.join(vs)})" if vs else ""))
    return {"standard": standard, "custom": custom_lines,
            "standard_count": len(standard), "custom_count": len(custom)}
