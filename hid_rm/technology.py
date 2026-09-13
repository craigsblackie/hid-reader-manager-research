"""Map what the unauthenticated discovery loop observes (SEOS PACS ADF OIDs and
the AIDs the reader cycles) onto HID Reader Manager's own credential-technology
vocabulary, so `hid_rm` answers "what card technologies is this reader set up
for?" in the app's terms.

Reader Manager models every credential/key as a
`KeyListConfiguration.KeyType` (decompiled from HidGlobal.ArtemisManager):
    ReaderAdmin, MobileAdmin, MobileAccess, Seos, IClass, IClassSE, IClassSR,
    MifareDesfireEV3, MifareDesfireEV1, GoogleWallet, AppleWallet, SamsungWallet

IMPORTANT honesty boundary: the unauthenticated discovery loop only reveals what
the reader *advertises* while hunting for a credential — chiefly its SEOS PACS
ADF(s) and the admin/updater AIDs. It does NOT enumerate the reader's full
per-technology key list (iCLASS/MIFARE/wallet enable flags live in the
auth-gated config MIB). So this module reports two tiers:
  - "configured (seen on the wire)"  — proven by the discovery loop
  - "requires authenticated read"    — can't be confirmed without a mobile key
See MOBILE_KEYS.md for why the authenticated tier is out of reach.
"""

# Reader Manager KeyType names (ground truth, for consistent labelling).
KEY_TYPES = [
    "ReaderAdmin", "MobileAdmin", "MobileAccess", "Seos", "IClass", "IClassSE",
    "IClassSR", "MifareDesfireEV3", "MifareDesfireEV1", "GoogleWallet",
    "AppleWallet", "SamsungWallet",
]

# HID application RID families seen in reader AIDs (from Constants.AID / live).
RID_SEOS_STANDARD = bytes.fromhex("a000000440")  # STANDARD_SEOS = a0000004400001010001
RID_HID_MOBILE = bytes.fromhex("a000000676")     # A0000006 76... probed live (mobile/SEOS access)
RID_HID_READER = bytes.fromhex("a000000382")     # a0000003 82... reader admin/updater/operation AIDs


def classify(report: dict) -> dict:
    """Given a leak/enumerate report (dict with 'oids' and 'aids'), return a
    technology posture: which KeyType technologies are proven configured from
    unauthenticated discovery, plus mobile-key posture and what's still gated."""
    oids = report.get("oids", [])
    aids = report.get("aids", [])
    aid_names = {a["name"] for a in aids}
    aid_hexes = [a["hex"] for a in aids]

    confirmed = []  # (KeyType, evidence)

    # SEOS / PACS: any PACS ADF OID (known standard or customer SIO object).
    pacs = [o for o in oids if o.get("kind") in ("known", "pacs_adf_candidate")
            and ("PACS" in str(o.get("name", "")) or o.get("kind") == "pacs_adf_candidate")]
    if pacs:
        confirmed.append(("Seos", f"reader offered {len(pacs)} SEOS/PACS ADF credential object(s)"))

    # Standard SEOS AID advertised directly.
    if any(bytes.fromhex(h).startswith(RID_SEOS_STANDARD) for h in aid_hexes):
        confirmed.append(("Seos", "standard SEOS AID (A0000004 40) advertised"))

    # Mobile admin: reader cycles the mobile SEOS admin-card AIDs.
    mobile_admin_aids = [n for n in aid_names
                         if "MOBILE_SEOS_ADMIN" in n or "OPERATION_SELECTOR" in n]
    if mobile_admin_aids:
        confirmed.append(("MobileAdmin",
                          "reader expects a mobile admin card ("
                          + ", ".join(sorted(mobile_admin_aids)) + ")"))

    # Mobile access: HID mobile credential-family AID probed (A0000006 76...).
    hid_mobile = [h for h in aid_hexes if bytes.fromhex(h).startswith(RID_HID_MOBILE)]
    if hid_mobile:
        confirmed.append(("MobileAccess",
                          "reader probes a HID mobile/SEOS access credential AID "
                          + "(A0000006 76 family): " + ", ".join(hid_mobile)))

    # Reader admin / updater modes (not a card tech, but part of parity picture).
    admin_modes = sorted(n for n in aid_names
                         if "UPDATER" in n or "ADMIN" in n or "PASSTHROUGH" in n
                         or "OPERATION_SELECTOR" in n)

    # Technologies Reader Manager knows about but that the UNAUTHENTICATED path
    # cannot confirm on/off — they live in the gated config.
    confirmed_types = {t for t, _ in confirmed}
    gated = [t for t in ("IClass", "IClassSE", "IClassSR", "MifareDesfireEV3",
                         "MifareDesfireEV1", "GoogleWallet", "AppleWallet", "SamsungWallet")
             if t not in confirmed_types]

    return {
        "confirmed": confirmed,
        "confirmed_types": sorted(confirmed_types),
        "admin_modes": admin_modes,
        "accepts_mobile_keys": bool(mobile_admin_aids or hid_mobile),
        "gated_unknown": gated,
    }


def render(report: dict, verbose: bool = False) -> str:
    t = classify(report)
    lines = ["Credential technologies (Reader Manager KeyType vocabulary):"]
    if t["confirmed"]:
        seen = {}
        for kt, ev in t["confirmed"]:
            seen.setdefault(kt, []).append(ev)
        for kt, evs in seen.items():
            lines.append(f"  ✓ {kt} — configured (seen on the wire)")
            if verbose:
                for ev in evs:
                    lines.append(f"        · {ev}")
    else:
        lines.append("  (no credential technology proven from this discovery run)")

    lines.append("")
    lines.append("Mobile keys: "
                 + ("this reader is configured to USE mobile keys "
                    "(mobile admin card and/or HID mobile access credential probed)."
                    if t["accepts_mobile_keys"] else
                    "no mobile-key admin/access AIDs observed this run."))
    if t["admin_modes"] and verbose:
        lines.append("  admin/management AIDs seen: " + ", ".join(t["admin_modes"]))

    lines.append("")
    lines.append("Not determinable without an authenticated (mobile-key) read — "
                 "these live in the gated config MIB:")
    lines.append("  " + ", ".join(t["gated_unknown"]))
    lines.append("  (see MOBILE_KEYS.md: the admin mobile key needed to read/change these")
    lines.append("   is cloud-issued, device-bound and non-exportable.)")
    return "\n".join(lines)
