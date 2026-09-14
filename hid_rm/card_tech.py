"""Card/credential technology posture summary.

Combines what this tool can actually verify live (an unauthenticated config
item is present and non-empty -- real evidence) with what the reader owner
has confirmed out-of-band from their own knowledge of the hardware (e.g. its
model/spec sheet). The two are kept clearly separate in the rendered report:
conflating "detected on the wire" with "the owner told us" would misrepresent
what this tool actually proved.

iCLASS / iCLASS SE in particular: this reader supports both (confirmed by its
owner), but neither has a config-item OID in our catalog to test against --
HID's client code keys iCLASS/Picopass support off SAM *library hivecodes*
(PicopassCardEdgeLibraryHivecode, PicopassApiLibraryHivecode,
iClassApiLibraryHivecode -- decompiled `HidGlobal.ArtemisManager` constants),
which live outside the config MIB this tool walks (see PROTOCOL.md sec:33/34).
Until that hivecode/assemblies-list command is reverse-engineered, iCLASS
support is not independently verifiable through this tool -- it's reported
here because the owner told us, not because we detected it.
"""

# Live-inferable: (label, [OIDs whose presence/non-empty value is evidence], note)
LIVE_EVIDENCE = [
    ("SEOS", ["030107020205", "030107020E00", "030107020206"],
     "SEOS PACS / admin-card key-set structure and/or AID list present"),
    ("MIFARE DESFire EV3", ["0301070140", "030107020F00"],
     "DESFire EV3 credential / SIO file config present"),
    ("EM 125kHz proximity", ["030107030101"],
     "EM prox output format configured"),
]

# Config slot exists in the catalog, but reads refused unauthenticated --
# presence of the *slot* isn't evidence either way of whether it's enabled.
GATED_EVIDENCE = [
    ("CHUID / PIV", ["0301070120"]),
    ("DESFire proximity-check", ["030107017C"]),
]

# No config-item OID mapped at all -- can't be probed by this tool yet.
# Reported here strictly because the reader owner confirmed it, not because
# anything was detected.
OWNER_CONFIRMED = [
    ("iCLASS", "no config-item OID mapped in this catalog; iCLASS/Picopass "
               "entitlement lives in SAM library hivecodes, not the config MIB"),
    ("iCLASS SE", "same gap as iCLASS -- not yet independently verifiable"),
]


def render(results: dict) -> str:
    """`results`: {oidhex (any case): bytes value or None}, as produced by
    tools/live_full_config_pull.py's live sweep."""
    lower = {k.lower(): v for k, v in results.items()}
    lines = ["Card technologies", ""]

    detected_any = False
    for label, oids, note in LIVE_EVIDENCE:
        present = [o for o in oids if lower.get(o.lower())]
        if present:
            detected_any = True
            lines.append(f"  [DETECTED live, unauthenticated]  {label}")
            lines.append(f"      {note}")
    if not detected_any:
        lines.append("  (nothing detected this run -- reader may be busy/unreachable for some items)")

    gated = []
    for label, oids in GATED_EVIDENCE:
        seen = [o for o in oids if o.lower() in lower]
        if seen and all(lower.get(o.lower()) is None for o in seen):
            gated.append(label)
    if gated:
        lines.append("")
        lines.append("  Config slot exists but refused unauthenticated (enabled/disabled undetermined):")
        for label in gated:
            lines.append(f"      {label}")

    lines.append("")
    lines.append("  Also supported on this reader per the owner (NOT detected by this tool):")
    for label, note in OWNER_CONFIRMED:
        lines.append(f"  [OWNER-CONFIRMED, not live-verified]  {label}")
        lines.append(f"      {note}")

    return "\n".join(lines)
