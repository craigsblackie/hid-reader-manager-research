"""Reader config-item OID map -- names and human-readable settings.

Extracted 1:1 from the named `public const string X = "<hex-oid>"` constants in
HidGlobal.ArtemisManager (decompiled). These are the OID identifiers the reader
uses for its configuration MIB items; each maps to a setting the HID Reader
Manager app reads/writes. Use them with `config-get`/`config-set` (by hex OID or
by name) once you have your reader's Origo-issued keys (see PROTOCOL.md §23),
or to name OIDs seen in an unauthenticated capture.

Each entry: hex OID -> (canonical_name, human_label, category, dangerous?).
`dangerous` flags settings that change reader mode / bootloader / key material
(don't write these without knowing exactly what you're doing on a reader you own).

NOTE on OID form: these are the short reader-internal config OIDs (e.g.
"030107012A"), as the app stores them. The SNMP wire form may need the reader's
config-tree prefix; `config-set` for these OIDs goes through the app's same
DeterministicProvisioning path. The name<->OID mapping here is exact regardless.
"""

# hex OID: (name, human label, category, dangerous)
CONFIG_OIDS = {
    # ---- reader mode / identity ----
    "03000701":     ("READER_MODE", "Reader operating mode", "mode", True),
    "0301070109":   ("PRODUCT_SERIAL_NUMBER", "Product serial number", "identity", False),
    "0301070138":   ("ICE_NUMBER", "ICE (customer) number", "identity", False),
    "0301070178":   ("DEVICE_MANAGEMENT_UUID", "Device management UUID", "identity", False),
    "0301070901":   ("HID_IDENTITY", "HID identity object", "identity", False),
    "03010704":     ("OEM_ADMIN_USERNAME", "OEM admin SNMP username", "identity", False),
    "03010705":     ("OEM_ADMIN_ENGINEID", "OEM admin SNMP engineId", "identity", False),
    "0301070132":   ("OEM_WHITELIST", "OEM whitelist", "security", False),

    # ---- credential technology config ----
    "0301070120":   ("CHUID_CONFIG", "CHUID (PIV/CAC) config", "credential", False),
    "0301070140":   ("DESFIRE_EV3", "MIFARE DESFire EV3 config", "credential", False),
    "030107017C":   ("DESFIRE_PROXIMITYCHECK", "DESFire proximity-check config", "credential", False),
    "030107020F00": ("DESFIRE_SIO_FILE_SETTINGS", "DESFire SIO file settings", "credential", False),
    "030107030101": ("EM_PROXIMITY_OUTPUT_FORMAT", "EM (125kHz) prox output format", "credential", False),
    "030107020205": ("SEOS_PACS_CONFIG", "SEOS PACS config / card-edge key set (R8)", "credential", True),
    "030107020206": ("SEOS_AIDS_ORDERED_LIST", "SEOS AIDs ordered list", "credential", False),
    "030107020E00": ("SEOS_ADMIN_CARD_APP", "SEOS admin-card application config (R8)", "credential", True),

    # ---- output / host interface ----
    "030107012A":   ("MEDIA_OUTPUT", "Media output (Wiegand/format) config", "output", False),
    "0301070169":   ("CSN_OUTPUT_CONFIG", "CSN output config", "output", False),
    "0301070151":   ("OSDP_CONFIGURATION", "OSDP configuration", "output", False),
    "030107017E":   ("OSDP_TRANSPARENT_MODE", "OSDP transparent mode", "output", False),
    "030107030C00": ("OSDP_REVERSE_CRC", "OSDP reverse CRC", "output", False),
    "030107014C":   ("EXTERNAL_UART_CONFIGURATION", "External UART config", "output", False),
    "0301070179":   ("SIGNO_UART_CONFIGURATION", "Signo UART config", "output", False),
    "030107016D":   ("I2C_WHITELIST", "I2C whitelist", "output", False),
    "0301070150":   ("STARTUP_DATA_TRANSFER", "Startup data transfer", "output", False),

    # ---- visual / audio feedback ----
    "030107010A":   ("LED_COLOR", "Default LED colour", "feedback", False),
    "0301070136":   ("SLAVE_MODE_RF_ACTIVITY_LED_COLOR", "Slave-mode RF-activity LED colour", "feedback", False),
    "030107010B":   ("VISUAL_MEDIA_ACCEPTED", "Visual: media accepted", "feedback", False),
    "0301070126":   ("VISUAL_MEDIA_REFUSED", "Visual: media refused", "feedback", False),
    "0301070134":   ("VISUAL_START_REPORT", "Visual: start report", "feedback", False),
    "0301070135":   ("VISUAL_END_REPORT", "Visual: end report", "feedback", False),
    "030107020201": ("SEOS_VISUAL_MEDIA_ACCEPTED", "SEOS visual: media accepted", "feedback", False),
    "030107020202": ("SEOS_CARDEDGE_START_REPORT", "SEOS card-edge start report (audio/visual)", "feedback", False),
    "030107020203": ("SEOS_CARDEDGE_END_REPORT", "SEOS card-edge end report (audio/visual)", "feedback", False),

    # ---- keypad / PIN ----
    "030107012F":   ("KEYPAD_CONFIGURATION", "Keypad configuration", "keypad", False),
    "0301070175":   ("ENHANCED_KEYPAD_CONFIG", "Enhanced keypad config", "keypad", False),
    "0301070159":   ("PIN_CONFIGURATION", "PIN configuration", "keypad", False),

    # ---- BLE / mobile / ECP ----
    "030107030A04": ("DEVICE_NAME_BLE", "BLE device name", "ble", False),
    "030107030A03": ("DEVICE_SCAN_RESPONSE_DATA", "BLE scan-response data", "ble", False),
    "030107030A1B": ("BLE_CENTRAL_PARAMETER_DATA", "BLE central parameter data", "ble", False),
    "030107030A21": ("SIGNO_BLE_PERMANENT_DISABLE", "Signo BLE permanent disable", "ble", True),
    "0301070170":   ("ECP_TCI", "Apple ECP TCI value", "ble", False),
    "030107017000": ("ECP_MODE_CONFIG", "Apple ECP mode config", "ble", False),
    "030107017001": ("ECP_MFA_MODE", "Apple ECP MFA mode", "ble", False),

    # ---- security / tamper / anti-attack ----
    "0301070107":   ("OPTICAL_TAMPER_CHECK", "Optical tamper-check config", "security", False),
    "0301070128":   ("VISUAL_TEMPLATE_ATTACK_DETECTED", "Visual template-attack-detected", "security", False),
    "030107012E":   ("VELOCITY_CHECK", "Velocity (anti-passback) check", "security", False),

    # ---- RF / power / tuning ----
    "0301070133":   ("INTELLIGENT_POWER_MANAGEMENT", "Intelligent power management", "power", False),
    "0301070137":   ("HF_FIELD_STABILIZATION_DELAY", "HF field-stabilization delay", "power", False),
    "030107030F":   ("METAL_TUNING", "Metal-surface tuning", "power", False),
    "0301070305":   ("HF_REGISTERS_SETTINGS", "HF/EEPROM register settings", "power", False),
    "0301070161":   ("AUTONOMOUS_MODE_POLLING", "Autonomous-mode polling config", "power", False),
    "0301070171":   ("SIGNO_SOFT_CHARGING", "Signo soft-charging profile", "power", False),

    # ---- provisioning / config-card / bookkeeping ----
    "0301070129":   ("CONFIG_CARD_TIMEOUT", "Config-card timeout", "provisioning", False),
    "030107015F":   ("DATAMODELS_VS_PROTOCOL_TABLE", "Data-models vs protocol table (R8)", "provisioning", False),
    "030107030A1E": ("PROPERTY_VERSION_LIST", "Device property-version list", "provisioning", False),
    "03000306":     ("STORE_OPERATION_PARTIAL_READ", "Store op: partial read", "provisioning", False),
    "03000309":     ("STORE_OPERATION_ATOMIC_UPDATE", "Store op: atomic update", "provisioning", False),

    # ---- bootloader / mode switches (DANGEROUS) ----
    "03000001":     ("SWITCH_TO_SNMPLOADER", "Switch to SNMP loader", "bootloader", True),
    "0301070157":   ("SWITCH_TO_DISPATCHER_BOOTLOADER", "Switch to dispatcher bootloader", "bootloader", True),
    "030107016C":   ("SWITCH_TO_SMART_MODULE_BOOTLOADER", "Switch to smart-module bootloader", "bootloader", True),
}

# name (canonical or common alias) -> hex OID
_ALIASES = {
    "SEOSPACS": "030107020205", "PACS_CONFIG": "030107020205",
    "SEOS_CARD_EDGE_KEY_SET": "030107020205",
    "ADMIN_CONFIG": "030107020E00", "SEOSADMINCARDAPP": "030107020E00",
    "DEVICE_NAME": "030107030A04", "EEPROM_REGISTERS": "0301070305",
    "KEYPAD_CONFIG": "030107012F", "PIN_CONFIG": "0301070159",
}
NAME_TO_OID = {v[0]: k for k, v in CONFIG_OIDS.items()}
NAME_TO_OID.update(_ALIASES)


def resolve(oid_or_name: str) -> str:
    """Accept a hex OID or a setting name; return the hex OID (or the input if
    already a hex OID we don't recognise)."""
    s = oid_or_name.strip()
    up = s.upper().replace("-", "_").replace(" ", "_")
    if up in NAME_TO_OID:
        return NAME_TO_OID[up]
    return s.lower()


def describe(hex_oid: str) -> dict:
    e = CONFIG_OIDS.get(hex_oid.lower())
    if not e:
        return {"oid": hex_oid, "known": False, "label": None}
    return {"oid": hex_oid, "known": True, "name": e[0], "label": e[1],
            "category": e[2], "dangerous": e[3]}


def render_catalog(category: str = None) -> str:
    lines = ["Reader config settings (name -> OID):"]
    cats = {}
    for oid, (name, label, cat, danger) in sorted(CONFIG_OIDS.items(), key=lambda kv: (kv[1][2], kv[1][0])):
        if category and cat != category:
            continue
        cats.setdefault(cat, []).append((name, oid, label, danger))
    for cat in sorted(cats):
        lines.append(f"\n[{cat}]")
        for name, oid, label, danger in cats[cat]:
            flag = "  ⚠ DANGEROUS" if danger else ""
            lines.append(f"  {name:32} {oid:14} {label}{flag}")
    return "\n".join(lines)
