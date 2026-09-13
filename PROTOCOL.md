# HID Reader Manager — reverse-engineered protocol & Python reimplementation

Scope: HID Reader Manager 1.33.1 managing HID **Signo / iCLASS SE / MultiClass SE**
readers over **BLE** (also NFC/serial). Everything here is derived from the
decompiled app (`decompiled/`) and, where marked *[ground-truth]*, from running the
app's own encoders under .NET.

## 0. TL;DR — can you pull the full config without authentication?

**No — not the real config.** The reader configuration is an **SNMPv3 MIB**. Reading
the config OIDs (enabled technologies, key references, Wiegand/OSDP output, etc.)
requires an SNMPv3 **auth key + priv key**, and those keys are **not in the app** —
they are computed **server-side by HID's Origo cloud** (SDS/SDI micro-service:
`UpdateCredential`, `FetchELITEConfiguration`, `iCLASSKeyManagement`, `KeyRoll…`,
each called with the reader's engineId+username by an authenticated user, for that
user's own organisation's readers). Factory "Genesis" engineIds/usernames for a few
reader families are embedded in the app, but the matching Genesis auth/priv keys are
not, so even a factory reader can't be read offline from the APK alone.

**What you *can* get with no keys:**
- **SNMPv3 discovery** → the reader's authoritative `engineId`, `engineBoots`,
  `engineTime` (RFC-3414 style; `hid_rm.snmpv3.build_discovery()` is byte-identical
  to the app). This is the only config-plane exchange that needs no secret.
- BLE/GATT identity (device name, service/char UUIDs), and the SEOS auto-select
  frames the reader emits on connect.
- Possibly a handful of `noAuthNoPriv` OIDs / core reads (empirically testable).

Also note the BLE data characteristic doubles as the **SEOS credential (door-open)
interface**, which the reader gates behind SEOS AKE. Whether config traffic is
accepted directly, or only after the reader is placed in a config/admin mode
(config-card tap / admin BLE opening), can only be confirmed against live hardware.

## 1. Layer cake

```
  BLE GATT  (service 0000 9800.., data char 0000 aa00.., write-no-resp + notify)
    │   MTU 23 (20-byte payload); larger frames are fragmented
    ▼
  Artemis frame:   [u16 length BE] [ APDU ] [u16 CRC16]        (framing.py)
    │   CRC16 = CRC-16/CCITT "Kermit", poly 0x8408, init 0, byte-swapped  (crc16.py)
    ▼
  ISO7816 APDU:    CLA INS P1 P2 Lc  DATA                       (framing.py)
    │   INS: GET_DATA=0xCA, PUT_DATA=0xDA, GET_RESPONSE=0xC0, SELECT=0xA4
    ▼
  DATA is one of:
    (a) BER Payload  — Artemis core/HF/LF/firmware commands     (artemis.py)
    (b) SNMPv3 msg   — reader-config MIB get/set                 (snmpv3.py)
```

Response framing: the reader echoes the APDU header, then `[len][data][crc]`.
Payload offset = 5 (or 7 if `Lc==0`) for BLE/NFC, 6 for serial.

## 2. Artemis messaging (BER `Payload`)  *[ground-truth]*

`Payload` is a BinaryNotes CHOICE; the selected module is a constructed context tag,
wrapping an inner CHOICE (the command), wrapping its argument.

Top-level module tags: sam=0 hf=1 contact=2 wiegand=3 clockAndData=4 **core=5**
hwio=6 lf=7 … bleModule=21 response=29 errorResponse=30 …

No-argument Core read commands (exact bytes, verified with the app's encoder):

| command            | Payload bytes  | framed on aa00 (GET_DATA)          |
|--------------------|----------------|------------------------------------|
| GetVersionInfo     | `a5028600`     | `000700ca000004a5028600<crc>`      |
| GetSamFirmware     | `a5028100`     |                                    |
| GetBoardRevision   | `a5029700`     |                                    |
| GetChipUid         | `a5029a00`     |                                    |
| GetDeviceId        | `a5029b00`     |                                    |
| GetDeviceInfo      | `a5039f2100`   |                                    |
| GetReaderInfo      | `a5039f2300`   | `000a00ca000005a5039f2300<crc>`    |
| Reset              | `a5028200`     |                                    |

(See `artemis.CORE`. Encoding rule: implicit tag on a CHOICE-typed element →
constructed `[n]` wrapper, e.g. `A5 02 86 00` = core[5]{ getVersionInfo[6] NULL }.)

Full command surface (schema HidGlobal.Asn1.Messaging.Artemis): CoreCommand (37
sub-commands incl. properties, tamper, bootloader, board rev, device/reader info),
HFCommand & LFCommand (RF field scan / transmit / transceive / authenticate),
SAMCommand, WiegandCommand, OsdpModuleCommand, KeypadCommand, LcdCommand,
SoundModuleCommand, UHFModuleCommand, BLEModuleCommand, UpgradeCommand, etc.

## 3. Reader config = SNMPv3 MIB

- Enterprise root: **1.3.6.1.4.1.29240** (PEN 29240 -- corrected; `2B 06 01 04 01 81 E4 38` decodes to 29240, not 24632 as earlier stated).
- Config is a list of OIDs (`OidInfo`: oid / value / type∈{KeyReference,Key,Data} / kcv).
- Useful OID prefixes seen in the app:
  `STANDARD_PACS_ADF_OID = 2B0601040181E438010102011801010202`,
  `PACS_CONFIG_OID_R8 = 030107020205`, SEOS AIDs list `030107020206`, …
- **Discovery** (`build_discovery()`, *[ground-truth]*):
  `3037020103300D020101020202F40401040201030410300E04000201000201000400 04000400301104000400A00B0201010201000201003000`
- **Secured GET/PUT**: `BuildGetSecuredDataSnmpMessage(engineId,user,authKey,privKey,oid)` /
  `BuildPutDataSnmpMessage(...)` with msgFlags Auth|Priv|Reportable. HID's USM is
  **custom**: auth = **SMAC (SHA-1 MAC)** (`AuthFactory` algo 0; OMAC/CMAC-AES = 1),
  priv = **AES-128-CBC, MsCrypto padding** (`ConfFactory` algo 1). A stock SNMP stack
  will not interoperate — reimplement `AuthSMAC`/`ConfAES` from the decompile if you
  ever obtain keys.

Hardcoded (Genesis/factory) SNMP identities recovered by running the app
(`snmpv3.GENESIS_IDENTITIES`) — engineId/username only, **no keys**:
OmnikeyReaderCoreHID, OmnikeyReaderCoreAA, CredentialRoller. Other families
(RevE, Eureka, Stingray, Raptor*, CCM, Aurora, …) load from the cloud `AppSettings.xml`.

## 4. Supported card technologies (from the app — no reader needed)

**13.56 MHz (HF):**
- **Seos** (HID's secure credential; also Mobile Access over BLE/NFC)
- **iCLASS**: Legacy, SE, SR / **Picopass**
- **MIFARE**: Classic, Plus, Ultralight
- **MIFARE DESFire**: EV1 / EV2 / EV3 (with SIO file config + Proximity Check)
- **FeliCa**, **CEPAS**
- generic **ISO14443 A/B**, **ISO15693**, **NFC**

**125 kHz (LF):**
- **HID Prox**, **Indala**, **EM (EM410x) Prox**, **AWID** (+ Prox-family: Keri/Pyramid)

**UHF:** UHF credentials (UHFModuleCommand)

**Interfaces / output:** Wiegand, OSDP, Clock-and-Data, MagStripe emulation,
Keypad, LCD, Sound/LED, BLE (Twist-and-Go / Tap / Seamless / Mobile Access), NFC-HCE.

(Which of these are *enabled* on a given reader is exactly what lives in the SNMP
MIB behind auth — see §3.)

## 5. Python client (`hid_rm/`)

```
python -m hid_rm.cli show snmp-discovery         # print discovery + framed bytes
python -m hid_rm.cli show core get_reader_info   # print a framed Artemis read
python -m hid_rm.cli scan                         # BLE scan (needs bleak)
python -m hid_rm.cli snmp-discover <MAC>          # the no-auth config exchange
python -m hid_rm.cli send <MAC> <apdu-hex>        # raw framed APDU, print reply
python -m hid_rm.cli decode-snmp <hex>            # parse a Report (engineId/boots/time)
```

Validated offline: CRC (matches decompiled table), frame round-trip, SNMPv3 discovery
(byte-identical to the app), Artemis core command bytes (from the app's encoder).
Live BLE behaviour (does the reader answer config traffic pre-auth, and via which
mode) must be confirmed against your hardware — that's what `snmp-discover`/`send`
are for.

---

## 6. Deep dive: getting past the auth-gated MIB (results)

### 6.1 Unauthenticated attack surface (no cloud, no keys) — what you CAN read
Confirmed from the decompile + the app's own crypto (run under .NET):
- **SNMPv3 discovery** → reader authoritative `engineId`, `engineBoots`, `engineTime`
  (`snmpv3.build_discovery()`, byte-identical to the app). Always answered, no keys.
- **SEOS SELECT + `GenesisPrivacyKeyset`** → `readAlgorithmInfo()` (SEOS id + supported
  crypto). Genesis privacy is the SEOS **factory-default** keyset embedded in the app,
  so this needs no cloud auth (see `seos.py`).
- **Pre-auth Artemis Core reads** (device/HW identity) — the app must read these to know
  which cloud keys to fetch, so they happen before authentication:
  `get_version_info, get_device_info, get_reader_info, get_board_revision,
   get_chip_uid, get_secure_element_mode, get_sam_firmware`. `get_reader_info` /
  `get_device_info` carry the HW capability flags (`HasHwLf/Ble/Uhf/Osdp/Bio/...Support`)
  = which technologies the reader hardware supports.
  *(Whether a given reader answers these over BLE before a SEOS session is the one thing
  that needs live confirmation — that is what `hid_rm.cli probe` is for.)*

### 6.2 The auth gate is real — what you CANNOT read unauthenticated
- Every real config-OID read/write uses SNMPv3 `Reportable|Priv|Auth` (verified across
  all `buildSnmpMessage` call sites). There is **no** noAuth/authNoPriv read of a real
  OID anywhere in the app — discovery is the only unauthenticated exchange.
- The auth/priv keys are **not in the app**: they are produced by HID's Origo cloud
  (SDS/SDI) for an authenticated user's own readers. HID's USM is custom
  (auth=SMAC/SHA-1, priv=AES-128-CBC), so no stock SNMP shortcut either.
- Reader-management SEOS sessions need an `authenticationKeyset` (cloud) beyond the
  Genesis privacy keyset.
- Net: **a full config dump without authentication is not achievable** short of
  (a) obtaining cloud keys for your own readers, (b) recovering the Genesis privacy/auth
  keyset AND targeting a factory-state reader, or (c) a firmware vulnerability.

### 6.3 Latent weaknesses noted (not live attack paths from the app)
- `KeyChangeGenerator()` (default ctor) derives BOTH the new auth key and priv key from
  `new Random(DateTime.Now.Millisecond)` — non-CSPRNG, ≤1000 seeds. **Not called by the
  shipped app** (key-change is server-side), so it is a latent/robustness note, not an
  exploitable path here — but worth flagging to HID.
- Firmware & SNMP-loader packages are encrypted (`FwEncryptedPackage`,
  `SnmpLoaderEncryptedPackage`) → no trivial downgrade/loader-key path.

### 6.4 Remaining leads to break the gate (for owned-hardware research)
1. **Genesis privacy/auth keyset extraction** — the keys live in obfuscated AAMK code
   (`GenesisPrivacyKeyset`/`GenesisSymmetricKey`, diversified via
   `EMPTY_OID_AND_DIVERSIFIER = 06 00 CF 00`). Recoverable by instrumenting the SEOS
   crypto (Frida on a device, or porting the diversification) — then a **factory** reader
   is reachable. Provisioned readers changed these keys.
2. **Firmware bug** — see §7 (a crash that fails-open would bypass the gate outright).

## 7. Robustness / crash testing (`hid_rm.fuzz`, `cli fuzz`)

Authorized robustness testing of your own readers. The reader's frame-length parser,
ISO7816 APDU parser, BinaryNotes/BER decoder, SNMPv3 parser, and BLE fragment
reassembly are the crash surface. `hid_rm.fuzz.cases()` emits 21 malformed vectors:
- frame length lies (0 / 0xFFFF / ±1 / big+truncated), bad/zeroed CRC, empty/1-byte
- APDU Lc overflow / Lc=0-with-data / truncated header
- BER 64-deep nesting (recursion/stack), 5-byte long-form length, length=0xFFFFFFFF,
  truncated constructed, indefinite length
- SNMP msgFlags=0xFF, huge msgMaxSize (allocation), 200-byte OID
- 240-byte payload → multi-fragment reassembly

`python -m hid_rm.cli fuzz <MAC> [case]` sends each on a fresh connection and flags
**DISCONNECT (possible crash/reboot)**, **no-reply (stall)**, or the EOT status.
A reboot/hang on a door reader is a real finding (availability, and possibly bypass if
it fails open) — characterise it (does it drop the door relay? re-advertise? how long?),
capture the exact vector, and disclose to **HID PSIRT** rather than leaving it live.
Note: a clean commanded reboot is just `core reset` (`a5028200`) but that needs an
authenticated session; the fuzz vectors probe for an *unauthenticated* crash instead.

## 8. Config leak — implemented, decoded, human-readable (`hid_rm.leak`)

The unauthenticated OID disclosure from §6.4/AAMK.md is now a first-class feature:
connect over BLE, reply `9000` (ISO7816 success) to whatever the reader offers, and
collect every distinct **SEOS PACS credential OID** and **application-mode AID** it
tries across its full discovery sequence — no auth, no keys.

```
python -m hid_rm.cli leak <MAC> [cooldown_sec] [out_prefix]
```

Pipeline:
- `hid_rm/oid.py` — DER OID encode/decode (also **corrects an earlier error**: the
  enterprise arc `2B 06 01 04 01 81 E4 38` is **PEN 29240**, not 24632 as this
  document previously stated — verified by hand-deriving the base-128 continuation
  bytes for both candidates).
- `hid_rm/oid_db.py` — a 30-entry named-OID database extracted 1:1 from every
  `public const string X = "<hex>"` in the decompiled sources that decodes as a
  valid OID, plus a `describe()` that: matches known constants exactly; for
  anything under `STANDARD_PACS_ADF_OID`'s tree, decomposes it into
  `subtype/object_id/variant` and flags whether it's the generic PACS object or a
  **non-standard, deployment-specific SIO object**; otherwise reports proximity to
  the nearest known OID under HID's enterprise arc.
- `hid_rm/leak.py` — `LeakCollector` parses each reader→phone `SELECT_ADF`/
  `SELECT_AID` APDU, de-duplicates OIDs/AIDs across the whole session, and renders
  both a human-readable text report and a JSON structure (timestamped, diffable
  across readers or over time).

### Live result (reader C0:60:33:15:2B:31, your desk unit)
7 distinct PACS OIDs recovered with zero authentication: 1 is the generic
`STANDARD_PACS_ADF_OID`; the other 6 are non-standard object IDs (`11571.1/2/7`,
`163.11433.1/2`, `6.1.1.10664`) — i.e. this reader has been configured with
**6 customer/deployment-specific SIO credential objects** that are not part of any
HID default, discoverable by anyone who connects over BLE and says "yes" to
whatever it asks. Also recovered: the true 16-byte on-wire `STANDARD_SEOS` AID
(`a0000004400001010001 000047052b03` — corrects an under-count in §6.2/FINDINGS.md
of the same value) and the `MOBILE_SEOS_ADMIN_CARD`/`OPERATION_SELECTOR` mode AIDs.

Saved example: `leak_reports/reader_C0-60-33-15-2B-31.{txt,json}`.

This is real information disclosure — it doesn't compromise credentials or open the
door, but it tells an unauthenticated bystander with a BLE radio exactly which
custom SIO object IDs a specific reader is configured to accept, which is
reconnaissance a real attacker could use before attempting a card/credential clone
or a targeted SAM/config attack. Worth including in the HID PSIRT writeup alongside
the fuzzing/robustness findings.

## 9. Live proof pass (reader C0:60:33:15:2B:31) — reproducibility + definitive negative

Re-ran the config leak twice, independently, several minutes apart:

```python
oids_run1 == oids_run2   # True — identical 7 OIDs, same order
aids_run1 == aids_run2   # True — identical 3 AIDs
status_run1 == status_run2  # True — SAM_REJECTED both times
```
**The unauthenticated OID/AID leak is fully reproducible**, not a one-off artifact
(`leak_reports/reader_C0-60-33-15-2B-31.json` vs `leak_reports/proof_run1.json`).

### Definitive proof: two distinct sub-protocols share this one characteristic
Live-tested, for the first time with the fragmentation bug actually fixed (earlier
attempts failed outright at the BLE write with an MTU error before fragmentation
was implemented — so this had never actually been exercised before):

- Sent a **properly-framed** SNMP-discovery message — `[u16 len][ISO7816 GET_DATA
  APDU][u16 CRC16]` (`framing.frame()`), correctly split into 4 BLE fragments
  (`framing.ble_fragment()`) — as an unsolicited write.
- **Result: the reader ignored the content entirely and restarted its own SELECT
  sequence from the top** (re-selected `STANDARD_SEOS`), the exact same behavior
  as sending a garbage/invalid ISO7816 status word (`6A82`, tested earlier).

This proves conclusively (not just inferred) that the `[len][apdu][crc]`-framed
Artemis/SNMP command channel and the raw-APDU credential-read exchange are **two
separate sub-protocols on the same GATT characteristic**, and that an
unauthenticated central cannot switch from one to the other by simply sending a
well-formed message on the wrong one — the reader's own state machine has to be
in a mode expecting it, which it never voluntarily enters here. Combined with the
earlier finding that our raw APDU replies only ever influence the credential-read
loop, this closes out "can a properly-constructed Artemis/SNMP command get through
if you just format it correctly" with a hard **no**, live-verified, not assumed.

### Also reconfirmed: FCI content is irrelevant, only the status word matters
Replied to the very first spontaneous SELECT (the `STANDARD_SEOS` auto-select) with
a full, plausible FCI (`6F 12 84 10 <16-byte AID> 40 02 00 00` + `9000`) instead of
bare `9000`. Identical downstream behavior (same 5-OID `SELECT ADF` offer
follows) — the reader does not parse/validate our FCI payload at all, it only
checks the trailing SW1SW2. Rules out "the right FCI unlocks something different"
as a remaining lead.

## 10. Live fuzz/robustness results (corrected harness, reader C0:60:33:15:2B:31)

`hid_rm/fuzz.py` was rewritten (see its docstring) after live testing proved the
original version targeted an unreachable layer: it fuzzed the `[len][APDU][CRC]`
Artemis/SNMP frame, but §9 proved that frame's content is ignored outright by an
unauthenticated central regardless of validity — so no amount of malforming it
would ever reach a parser. The corrected version targets the layer that IS live:
the ISO7816 credential-read exchange (status words, FCI/TLV content, and the BLE
`ProtocolV1Fragment` reassembly state machine), where the reader is the active
party parsing our replies.

**8 cases run live, one per fresh connection, spaced ~6s apart:**

| case | result |
|---|---|
| `sw_all_zero` (SW=0000) | graceful restart-to-top |
| `sw_61_max` (GET RESPONSE, claims 255B) | correct `GET RESPONSE` chaining, no crash |
| `fci_negative_len` (length byte lies about size) | accepted (trailing SW is all that's checked — internal TLV consistency not validated, but harmlessly so) |
| `frag_claims_more_never_sends` (BLE fragment promises 5 more, we send 0) | clean `MSG_TIMEOUT`, no hang |
| `frag_double_init` (two INIT fragments back-to-back) | resynced and continued normally |
| `frag_final_only_no_init` (orphan FINAL, no INIT) | graceful restart-to-top |
| `fci_huge_single_write` (14-fragment oversized FCI reply) | clean `MSG_TIMEOUT` |
| `reply_then_immediate_disconnect` | handled (ties into the rate-limit/cooldown behaviour already observed in §6.4/AAMK.md) |

**Result: no crash, no reboot, no hang found in this round.** The firmware's
BLE-fragment reassembly and ISO7816 reply parsing on this reader/firmware appear
robust against the malformed-input classes tested here — every case was either
accepted harmlessly or rejected with a defined status/timeout, never an
unhandled state. This is a genuine (if negative) result, not a gap: it directly
answers the earlier request to look for a crash/reboot condition. Remaining
untested surface for a deeper campaign: BLE link-layer/L2CAP fuzzing (below GATT,
needs a different tool — e.g. a sniffer + raw HCI injection, not achievable with
bleak/BlueZ GATT writes alone), and the credential-read exchange under actual
mutual-authentication attempt (GET CHALLENGE/AUTHENTICATE, requires real or
guessed key material — out of scope here per your unauthenticated-only preference).

## 11. Settings-management exploration — a third sub-protocol found, dead-ended honestly

Explored whether the BLE "Extension" frame type (`0xE0|type`, distinct from both
the ISO7816 credential-read exchange and the `[len][APDU][CRC]`-framed Artemis/SNMP
channel) offers an unauthenticated path to read/manage reader settings.

**Live-tested, unauthenticated, sending `0xE5` (CONFIGURATION) + `84 00`
(`REQUEST_GET_PROPERTIES`) directly:**
- Result: a **distinct `EOT status=MSG_TIMEOUT`** response — not the generic
  "restart to STANDARD_SEOS" or `FRAG_TIMEOUT` we get from arbitrary garbage. This
  proves the reader's parser *does* recognize `0xE5` as a distinct, valid extension
  message type (different code path from junk input) — genuinely new information.
- Reproducible across repeated attempts and independent of whether a `0x40` poll
  precedes it.
- **But it goes nowhere**: static analysis shows `REQUEST_GET_PROPERTIES` (`84 00`),
  `REQUEST_GET_PROPERTIES2` (`8C 00`), and the `FRAGMENT_CONFIGURE_MODE` header
  constant itself are **declared but never called anywhere** in either
  `HidGlobal.ArtemisManager.dll` or `HidGlobal.ArtemisManager.UI.dll` (252k
  decompiled lines checked). The app that ships this protocol doesn't use it —
  there's no reference implementation to learn the real multi-byte payload/session
  format from, so guessing further live against real hardware isn't a productive
  use of connection attempts. Likely a leftover/reserved code path from an earlier
  protocol version (see the neighboring `SWITCH_TO_BLE_FW_UPDATE_PROTOCOL_V2`
  constant, which implies a v1/v2 split we don't have visibility into).

**Deliberately NOT tested: `0xE2` (FW_UPDATE) + `REQUEST_INIT_FLASH`.** Unlike
`CONFIGURATION`, this path IS actively used by the real app
(`SendBleFragmentV2(REQUEST_INIT_FLASH, REQUEST_INIT_FLASH_ACK)`), and its 4-byte
ACK (`84 82 00 00`) is consistent with genuinely initiating a firmware-flash
sequence on success. That's not a "setting" and not reversible if it goes wrong on
real hardware — sending it wasn't attempted.

### Where this leaves "managing settings" unauthenticated
Every genuine settings-management primitive (BLE device name, LED/beep, output
config, technology enable/disable, key references) travels over the Artemis
`GET_DATA`/SNMP channel — and §9 already proved live that this channel ignores
content outright from an unauthenticated central regardless of validity. The
Extension-frame path is either dead code (`CONFIGURATION`) or too risky to probe
(`FW_UPDATE`). **No unauthenticated settings-management path was found** on this
reader/firmware — consistent with, and now more thoroughly tested than, the
conclusion in §6.2/AAMK.md.

## 12. Flipper Zero integration — findings, what's built, what's realistic

A Flipper Zero (Momentum firmware `mntm-012`, connected via USB serial at
`/dev/ttyACM1`) was made available to add NFC coverage, since not all HID readers
carry BLE. Findings below are from live probing of the actual device, not assumed.

### What's already on this Flipper (found, not created by this research)
- **Community apps already installed**: `seos.fap`, `seader.fap` (a known SEOS/
  iCLASS credential tool), `picopass.fap`, `hid_ble.fap`, `nfc_apdu_runner.fap`,
  `guesskey_bf.fap`, among many others.
- **`/ext/apps_data/seader/` already contains captured credential files** — five
  files (four `.credential`/`.picopass` files with user-chosen labels, plus a
  `sam_serial.txt`) that look like real, previously scanned access badges (not
  synthetic test data), predating this research session. One label appeared to be
  a person's first name. **Not opened, read, or used here** — that's a different
  authorization question than testing your own reader's protocol, and not
  appropriate to name in a public document regardless; flagged for you to decide
  what to do with those files.

### CLI capability, confirmed live
```
nfc apdu -p {4a,4b,15} -d "..."   Flipper as READER, sends APDU to a card already
                                  in its field -- needs a target CARD, not useful
                                  against our reader (which is itself a PCD).
nfc scanner                      passive reader-mode scan. LIVE-TESTED against
                                  the physical HID reader: "Protocols detected: "
                                  (empty) -- confirms the reader does not answer
                                  as a passive NFC tag, mirroring the BLE finding
                                  that it only ever acts as an initiator.
nfc emulate -f <file>            emulates a STATIC previously-saved .nfc dump --
                                  no dynamic/scripted response logic.
nfc field / raw / dump           also reader-mode / one-shot capture.
bt hci_info                      the ONLY bt CLI subcommand -- no general BLE
                                  GATT-central scripting surface over this CLI.
```

### What this means for the two transports
- **BLE**: unaffected — this machine's own Bluetooth adapter (via `bleak`) already
  does everything `hid_rm` needs and is fully working/tested all session. The
  Flipper's `bt` CLI doesn't add BLE-central capability (`hci_info` only), so
  there's nothing to port here; BLE stays exactly as-is.
- **NFC**: the reader only acts as an initiator on NFC too (confirmed live,
  `nfc scanner` → empty), exactly like BLE. To have anything talk to it over NFC,
  the *far side must dynamically emulate a card* — react differently depending on
  what the reader sends, the same job `hid_rm.emulate`'s responder does over BLE.
  Momentum's stock CLI has no primitive for that (`emulate -f` is static-only).
  Real dynamic ISO14443-4 card emulation needs either:
    1. **The already-installed `seos.fap`/`seader.fap`**, operated by hand on the
       device (GUI, d-pad navigation) — the practical, immediate path, since these
       are purpose-built community tools likely more mature than anything
       buildable here in one session. I can help interpret whatever files they
       produce (same `oid_db.py`/`leak.py` decoding logic applies once the bytes
       are in hand) once you've run them and want the output analyzed.
    2. **A custom C FAP** using the Flipper NFC HAL's ISO14443-4 *listener* API
       (which does support a live per-APDU callback, just not exposed through the
       base CLI) — a genuine embedded-firmware development task (needs `ufbt`,
       cross-compilation, on-device testing), out of scope for a CLI-scripting
       pass but scoped here if you want to pursue it.

### Built and live-tested this pass
`hid_rm/flipper_cli.py` — a serial-CLI transport (`FlipperCLI`: connect, run
commands, safe Ctrl+C cleanup, storage browsing) plus `probe_capabilities()`.
Wired into `python -m hid_rm.cli flipper-probe [port]`, live-tested: reports
firmware, confirms NFC CLI present / BT CLI limited, runs the passive scan and
reports the (expected) empty result in one clean line by default, full raw output
with `--verbose`.

## 13. Custom Flipper Zero NFC app — built, deployed, live-tested (option 2 from §12)

Built `flipper_app/hid_recon.c`, a from-scratch Flipper application that ports
`hid_rm.emulate`/`hid_rm.leak`'s protocol logic to a real ISO14443-4A **listener**
(dynamic card emulation), addressing the exact gap identified in §12 (Momentum's
stock CLI only offers static `.nfc` replay, no scripted response logic).

### What it does
- Emulates the live-verified 16-byte `STANDARD_SEOS` AID (`A0 00 00 04 40 00 01 01
  00 01 00 00 47 05 2B 03`), SAK=0x20 (ISO14443-4 compliant), random UID per session.
- On every received post-activation APDU: parses `SELECT_ADF` (0xA5) for tag-0x06
  OIDs exactly like `leak.py.parse_select_adf`, parses `SELECT_AID` (0xA4) against
  the same 10-entry known-AID table as `emulate.py`, de-duplicates both, and always
  answers `90 00` — the same "content doesn't matter, only the status word does"
  responder logic proven over BLE in §9.
- Live screen: exchange count, field on/off toggle count, running OID/AID tallies,
  last event — OK saves a full text log to
  `/ext/apps_data/hid_recon/session.txt`, Back exits.
- Ported the DER-OID decoder (`oid.py`'s `decode()`) to C directly on-device.

### Build/deploy chain (verified working end-to-end)
`ufbt` targeting the **Momentum** firmware SDK (not stock — this device runs
`mntm-012`) via `ufbt update --index-url=https://up.momentum-fw.dev/firmware/directory.json`.
API surfaces (`iso14443_4a_listener`, `nfc_listener`, `BitBuffer`, `SimpleArray`)
were taken from the actual firmware source (fetched live from
`flipperdevices/flipperzero-firmware`, cross-checked against the already-installed
`bettse/seader` project's usage) rather than assumed — the shipping `nfc_cli_command_emulate.c`
confirmed the CLI's `emulate` passes a `NULL` callback (static-only, as found live
in §12); `iso14443_4a_listener.c` gave the exact dynamic-callback event shape used
here. Deployed via `ufbt launch` over the same USB-CDC serial connection used for
`flipper_cli.py` (they cannot be held open concurrently — sequential only).

### Live test results (multiple runs, reader C0:60:33:15:2B:31)
- App itself: **fully verified working.** Compiles clean, deploys, starts the
  listener, detects real RF field activity from the physical reader, redraws
  correctly (after fixing a self-inflicted `view_port_update()` flood -- calling it
  unconditionally from both the ~4 Hz NFC callback and the main loop tripped
  `ViewPort lockup` warnings; fixed with a dirty-flag + main-loop-only throttle),
  and exits/cleans up (`nfc_listener_stop/free`, `nfc_free`) correctly every time —
  confirmed via live `log info`/`log trace` serial streaming, not assumed. (One
  operational note: Loader's remote "close app" RPC doesn't work for a raw
  ViewPort app that isn't registered with the scene/ViewDispatcher framework —
  `loader close` and simulated `input send back` both report "has to be closed
  manually"; worked around with a built-in `AUTO_EXIT_MS` timeout so the app is
  fully testable without needing physical/remote button delivery.)
- **RF activation: CONFIRMED WORKING, live, against the real reader.** Initial
  runs (30s each, ~50-125 field on/off toggles per run at ~200-240ms intervals —
  the reader's idle presence-detection polling) got RF field detection but no
  completed activation, pointing at physical antenna coupling rather than a
  protocol bug (adjusting the ATS made no difference). Repositioning the Flipper
  on the reader (small movement/tilt rather than a fixed hold) got past
  activation on two separate runs. One run — after fixing an `OID_STR_LEN`/
  `AID_STR_LEN` truncation bug found from the first (truncated) capture — produced
  a complete, clean result:
  ```
  APDU exchanges: 8    Field on/off toggles: 143
  OIDs found: 4         AIDs found: 4
  OID 1: 1.3.6.1.4.1.29240.1.1.2.1.24.1.6.1.1.10664
  OID 2: 1.3.6.1.4.1.29240.1.1.2.1.24.1.1.11571.2
  OID 3: 1.3.6.1.4.1.29240.1.1.2.1.24.1.1.163.11433.1
  OID 4: 1.3.6.1.4.1.29240.1.1.2.1.24.1.1.11571.1
  AID 1: STANDARD_SEOS         AID 3: MOBILE_SEOS_ADMIN_CARD
  AID 2: A00000067660091E052B03 (NEW — not seen over BLE)  AID 4: OPERATION_SELECTOR
  ```
  **All 4 OIDs are an exact match to a subset of the 7 OIDs found independently
  over BLE earlier in this research (§8/leak.py)** — zero discrepancies. This is
  genuine cross-transport corroboration: two completely independent code paths
  (Python/bleak over BLE GATT; from-scratch C/ISO14443-4A-listener over NFC),
  talking to the reader over two different radios, agree exactly on the reader's
  configured credential OIDs. Saved at `leak_reports/flipper_nfc_session.txt`.
- **New lead: AID `A0 00 00 06 76 60 09 1E 05 2B 03`** — offered by the reader
  over NFC in both successful runs, not part of the 10-entry `Constants.AID` table
  used for BLE probing and not yet identified. Worth adding to `emulate.py`'s AID
  table and investigating the RID `A0 00 00 06 76` (not one of HID's own
  `A000000382xx`/`A000000440xx` prefixes seen elsewhere in this research) if this
  work continues.
- **NFC contact remains finicky** (expected — typical NFC coupling range is a few
  mm and very alignment-sensitive): most attempts still time out with only field
  toggles and no activation; success came from small deliberate repositioning
  rather than a static hold. Re-running is cheap (`ufbt launch` + watch
  `log info`) and each success is independently useful data.

Files: `flipper_app/hid_recon.c`, `flipper_app/application.fam`,
`leak_reports/flipper_nfc_session.txt`.

## 14. Flipper app output — plain-English by default

Updated `hid_recon.c` so the on-screen display and the saved report lead with
plain English (matching the same concise-by-default principle already applied
to the Python CLI in §leak.py/recon.py) rather than raw AID names/hex or bare
OID dotted-decimal:

- **Screen**: "Credentials: N std, M custom" and "Admin mode: seen/not seen"
  replace the earlier raw "OIDs: N  AIDs: N" counts; status lines during a
  session read as e.g. "Found 2 new credential object(s)" / "Admin/management
  access mode" / "Waiting for reader contact (N tries)" instead of "SELECT ADF
  -> N OID(s)" / "SELECT AID: MOBILE_SEOS_ADMIN_CARD" / "Field toggles: N (no
  RATS yet)".
- **Saved report** (`/ext/apps_data/hid_recon/session.txt`) now has two parts:
  a plain-English summary first (credential counts by standard/custom, whether
  admin mode was offered, and each mode described in a sentence), then a
  "Technical detail" section with the raw OIDs/AIDs for cross-referencing
  against `hid_rm`'s Python tooling.
- New byte-level OID classifier (`classify_oid()`, port of `oid_db.py`'s
  `describe()`/`summarize()`) compares the raw DER bytes against
  `STANDARD_PACS_ADF_OID` and the shared PACS-ADF prefix directly, rather than
  string-matching after decoding.
- New `english_for_aid()` table glosses every known technical AID name (e.g.
  `MOBILE_SEOS_ADMIN_CARD` -> "Admin/management access mode",
  `OPERATION_SELECTOR` -> "Mode selector"); an unrecognised AID is described by
  its RID rather than dumped as raw hex (e.g. the new AID from §13 renders as
  "Unrecognized app (RID A000000676)").

Live-verified: a real capture on this reader (after this change) rendered as
the plain-English block quoted above, with the technical OID/AID list
underneath — confirms both the classification logic and the report format work
against real device data, not just synthetic test input.

## 15. Firmware update — static verification check (negative/inconclusive)

Checked whether the app performs any firmware signature/hash verification before
transferring an image to the reader's Nordic BLE radio chip (the `FW_UPDATE`
extension channel, §11). Searched every class in the upgrade pipeline
(`FwEncryptedPackageStrategy`, `NordicFirmwareTransferStep`,
`PrepareOneFileFirmwareStep`, `ConfigWriteStep`, `SamFirmwareTransferStep`, and
the rest of the `IUpgradeStep` chain) for signature/hash/RSA/ECDSA/AES calls.

**Result: none found anywhere in the app-level code.** The app only CRC16-frames
data (integrity against transmission errors, not authenticity) and relays bytes;
`FwEncryptedPackageStrategy` just orchestrates *which* artifact to send, it
doesn't verify anything cryptographically itself.

**This is inconclusive, not a finding of a vulnerability** — real embedded
secure-boot designs correctly put signature verification on the *device's own*
bootloader, not the phone app, so a negative result here says nothing about
whether the reader's Nordic chip rejects unsigned images once it receives them.
That verification (if it exists) lives in the reader's own firmware, invisible
to APK analysis, and confirming it either way would need either firmware
extraction (JTAG/SWD, physical hardware access — out of scope for this
BLE/NFC-only research) or actually attempting a live firmware update with a
malformed image (real bricking risk, not attempted). Also lower-priority in
practice: reaching `FW_UPDATE` requires the same authenticated admin session
this research has already shown is unreachable unauthenticated — so even a
confirmed weakness here would sit behind the same wall as everything else.

## 16. NFC fuzzing (Flipper) — robust, plus a genuinely new command found

Extended `flipper_app/hid_recon.c` with an NFC fuzz mode (`FUZZ_MODE`, ported
from `hid_rm.fuzz`'s BLE cases): instead of always answering `90 00`, it cycles
through 8 reply strategies (control 9000, `SW=0000`, `SW=6A82`, `SW=61FF`,
1-byte truncated, an FCI-length lie, an empty reply) on every received APDU,
logging the case used and the reader's next move. Config data is still parsed
from the reader's own commands regardless of which reply is sent.

**Result: no crash, hang, or reset found.** One successful live run exercised
**210 fuzzed exchanges** (141 of one command type, 69 of another — see below)
over ~30 seconds with every malformed reply, and the session ended with a clean
auto-exit and resource teardown, matching the BLE fuzz result (§10) — the
reader's NFC front-end is equally robust to the classes of malformed input
tested so far.

### New command found — not seen over BLE
The run surfaced two command types never observed over BLE:
- **`CLA=0x00 INS=0xC0` (GET RESPONSE)** — 69 occurrences, correctly triggered
  by the `SW=61FF` fuzz case. Consistent with the BLE-side finding (§9) that the
  reader implements real ISO7816 response chaining; confirms it on NFC too.
- **`CLA=0x90 INS=0x5A ...` — 141 occurrences, a genuinely new instruction.**
  Neither `0x90` nor `0x5A` appears in any previously-documented SEOS APDU set
  from this research (`SELECT_AID=0xA4, SELECT_ADF=0xA5, AUTHENTICATE=0x87,
  CORE_ADMIN=0x15, FS_OPS=0xE6, GET_DATA=0xCB/0xCD, PUT_DATA=0xDB/0xDD,
  GEN_KEYPAIR=0x47, REMOVE=0xED, RESPONSE=0xC0, AMR=0x41`). Only the first 4
  bytes were captured before the logging was widened to dump the full APDU
  (`90 5A 00 00`, len=9, so 5 more data bytes are still unseen) — the fix is in
  place (`flipper_app/hid_recon.c`, full-hex logging on the "other command"
  path) but a repeat successful NFC contact hasn't landed yet this session to
  capture the complete bytes. **Open item**: re-run `flipper_app` and grep the
  device log for `Other command ins=5A` to get the full APDU.
- A public-registry lookup for the unrelated new AID from §13
  (`A0 00 00 06 76 60 09 1E 05 2B 03`) found no match in EMV/payment AID
  databases (expected — those don't cover PACS/access-control RIDs) or general
  smart-card RID lists searched. **Unidentified**, not a dead end so much as
  outside the registries checked so far.

## 17. Live BLE follow-up (SELECT ADF response content) — inconclusive this session

Attempted to test whether replying to `SELECT_ADF` with an FCI that echoes back
`STANDARD_PACS_ADF_OID` (claiming a specific credential match, rather than the
generic bare `9000` used throughout §6-§9) changes the reader's behaviour --
e.g. whether it advances toward a real `GET CHALLENGE`/AKE step instead of
continuing down its candidate list. **Not yet resolved**: every attempt this
session hit an immediate `MSG_TIMEOUT` with no discovery offer at all -- the
reader's connection-rate cooldown (§6.4/AAMK.md) appears to have engaged more
persistently than earlier in this research, likely from the cumulative number
of BLE connects across this whole session. Code for the experiment is
reproducible (see this section's history) and worth another pass after the
reader has had a longer rest.

## 18. BLE connection lockout — characterized more precisely (possible availability finding)

Following up on the "rate-limit/cooldown" observation from §6.4/AAMK.md with more
data points from this session: after a cluster of ~8-10 BLE connection attempts
in a fairly tight window, the reader entered a state where **every subsequent
connection attempt fails identically** — GATT connects fine, the spontaneous
`SELECT` frame arrives normally, but the reader then sends an
`EOT status=MSG_TIMEOUT` **before we ever send a reply**, and this persisted
across many retries spread over more than 20 minutes of wall-clock time,
including a verified-normal BLE advertisement (`rssi -76`, same as always — not
a power/range/hardware issue).

This is a **materially different failure mode from NFC's**, which is worth
distinguishing precisely rather than conflating as "the same cooldown":
- **BLE failures are a deliberate reader decision** — the connection and
  ISO7816 exchange succeed at the protocol level; the reader actively chooses
  to abort with a specific status code. This looks like real anti-abuse logic.
- **NFC failures are silent** — no APDU exchange happens at all, consistent
  with antenna-coupling variance (the RATS/activation handshake simply doesn't
  complete), not a deliberate reader response.

**Working hypothesis, not yet confirmed**: the lockout window may be
**self-extending on retry** — i.e. each connection attempt made *during* the
lockout resets or extends the backoff timer, which would explain why it never
cleared despite the individual attempts being spaced 1-2 minutes apart (if the
real base timeout is, say, 60-120s of *total silence*, repeatedly probing every
60-90s would keep re-triggering it indefinitely). This is exactly the behaviour
you'd want from a well-designed anti-brute-force mechanism, but it also means
a well-meaning tester (or a malicious one) doing exactly what this research did
— periodic reconnect attempts — **could keep a real reader locked out of normal
BLE credential-read use for as long as they keep probing**, which is worth
flagging as a potential availability/DoS consideration for responsible
disclosure alongside the OID/config-leak finding (§8-9). Not confirmed as a
genuine DoS (would need a controlled test: stop ALL connection attempts for a
long, precisely-timed idle period, then test once) — recommended as the
concrete next step before further BLE work.

**Status of this session's two open items pending a real BLE rest period**:
- §16's full `CLA=0x90 INS=0x5A` capture — pursued via NFC (unaffected by the
  BLE-specific lockout above) across 10 attempts, 2 partial successes, full
  bytes still not captured (logging fix is in place and correct, just needs
  one more good contact).
- §17's SELECT_ADF FCI-echo experiment — blocked by the BLE lockout
  characterized above; deliberately not retried further this session to avoid
  extending it further, per the hypothesis just described.

## 19. "Find reader" — CoreCommand.readerLocate implemented (tag 36)

Implemented the reader-locate ("find my reader") feature from HID Reader
Manager: flash the LED and/or beep the reader on command, over BLE, fully
unauthenticated. This is `Payload.core.readerLocate` — `CoreCommand` sub-tag
**36** — which was previously only noted by name during the CoreCommand
tag enumeration; its field structure had not been examined until this pass.

### Schema (from `HidGlobal.Asn1.Messaging.Artemis.cs`, decompiled)

```
ReaderLocateCommand ::= SEQUENCE {
    ledPattern  [0] ReaderLocateLedPattern OPTIONAL,
    beepPattern [1] ReaderLocateBeepPattern OPTIONAL
}
ReaderLocateLedPattern ::= SEQUENCE {
    totalDurationMs       [0] INTEGER (0..65535) OPTIONAL,
    initialColourTimeMs   [1] INTEGER (0..65535) OPTIONAL,
    alternateColourTimeMs [2] INTEGER (0..65535) OPTIONAL,
    initialColour         [3] HwioLedColor OPTIONAL,
    alternateColour       [4] HwioLedColor OPTIONAL
}
ReaderLocateBeepPattern ::= SEQUENCE {
    totalDurationMs [0] INTEGER (0..65535) OPTIONAL,
    onTimeMs        [1] INTEGER (0..65535) OPTIONAL,
    offTimeMs       [2] INTEGER (0..65535) OPTIONAL
}
HwioLedColor ::= ENUMERATED { black(0), red(1), green(2), amber(3), blue(4),
    magenta(5), cyan(6), white(7), transparent(8), default(9), global(255) }
```

Every field at every level is `OPTIONAL` — an empty `ReaderLocateCommand{}` is
valid (ground-truthed as `a5 03 bf 24 00`), so the command doubles as a no-op
liveness probe if sent with nothing set.

### Ground truth and implementation

As with every other `CORE` byte template in this project, the exact BER
encoding was generated by running the app's own BinaryNotes.NET encoder
against the shipped `HidGlobal.Asn1.Messaging.Artemis.dll` (see the `enc`
harness referenced in `FINDINGS.md`). Six parameter combinations (empty,
beep-only, LED-only, both, a short "chirp", and a long 10s pattern) were
generated this way and used as regression tests.

Rather than hardcode six fixed byte strings (as the read-only `CORE` commands
do, since those take no arguments), `hid_rm/artemis.py` implements a small
general BER encoder (`build_led_pattern()`, `build_beep_pattern()`,
`build_locate()`) so duration and colour are real parameters. `_der_int()`
reproduces BinaryNotes.NET's minimal-length two's-complement-style DER
INTEGER encoding (confirmed necessary: e.g. `200` encodes as `00 c8`, with a
leading zero byte, because `c8` alone has its high bit set). All six ground-
truth test vectors round-trip byte-for-byte through the Python encoder.

`artemis.locate_payload(seconds, color, beep)` is the convenience preset used
by the CLI: alternates the chosen colour with off every 300ms and beeps at a
200ms on/off cadence, for the requested duration.

### CLI

```
python -m hid_rm.cli show locate [seconds] [color]   # offline: preview the payload
python -m hid_rm.cli locate <MAC> [seconds] [color]   # live: flash + beep the reader
```

Wired the same way as `core`: connect, write the ISO7816-framed APDU,
decode+print the reply in plain English by default, raw frames with
`--verbose`. No session/auth needed — like the OID/AID discovery loop, this
sits on the reader's always-open unauthenticated command surface.

### Live verification status

Not yet tested against the physical reader this pass — deliberately deferred.
§18 identified a BLE connection lockout that looked like a self-extending
backoff, and the reader was being left to rest rather than risk re-triggering
or extending it with another connection attempt. The encoding itself is
verified correct independent of the reader (matches the vendor's own
encoder exactly); live confirmation that the reader actually flashes/beeps on
receipt is the next live-BLE step once a genuine idle period has passed. This
command is BLE-only by nature — it is a client-to-reader instruction sent over
an active connection, not something meaningful over the Flipper's passive
NFC card-emulation listener (which only ever receives commands *from* the
reader, never sends commands to it).

## 20. "Find reader" on the Flipper Zero — BLE-central app (no firmware rebuild)

The locate command needs the sender to act as a BLE **central** (GATT client):
connect out to the reader, discover its command characteristic, write to it.
This turned out to be the hard part on a Flipper, and the investigation is worth
recording because the conclusion is non-obvious.

### Finding: stock/Momentum firmware exposes no central role to apps

Flipper's released SDK exposes only **peripheral/GATT-server** BLE to apps
(advertising, `ble_gatt_service_add`, the serial profile, the extra-beacon
spoofer, and radio DTM test modes). Every `aci_gap_*` / `aci_gatt_*` function
— and even the raw `hci_send_req` transport primitive — is **absent from the
app-accessible API symbol table** (the `elf_api_table` the `.fap` loader
resolves against; disabled entries are filtered out of it). Confirmed by
enumerating the entire table: zero central/client symbols. So a normal app,
built against the SDK, simply cannot open an outbound BLE connection. There is
also no BLE-central path through the serial CLI (`bt hci_info` only) or the JS
runtime. The capability exists in the STM32WB co-processor stack (full BLE
stack, central-capable) — it's just not wired through the core-1 firmware for
apps to reach.

### The one no-rebuild path: call `hci_send_req` by absolute address

The `aci_*`/`hci_le_*` functions are thin parameter-packers that build a command
buffer and call `hci_send_req` (verified in the ST copro source, e.g.
`aci_gap_create_connection` → OGF 0x3f/OCF 0x9c). `hci_send_req` **is** present
in the firmware binary at a fixed address. So an app can:

1. Call `hci_send_req` via a raw function pointer at its known flash address.
2. Reimplement the handful of wrappers it needs — here `hci_le_create_connection`
   (OGF 0x08/OCF 0x00d — raw HCI, so no GAP central-role init is required),
   `aci_gatt_disc_char_by_uuid` (0x3f/0x116), `aci_gatt_write_without_resp`
   (0x3f/0x123), plus create-connection-cancel and disconnect.
3. Receive the async events (connection-complete, char-discovery, proc-complete)
   through `ble_event_dispatcher_register_svc_handler` — which *is* an exposed
   app API, so event delivery is clean and supported.

Crucially, `hci_send_req` **self-serializes**: it acquires the OS's BLE command
mutex inside its own status callback (`NotifyCmdStatus(CmdBusy)` →
`ble_app_hci_status_not_handler` → `furi_mutex_acquire(hci_mtx)`). So calling it
from an app thread is automatically mutually-exclusive with the OS's own BLE
traffic — this is what makes the approach safe rather than merely possible.

### Safety gate (the address is firmware-build-specific)

`hci_send_req`'s address differs per firmware build (dev tip `d3f89dfe` had it at
`0x0801b8cd`; the device's release `mntm-012`/`e1784e74` at `0x0801b8ac`). A
wrong address is a jump into garbage → hardfault. The app therefore pins to
`mntm-012` and, before making any raw call, reads the 16 bytes at that address
(flash is memory-mapped/readable) and compares them to that build's known
`hci_send_req` prologue. Mismatch → the app shows an "unsupported firmware"
screen and does nothing. A version mismatch is thus harmless, not a crash. Other
builds are supported by adding their address + prologue to a small table.

### What's built

`flipper_locate/` — a from-scratch `.fap` (`hid_locate.c`, built with the same
Momentum `ufbt` SDK as the NFC recon app). d-pad selects a locate pattern
(colour/duration preset), OK runs connect → discover → write → disconnect. The
Artemis payloads are the same bytes validated byte-for-byte against the vendor
encoder (§19); CRC/framing/fragmentation is ported from `hid_rm`. Builds clean
and passes `APPCHK` (the loader's API-import validation). Live on-device
verification against the physical reader is the remaining step (deferred for the
same BLE-rest reason as §19, and because a first run of raw firmware-internal
calls is best done watched, on the device that's physically on the reader).
