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
and passes `APPCHK` (the loader's API-import validation).

### Live result: the raw-call approach works, but the Light stack blocks it

Deployed and run on the device (`mntm-012`/`e1784e74`). The on-device result
file records, in order:

```
fw_gate=OK(mntm-012)                       <- prologue check passed
radio_stack=1 (1=Light 2=Full)
probe hci_le_rand status=0x00              <- our raw hci_send_req path WORKS
gap_create_connection cmd_status=0x01      <- "unknown command"
hci_le_create_connection cmd_status=0x01   <- "unknown command"
result=FAILED: connect
```

This is a clean, airtight characterization:

- **The raw-address technique is sound.** The firmware-prologue safety gate
  passed, and a generic `hci_le_rand` sent through our hand-rolled
  `hci_send_req` call returns `0x00` (success) with real random bytes. So we can
  inject arbitrary HCI/ACI commands from an app and they execute correctly — the
  whole "call firmware internals by address" mechanism works exactly as designed.
- **The blocker is one level deeper than any of this.** Both the vendor GAP
  connect (`aci_gap_create_connection`) and the raw HCI legacy connect
  (`hci_le_create_connection`) return `0x01` = *unknown command*. The Flipper
  ships the STM32WB **BLE _Light_ co-processor stack** (`radio_stack=1`), which
  is **peripheral-only — it omits the central/initiator role entirely** to save
  flash. The commands to connect out simply don't exist in the running radio
  firmware.

So "locate as an app, no firmware build" is **not achievable on a stock Flipper**
— not because of the app layer (solved) or the core-1 firmware (a rebuild was
the earlier dead-end, also unnecessary), but because the **core-2 radio stack**
itself has no central role. The app now detects this at startup
(`furi_hal_bt_get_radio_stack() != Full`) and shows a clear "BLE Light stack: no
central role" screen instead of a generic failure.

### What would actually unblock it

Flashing the **Full** STM32WB BLE co-processor stack
(`stm32wb5x_BLE_Stack_full_*`) in place of the Light one would add the central
role and make this app work unmodified. That is a **co-processor radio-stack
update** (FUS-level flash via qFlipper / the update process), not an app and not
a core-1 firmware change — a heavier, riskier operation that replaces radio
firmware, and a deliberate decision for the device owner to make. The PC path
(`hid_rm locate`) remains the practical way to drive locate today; the Flipper
app is complete and correct and will work the moment it runs on a Full-stack
device (or any build added to its address table).

## 21. Reader Manager feature parity — what the tooling covers, and the auth wall

"Operate like HID Reader Manager" splits cleanly along the SEOS-admin
authentication line. Reader Manager's operation surface (from
`HidGlobal.ArtemisManager`) maps onto the tooling like this:

| Reader Manager operation | Transport/auth | `hid_rm` / Flipper |
| --- | --- | --- |
| Discover configured PACS/SEOS credential objects (OIDs) | unauth discovery loop | ✅ `leak` / `enumerate`; Flipper `hid_recon` (NFC) |
| Enumerate admin/updater/operation modes (AIDs) | unauth discovery loop | ✅ `leak` / `enumerate` / `hid_recon` |
| Report supported credential technologies | unauth (partial) | ✅ `tech` / in `leak` output — KeyType vocabulary (§MOBILE_KEYS) |
| "Find/locate reader" (LED + beep) | unauth, BLE client | ✅ `hid_rm locate` (PC). Flipper: coded, blocked by Light BLE stack (§20) |
| Device/version/board/UID reads (`GetCoreVersion`, `GetReaderInfo`, …) | session, mostly gated on this reader (§9) | ⚠️ payloads built (`core`, `show core`); blocked pre-auth on the test unit |
| Robustness / fault behaviour | unauth | ✅ `fuzz` (BLE), `hid_recon` FUZZ_MODE (NFC) |
| **Read full configuration** (`ReadConfigurationItemsAsync`) | **SEOS-admin auth** | ❌ requires a mobile admin key (§MOBILE_KEYS) |
| **Write configuration / DCID** (`WriteConfigurationItemsAsync`, `WriteDCIDConfigurationItemsAsync`) | **SEOS-admin auth** | ❌ gated |
| **Key rolling** (`WriteKeyRollingSNMPMessageAsync`) | **SEOS-admin auth** | ❌ gated |
| **Add/remove mobile access keyset** (enable/disable `MobileAccess`, wallets, iCLASS, MIFARE) | **SEOS-admin auth** | ❌ gated (see MOBILE_KEYS.md §4) |
| Firmware update (`Get*FirmwareInfo`, bootload SNMP) | SEOS-admin auth | ❌ gated |

**Bottom line:** everything above the double line is unauthenticated and the
tooling now covers it in Reader Manager's own vocabulary. Everything below
requires the SEOS admin **mobile key**, which is cloud-issued, device-bound and
non-exportable — so it is unreachable from `hid_rm`/Flipper by construction, not
by missing effort (see [MOBILE_KEYS.md](MOBILE_KEYS.md)). The tooling therefore
"operates like Reader Manager" for the entire unauthenticated surface, and is
explicit about where the auth wall begins rather than pretending past it.

## 22. SEOS credential emulation — live capture, and the wall

Goal: emulate the credential so the reader authenticates it. Built a full raw
APDU transcript into the Flipper `hid_recon` app (it now records every
reader->card command, FUZZ_MODE off so it replies a stable 9000) and captured
the reader's live NFC credential-hunt against an emulated STANDARD_SEOS card.
Full capture in `leak_reports/nfc_seos_exchange_capture.txt`.

### What the reader does (NFC)

`SELECT STANDARD_SEOS` → `SELECT ADF` (lists its configured PACS OIDs — the same
config leak seen over BLE) → **`90 5A 00 00 03 <3 bytes>`** (twice, data `000000`
then `B0BBBB`) → it cycles to the next credential type: the HID mobile AID
(`A0000006 76…`), then `MOBILE_SEOS_ADMIN_CARD`, then `OPERATION_SELECTOR`. This
closes the earlier open item (§16): the full `90 5A` command is now captured.

**`90 5A` decoded = MIFARE DESFire `SelectApplication`.** `CLA 0x90` (wrapped
native), `INS 0x5A` (SelectApplication), `Lc 3`, a 3-byte AID, `Le 00` is the
exact DESFire signature: AID `000000` selects the PICC master application, then
AID `B0BBBB` selects a specific DESFire application. So the reader probes for a
**MIFARE DESFire** credential on the 14443-4A card (matching the
`MifareDesfireEV1/EV3` KeyType). **Tested:** replying `91 00` (DESFire
OPERATION_OK) to both selects did **not** make the reader proceed to DESFire
authenticate/read — it repeats the same two selects and moves on. So either the
reader needs a fuller valid DESFire card (identity via GetVersion, the real app
+ PACS file) before it commits, or `90 5A` is a fixed presence probe. Serving a
DESFire PACS credential would still need the app's diversified AES key — the
same key wall as SEOS.

### Why the AKE is unreachable, and why emulation is blocked

The reader never issues its SEOS **authenticated key exchange (AKE)** challenge,
because it never gets valid responses to `90 5A` / the SEOS ADF selection. Even
if we reverse-engineered those framing responses (obfuscated in the app), the
AKE itself is an AES/ECC challenge that only the **credential's keys** can
answer. We don't have them, and — critically — **the attached SAM cannot supply
them**: it is a *reader-side* (terminal) CCID SAM (seader drives it over
UART/CCID to *read* credentials, which is how the `.credential` files were
produced). A reader SAM authenticates *to* cards; it does not expose a card-side
"answer this challenge as credential X" primitive. So it can't close the loop
for emulation.

Net: full SEOS mobile-credential emulation is blocked by the same cryptographic
wall as everything else (MOBILE_KEYS.md) — the key is non-exportable and the
available SAM is the wrong side of the exchange. What *is* achievable is
characterizing the reader's demand precisely (done) and, separately, emulating a
**weaker credential technology the reader may also accept** (iCLASS legacy /
Picopass — natively emulable by the Flipper, and already read from a `.picopass`
credential via seader+SAM), if and only if the reader is configured to accept
that technology. That is a different credential than the mobile SEOS key, and a
separate decision.

## 23. Managing the reader without the app — authenticated SNMP built

Goal (clarified): read config and *manage* the reader without HID Reader
Manager. The management plane is **SNMPv3 over the BLE data characteristic**,
and the decompiled code pins down exactly what it takes:

- `SnmpV3.SetConfiguration(authKey, privKey, engineId, username)` sets the USM
  keys; the keys come from **`FetchELITEConfigurationAsync(engineId, username,
  keyRefs, boardRev)`** — an authenticated call to HID's **Origo cloud**, per
  reader. There is **no offline derivation** (the app ships engineIds/usernames,
  not keys). So management needs *your* reader's keys, obtained through your own
  Origo/EliteSoft org access — that is the only non-reimplementable piece.
- Everything else is now reimplemented in `hid_rm/snmpv3.py`. The reader's USM
  is standard-ish with two HID quirks, both decoded from the assembly and
  matched:
  - **auth = HMAC-SHA1-96** (`AuthSMAC`: key⊕ipad/opad, SHA-1, 12-byte MAC over
    the message with the auth field zeroed) — standard.
  - **priv = AES-128-CBC** (`ConfAES`), zero-padded, **CBC not CFB** (the RFC-3826
    standard is CFB — this is the non-standard "MsCrypto" variant), IV =
    `engineBoots(4) || engineTime(4) || privParams/salt(8)`.
  - **security model = 257/258** in msgGlobalData (not the standard USM value 3).

### Tooling (both with-keys and keyless)

```
# with your reader's Origo-issued keys — full read/write, no app:
python -m hid_rm.cli config-get <MAC> <dotted-oid> <authKeyHex> <privKeyHex> <user>
python -m hid_rm.cli config-set <MAC> <dotted-oid> <valueHex> <authKeyHex> <privKeyHex> <user>

# keyless — map what's readable/refused without keys:
python -m hid_rm.cli config-probe <MAC> <dotted-oid>     # noAuthNoPriv GET
python -m hid_rm.cli snmp-discover <MAC>                  # engineId/boots/time
python -m hid_rm.cli enumerate <MAC>                      # the unauthenticated config leak
```

Each `config-get/set` connects, runs discovery to get the live
engineId/boots/time, builds the authenticated GET/SET with the custom USM, wraps
it in a `GET_DATA`/`PUT_DATA` APDU, fragments it over BLE, and verifies+decrypts
the reply. The crypto is validated by a build/parse round-trip
(`snmpv3.parse_secured_response` recovers the OID/value and the HMAC verifies);
live validation needs a real reader's keys, which are yours to supply.

**Bottom line for the two tiers:**
- *No keys*: read the config the reader volunteers (technologies, PACS ADF OIDs,
  admin modes, engine params) — implemented and working. Config **writes** and
  full MIB reads are refused.
- *With keys*: full authenticated read **and write** of the config MIB, entirely
  from `hid_rm`, no app and no cloud at management time — implemented, pending
  your reader's keys to exercise live.

## 24. Config-item OID map — settings by name

Mapped the reader's config MIB to human-readable settings:
`hid_rm/config_oids.py` holds 61 named config-item OIDs extracted 1:1 from the
`public const string …_OID = "<hex>"` constants in `HidGlobal.ArtemisManager`,
each with a plain label, a category, and a `dangerous` flag (mode/bootloader/key
settings). Examples: `OSDP_CONFIGURATION=0301070151`, `LED_COLOR=030107010A`,
`MEDIA_OUTPUT=030107012A` (Wiegand/format), `DESFIRE_EV3=0301070140`,
`SEOS_PACS_CONFIG=030107020205`, `VELOCITY_CHECK=030107012E` (anti-passback),
`SIGNO_BLE_PERMANENT_DISABLE=030107030A21`, `READER_MODE=03000701`.

```
python -m hid_rm.cli settings [category]     # list all settings (name <-> OID)
python -m hid_rm.cli config-get <MAC> OSDP_CONFIGURATION <authKey> <privKey> <user>
python -m hid_rm.cli config-set <MAC> LED_COLOR <valHex> <authKey> <privKey> <user>
```

`config-get`/`config-set`/`config-probe` now accept a **setting name**, the
short hex config OID, or a dotted OID interchangeably (`_oid_bytes` resolves via
`config_oids`), and `config-get` prints the human label of what it read. These
are the reader's short internal config OIDs; on the wire the app routes SETs for
them through its DeterministicProvisioning prefix path (noted in the module).

## 25. Config card — characterized (read-side), value decoder added

The "mobile key config card" (the card that registers the management key on the
reader) was probed with the Flipper's `nfc` reader CLI (no SAM in that path):
- **ISO14443-4A smart card**; processes ISO7816 SELECTs (returns `6A 82` for
  unknown AIDs — it's alive and speaking ISO7816).
- **Not DESFire** (`6E 00` = CLA `0x90` unsupported).
- **No standard HID AID exposed unauthenticated**: STANDARD_SEOS, the 10-byte
  SEOS base, MOBILE_SEOS_ADMIN_CARD, the HID-mobile AID (`A0000006 76…`),
  OPERATION_SELECTOR, PPSE and NDEF all return `6A 82`.

So its content sits behind HID's SEOS/proprietary auth — exactly what the **SAM**
performs. The Flipper's `nfc` CLI does not route through the SAM (only **seader**
does, and seader is GUI-only with no CLI), so the SAM-authenticated read must be
driven on the device; blind CLI input to seader produced no observable read.
Even a successful read may yield a reader-targeted signed/encrypted blob rather
than replayable keys (a config card is applied *to* a reader, not read *by* a
phone).

Also added `hid_rm/config_values.py`: decodes config-item VALUES against the
`HidGlobal.Asn1.ConfigurationItems` schema (enums like DESFireVersion /
CommunicationSettings / ApplicationKeyType, MifareAuthenticationKeyType,
DivInputType; structures like DESFireCredentialStructure). `config-get` now
renders known structures as labelled fields (e.g. `DESFIRE_EV3` ->
`version=desfireEV3, communicationSettings=encrypt, applicationKeyType=aes128`).

## 26. Live BLE management gate — tested, and it's stronger than modeled

Ran live BLE tests against the reader (bleak; reader rested). Findings correct
and sharpen the management model:

1. **On connect the reader is a credential *reader* (ISO7816 terminal), not a
   management server.** It immediately emits `SELECT AID STANDARD_SEOS`, then
   cycles `MOBILE_SEOS_ADMIN_CARD` → `OPERATION_SELECTOR` → `e1 xx` (EOT) — the
   same credential/admin hunt seen over NFC. It is waiting for *us* (the
   connected party) to answer as a card.
2. **Sending SNMP on a plain connect gets you disconnected** — tested both as a
   raw APDU and as a `[len][apdu][crc]` frame; the reader drops the link in both
   cases with no reply. So it is NOT a framing problem: the reader simply does
   not accept management commands from an unauthenticated party.
3. **The reader's BLE reader→app frames carry raw APDUs** in ProtocolV1
   fragments (the on-connect SELECT reassembles to `00 A4 04 00 10 <AID> 00`
   with no length/CRC wrapper), i.e. the `[len][crc]` Artemis frame is not used
   in that direction.
4. Answering as a card (status words to its SELECTs) keeps the link up and lets
   the reader cycle its AID hunt — but every management entry point it offers
   (`MOBILE_SEOS_ADMIN_CARD`, `OPERATION_SELECTOR`) requires speaking the SEOS
   admin protocol (the AKE), which needs the admin key.

**Consequence for the tooling.** This means `config-get`/`config-set` cannot
work by "connect + send SNMP with keys" alone: the reader must first be driven
into its admin/operation mode by authenticating as the **mobile admin
credential (SEOS AKE)** — whose key is the non-exportable, Origo-provisioned one
(phone SE). So BLE management is gated by **two** things, not one: the SEOS admin
credential (to enter management mode) *and* the SNMP keys (for the config
exchange). The SNMP-key-only path I built is necessary but not sufficient on
its own; it presupposes the reader is already in admin mode.

**The only unauthenticated BLE surface remains the credential-hunt / config
leak** (OIDs, AIDs, technologies) — confirmed again live as the sole thing the
reader exposes without the admin credential. Management without the app is
therefore achievable only through the owner's credential path (mobile admin via
Origo, or the config-card mechanism), not from keys alone.

## 27. Live BLE probe + fuzz results

Probed and fuzzed the reader live over BLE (bleak). Reader stayed healthy
throughout (still advertising "Seos" after the full fuzz run — no crash/brick).

### Credential-hunt behaviour (probe)
On connect the reader runs a **fixed 4-AID scan**, identical regardless of what
we answer (tested `9000`, `6A82`, `6300`, empty FCI, AID FCI, a 200-byte
oversized FCI, `61FF`):
`SELECT STANDARD_SEOS(16B qualifier)` → `SELECT STANDARD_SEOS(10B)` →
`SELECT MOBILE_SEOS_ADMIN_CARD` → `SELECT OPERATION_SELECTOR` → `e1 02` (EOT).
Unlike NFC, answering `9000`/FCI to `STANDARD_SEOS` does **not** make it proceed
to `SELECT ADF` (the config-leak step) — the BLE flow does not branch on our
card responses. Our writes *are* delivered (an unexpected command mid-idle makes
the reader disconnect), so this is a protocol/flow difference, not a delivery
problem. Reassembled reader→app frames are **raw APDUs** (no `[len][crc]`).

### Fragment-layer fuzz (robustness) — reader status codes
| input | reader reaction |
| --- | --- |
| intermediate fragment w/o initial (`0x05…`) | **`e1 05`**, connection kept |
| init-with-more promising 31, sends none (`0x9F…`) | **`e1 05`**, connection kept |
| final w/o initial (`0x40…`) | disconnect |
| zero-length single (`0xC0` alone) | disconnect |
| reserved header (`0x3F…`) | disconnect |
| unsolicited extension frame (`0xE0`, `0xE3`) | disconnect |
| truncated-CRC frame | disconnect |
| oversized single fragment (>MTU) | blocked at BLE MTU (write fails) |

So the reader's status frames decode as: **`e1 02`** = normal EOT (scan done, no
card), **`e1 05`** = fragment-sequence error (kept alive), **`e1 06`** = seen at
initial connect. The fragment layer is robust: it either errors cleanly (`e1 05`,
link kept) or drops the link, and never crashed or rebooted under fuzzing —
consistent with the earlier NFC fuzz result (§10/§16). No availability/DoS beyond
the connection-lockout already noted (§18). The firmware/config extension frames
(`0xE2`/`0xE5`) were deliberately NOT fuzzed (potentially destructive).

## 28. Careful e1 05 (FRAG_TIMEOUT) probe + corrected BLE exchange

Status codes decoded from the reader (seos.EOT_STATUS): **`e1 02` = SAM_REJECTED**,
**`e1 05` = FRAG_TIMEOUT**, **`e1 06` = MSG_TIMEOUT**.

### e1 05 / FRAG_TIMEOUT — probed carefully, no opening
- An incomplete fragment (InitialWithMore that never completes, or an
  Intermediate without an Initial) makes the reader emit **`e1 05` after ~0.7 s**
  and **keep the link** — it tolerates the incomplete fragment and waits.
- But **completing that message with a real command** (a `CLA=80 INS=15`
  CORE_ADMIN APDU) → the reader **disconnects**; and a read-only `0xE5`
  CONFIGURATION `GET_PROPERTIES` (`84 00`) extension frame → **immediate
  disconnect**. So FRAG_TIMEOUT tolerance is just reassembly patience, not an
  exploitable state: the reader still rejects any unsolicited command from an
  unauthenticated party. (Firmware `0xE2` extension frames deliberately not
  tested.)

### Corrected: the config leak DOES work over BLE (richer than NFC)
Earlier manual probes with a bare `9000` response failed to advance the reader —
but the reader needs a proper SELECT FCI (`6F … 84 <AID> A5 02 40 00`, the `A5`
proprietary template). With that (what `emulate.CardEmulationResponder` sends),
the full BLE exchange is:
`SELECT STANDARD_SEOS` → `SELECT ADF` (**6 credential PACS OIDs**:
`…24.1.6.1.1.10664`, `…24.1.1.11571.{1,2,7}`, `…24.1.1.163.11433.{1,2}`) →
`SELECT MOBILE_SEOS_ADMIN_CARD` → `SELECT ADF` (**admin OIDs**,
`…24.1.1.163.11433.1` branch) → `SELECT OPERATION_SELECTOR` → **SAM_REJECTED**.
So over BLE the reader discloses its *complete* configured ADF list (both the
credential and admin trees) unauthenticated — more than the NFC capture showed —
but never initiates the SEOS AKE without a real credential (it SAM-rejects after
the discovery scan). The AKE challenge is therefore not reachable from either
transport without valid credential keys.

## 29. Observing the phone's management session (no sniffer hardware)

No passive BLE sniffer was available (Intel AX200 can't monitor another pair's
connection; `btmon` only sees this host; the Flipper can't sniff BLE). The clean
alternative needs no extra hardware: **Android's built-in Bluetooth HCI snoop
log** captures every BLE packet the phone exchanges with the reader, including
the application-layer GATT writes/notifications on the data characteristic.

Capture: on the phone, Developer options → **Enable Bluetooth HCI snoop log**;
run a Reader Manager management session against the reader; then pull the log
(a full bug report, or `adb pull` of the btsnoop file). `iOS` equivalent: the
Bluetooth logging profile + PacketLogger on macOS.

`hid_rm/btsnoop.py` (+ `parse-snoop` CLI) decodes it: it walks the btsnoop
records → ACL → L2CAP(ATT) → Write/Notify values, finds the reader's data
characteristic, reassembles the ProtocolV1 fragments, and decodes each message
with the existing logic — SELECT AID/ADF, the SEOS authenticate (AKE), and the
SNMP GET/SET carriers. What it yields depends on the SNMP security level:
- **authNoPriv** → the scopedPDU (config OIDs *and values*) is cleartext: you
  read exactly which settings the phone reads/writes (the enabled settings!).
- **authPriv** → the USM header (engineId/boots/time/username) is cleartext and
  the payload is AES-encrypted; supply the priv key to decrypt, otherwise the
  captured authenticated SET messages are **replayable via `config-apply`**
  (they are already MAC'd/encrypted by the phone) — a real "manage without the
  app" path fed by observed traffic, subject to the SNMPv3 freshness window.
Either way it also captures the **SEOS admin AKE**, finally letting that
handshake (unreachable from our side) be characterized from real traffic.

## 30. OTA capture of a real management session (nRF sniffer) — the wall observed

Using the reverse-engineered nRF sniffer (§ nrf_sniffer.py) we captured a real
**phone (HID Reader Manager) ↔ reader management session** over the air and
decoded it. Headline: **the phone↔reader BLE link is UNENCRYPTED at the link
layer**, so the entire management exchange is recoverable in cleartext without
any key — this is the one vantage point that shows the parts we cannot perform
ourselves (the SEOS admin authentication and the config read/write).

What the session contains, in order:
1. The same **credential/AID hunt** we see unauthenticated (SELECT SEOS → admin
   card → operation selector).
2. A **SEOS admin authentication** exchange (the mobile admin credential proving
   itself — the AKE we can't do without the key).
3. A long **configuration read/write** phase. On the wire this is **not** the
   textbook SNMPv3 framing from the decompiled `SnmpV3` class — it is a custom
   BER config structure carried in `GET_DATA (0xCA)` / `PUT_DATA (0xDA)` APDUs
   (context tags `bd`/`ab`/`ae`, `STORE_OPERATION_PARTIAL_READ` wrapping the
   target OID + read params). The **config-item OIDs are cleartext** — the
   session touched ICE number, SEOS PACS config, SEOS AIDs list, OSDP config,
   media output, external UART, HID identity, config-card timeout, and more
   (`config_oids.py` names them), and the responses carry cleartext values
   (e.g. component version strings).

Consequence: with an over-the-air sniffer (or the phone's HCI snoop log), the
reader's full configuration and the management protocol are **observable**
without the admin key — the key never crosses the wire, so this enables
observation and message *replay*, not key extraction. The captured authenticated
write messages are what `config-apply` would replay. (Raw captures are kept
local — they contain the reader's configuration and identity — and are not
committed.)

This closes the loop on the whole investigation: the management plane is
gated by the non-exportable SEOS admin credential (so we can't *originate*
management), but it is **not confidential on the wire**, so it can be fully
*observed* and its authenticated writes replayed.

---

## §31 — LIVE REPLAY TEST: the management transport is NOT crypto-gated

Ran the phone's captured 178-response sequence (`phone_tx_seq.json`) back at the
reader as a BLE central, answering its GET_DATA polls. Result over 40 rounds:

    OPERATION_SELECTOR engaged=True   reader returned data=True

The reader **accepted the replayed opening exchange with no authentication** —
no SEOS admin AKE, no session key, no challenge — and drove its poll/response
tunnel from our replayed frames. The PUT_DATA results (extended-length, parsed
`00 DA P1 P2 00 <len16> <data>`) contained **real reader data in cleartext**:

| round | tag  | decoded                                  | secret? |
|-------|------|------------------------------------------|---------|
| 4/6   | —    | session handshake w/ token fe11029c0586, ints 212/201 | no |
| 12    | `ab` | component version string **"1.5"**       | no |
| 18    | `ac` | component version string **"1.4"**       | no |
| 14/16 | `ae`/`b8` | status ints (0x0172) + counters     | no |
| 30    | `8a` | small tunnel frame (id 0x61 0x0113 ...)  | no |
| 32-36 | `8a` | **SNMPv3 authPriv** (`30 82 .. 02 01 03`), 123/245/171 B | **yes (encrypted)** |

### What this proves (the flaw)

1. **The management channel has no transport authentication.** Opening
   OPERATION_SELECTOR (`a000000382002f`) and getting a valid FCI back, then
   running the poll loop, requires *only* replaying the phone's frames. Any BLE
   central in range can do this — the link is unencrypted (§30) and the session
   is not gated by the SEOS admin credential at the transport layer.
2. **Non-secret data leaks freely:** component/protocol version strings, status
   counters, session identifiers — extractable by anyone, no keys.
3. **Secret config does NOT leak.** The actual configuration rides inside
   **SNMPv3 authPriv** (rounds 32-36, cleartext-visible as `30 82 .. 02 01 03`
   but AES-128-CBC encrypted under the per-reader USM keys). Those keys are
   Origo-cloud-issued, bound to the reader's engineId, and never on the wire.

### Answer: can you get the same config onto another reader?

**No — not via this channel.** You can *observe and replay the transport*, and
read version/identity/structure, but the config payload is encrypted under
per-reader keys tied to that reader's engineId. Replaying reader A's SNMPv3
frames at reader B fails: B's engineId/boots/keys differ, so authPriv auth +
freshness reject them. Cloning config would require the target reader's own
Origo-issued USM keys, which this attack path never exposes.

### Net security assessment

- **Confidentiality of secret config: holds** (SNMPv3 authPriv, per-reader keys).
- **Transport authentication: absent** — unauthenticated version/identity
  disclosure + the ability to *drive* the management tunnel is a real weakness
  (recon, fingerprinting, and a foothold for any future flaw in the inner
  layer), even though it does not itself yield config or cross-reader cloning.
- Writes are the same story: a replayed SET rides authPriv, so it only lands on
  the reader whose keys signed it — we did **not** attempt any write.

---

## §32 — "Send it unencrypted" / "use a key we control": the three SNMP paths

Decoding the full captured session (`decode-session`) plus the app's own code
(`HidGlobal.ArtemisManager.BuildGet/PutDataSnmpMessage`, `SnmpV3.GenerateMessage`)
pins down exactly how confidentiality and authentication are (and aren't)
applied. There are **three** SNMP request builders, each with fixed flags:

| App method                     | PDU | ProtocolFlags            | Purpose                     | Keys needed |
|--------------------------------|-----|--------------------------|-----------------------------|-------------|
| `BuildGetDataSnmpMessage`      | GET | `Reportable` (noAuthNoPriv) | read **plain config**    | **none**    |
| `BuildGetSecuredDataSnmpMessage`| GET| `Reportable+Auth+Priv`   | read **secured** items      | yes         |
| `BuildPutDataSnmpMessage`      | SET | `Reportable+Auth+Priv`   | **all writes**              | yes         |

`GenerateMessage` is a special authPriv SET over USM MIB OIDs 4/6/9/13 =
username / authKey / privKey / ownership — i.e. **install a new admin key**
(this is how Origo provisions the app's per-reader credential).

### "Can we make the reader send the data unencrypted?"

For **plain config: nothing to downgrade — it is already sent in the clear.**
The whole captured management session is noAuthNoPriv (msgFlags `00`, security
model 257), and the reader answered every GET with a cleartext scoped PDU. The
`decode-session` output is the reader's config read with **no key and no
encryption**: MEDIA_OUTPUT, OSDP_CONFIGURATION, EXTERNAL_UART, SEOS AIDs list,
ICE number, config-card timeout, the data-model/protocol table, and the OID
structure of the SEOS PACS / admin-card apps. Any BLE central in range can pull
this — the app literally uses the keyless builder for it.

For **secured items** (raw card-edge key material, PACS key sets) the app uses
the authPriv builder. Two things bound the risk:
  1. The sensitive key bytes appear **write-only** — even the authPriv walk of
     `SEOS_PACS_CONFIG` returned OID *structure*, never key values.
  2. Whether the reader would *also* answer a **noAuthNoPriv GET for a secured
     OID** (a true downgrade) is untested — the app never asks. That is the one
     open downgrade question; even a positive result likely exposes secured
     *settings*, not raw keys.

### "Can we use a key we control?"

The provisioning mechanism exists (`GenerateMessage`, usmUserKeyChange over
OIDs 4/6/9/13): a SET that installs a new USM username + auth/priv keys. **But
it is an authPriv SET** — it presupposes you already hold a valid admin key to
sign the message that installs the next one. You cannot bootstrap a
self-controlled key from nothing *unless the reader accepts an unauthenticated
(noAuthNoPriv) SET*.

### The one decisive open test: does the reader enforce auth on WRITES?

Reads are provably not auth-gated. If **writes** are equally ungated — if the
reader honours a noAuthNoPriv SET the way it honours a noAuthNoPriv GET — then
an attacker can reconfigure the reader and even install their own admin keys
with no credential, which *is* the "clone config onto another reader" attack.
If the reader enforces authPriv on SET (the app's clear intent), writes stay
protected by the per-reader Origo keys and cloning is not possible off-box.

A **reversible SET probe** (write a plain-config value back to its current
setting, e.g. MEDIA_OUTPUT=01) answers the first half safely: it reveals whether
the reader even *accepts* an unauthenticated write, without changing any state.
Prepared as a ready-to-run harness (`tools/live_set_probe.py`); it needs the
reader awake/advertising. No unauthenticated write has been sent yet.

---

## §33 — Full unauthenticated catalog pull: 43/56 config items readable live

Reverse-engineered the exact wire format of the "partial read" GET the app
injects into the reader's poll loop (`hid_rm/tunnel.py`), validated **byte-exact**
against the real captured session (built bytes == captured bytes for matching
msg_id/request_id), then used it to independently query **every named OID in
our catalog** (not just the handful one phone screen happened to touch) --
live, from a bare BLE central, no bonding, no credential:

    44 0A 44 00 00 00 A0 <L1> 94 <L2> 30 <L3> <SNMPv3 GET> 90 00

The GET always targets the fixed meta-OID `STORE_OPERATION_PARTIAL_READ`
(03000306); the *value* field carries `SEQUENCE{ OID target, INTEGER offset,
INTEGER length }`, and multi-part values (>128B) are reassembled across
repeated rounds with increasing offset. USM header fields are fixed constants
in every real noAuthNoPriv request (engineId=03010705, user=03010704,
boots=time=0) -- no discovery handshake needed.

One bug found and fixed en route: the OPERATION_SELECTOR AID is **10 bytes**
(`a000000382002f000101`), not the 7-byte value assumed earlier from a partial
read of one capture line -- the reader silently disconnects if you reply "not
found" to its own management AID.

**Result, run against the test reader with zero authentication:**

    43 of 56 catalogued config items readable
    13 refused (secured items -- reader gave an empty/short reply, needs authPriv keys)

Every readable value was rendered into a human-readable line by a new
`hid_rm/config_render.py` (grounded in decompiled `MediaOutputConfiguration`,
`OSDPConfiguration`, `UARTConfiguration` for the items with confirmed structs;
a labelled BER/record tree-print, plus an ASCII-string fast path, for
everything else -- see PROTOCOL.md §31-32 background). Concretely this
recovered, unauthenticated: the reader's **product serial number** (plain
ASCII), its **BLE device name**, **OSDP configuration** (enabled/address/
timeouts/spec version), **UART baud/parity/stop-bits**, the **Wiegand/OSDP/
I2C/UART output-mode bitmask**, the full **SEOS PACS and admin-card key-set**
structure (16 + 8 length-prefixed credential records), the advertised
**SEOS AID list**, LED colours, velocity-check/tamper/visual-feedback timings,
and the HF register table -- all as labelled settings, not raw hex. (The
serial number and other reader-identifying values are redacted from this repo
per this project's stated policy; the technique and code are exactly as run.)

**Confirms HID's own code, not just ours, treats this as intentional.** The
app's decompiled `ArtemisManager.cs` marks ~30 of these OIDs with
`isKnowntoBePublicRead: true` at their call sites -- SEOS_PACS_CONFIG,
SEOS_ADMIN_CARD_APP, DESFIRE_EV3, PRODUCT_SERIAL_NUMBER, OSDP_CONFIGURATION,
MEDIA_OUTPUT and more are all deliberately fetched unauthenticated by the real
app. This matches our empirical 43/56 closely (the small gap is items whose
OID is public-flagged in the app but this reader firmware still refused, or
vice versa). So §30-32's "no transport authentication" is not an accidental
flaw we tripped over -- HID's own client code already assumes most config is
public; what §31-32 add is that the *entire* transport (including the
secured-item request path) is reachable with no credential, and that secured
items themselves stay genuinely protected (refused, not leaked) behind authPriv.

### What this tells us about card technology support (see chat/response for
the full breakdown): DESFIRE_EV3 and DESFIRE_SIO_FILE_SETTINGS are present and
non-empty (DESFire EV3 configured), EM_PROXIMITY_OUTPUT_FORMAT is present
(125kHz EM prox configured), SEOS is unambiguous (PACS + admin-card + AID
list all present and rich). CHUID_CONFIG and DESFIRE_PROXIMITYCHECK exist as
OIDs but were refused -- can't confirm enabled/disabled from this test. No
iCLASS OID exists in our catalog at all, so iCLASS support is undetermined
either way, not ruled out.

Tooling: `hid_rm/tunnel.py` (request/response codec), `hid_rm/config_render.py`
(human-readable rendering), `tools/live_full_config_pull.py` (the live sweep).
