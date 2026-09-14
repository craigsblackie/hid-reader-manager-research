# HID Reader Manager 1.33.1 — Security Analysis Findings

Target: `HID+Reader+Manager_1.33.1_APKPure.apk` (com.hidglobal.pacs.readermanager)
Workdir: `~/hid/`

## Progress log
- [x] Unpacked APK → `unpacked/`; jadx decompile → `jadx_out/` (12,618 Java files)
- [x] Manifest, permissions, signing cert, Firebase config, analytics secrets, crypto classes
- [x] Reverse-engineered `libassembly-store.so` (XABA container); extracted all 270 .NET assemblies → `dotnet_asms/`
- [x] String extraction from HidGlobal .NET assemblies (bypasses malformed PE headers) — found crypto keys, card tech types, crypto providers
- [x] Full decompile of HidGlobal .NET assemblies — UNBLOCKED (§9): blobs were LZ4-compressed,
      not malformed; all 270 assemblies decompile cleanly → `decompiled/`
- [x] Broad secret sweep of Java sources (§12a) — negative/validating, no new secrets
- [x] Inspect Assa Abloy MobileKey asset blobs (§12c) — structure characterized, contents
      opaque (no decryption keys available); `liba7a2.so` anomaly flagged but unresolved (§12b)
- [ ] Final report

## 1. App identity
- Package: `com.hidglobal.pacs.readermanager`, version 1.33.1
- .NET MAUI / Xamarin app (Mono). Native logic in `lib/arm64-v8a/libassembly-store.so` + `libxamarin-app.so`
- Self-signed cert: HID Global (SHA256 `04:B7:8D:83:44:B2:15:80:BD:72:37:69:78:4B:7A:58:57:47:A1:A1:39:BC:FD:F0:99:22:B4:CB:F2:F5:3A:6A`)

## 2. Hardcoded secrets (Java layer)
`jadx_out/sources/com/hid/origo/analytics/utills/ConstantsKt.java`:
- `SECRET = "DPFKaKQegG1MKFQJ"`
- `SECURE_LOGIN_CLIENT_SECRET = "DPFKaKQegG1MKFQJ"` (same value as SECRET)
- `SECURE_LOGIN_DISTINCT_ID = "5FkMe3Cech1viWo0"`
- `SECURE_LOGIN_TOKEN = "6RAA3uRLzqhfG113"`
- `SECURE_REGION = "fhgsadasdsadsdY7"` (looks like a test placeholder left in prod)
- `SECURE_SDS_TYPE = "ggGOp46XckD9ZR0d"`
- `SECURE_SUPER_PROPERTIES = "tQVBaZ3fgYMLInFs"`
- `SECURE_TIMED_EVENTS = "WNSKjbanP2f8yWVD"`

`resources.arsc` / Firebase:
- Firebase API key: `AIzaSyBsJ0ysY2wz3mu5__HbOs6pWZYjbZjBSQU`
- Project id `1:285745907272:android:cbc9123090acaaabc27a7d`, bucket `rm-distribution.firebasestorage.app`

Analytics endpoints (`BuildConfig.java`):
- DEV `https://uimlhvl3wc-vpce-010f9ef178975e612.execute-api.us-east-1.amazonaws.com/dev`
- PREPROD `https://preprod-eventlogger.api.hidcloud.com`, `https://preprod-eventlogger-api.origo.hidglobal.cn`
- PROD `https://prod-eventlogger.api.hidcloud.com`, `https://prod-eventlogger-api.origo.hidglobal.cn`
- Headers: `x-api-key`, `Authorization: Bearer`, `source-system`
- Auth endpoints: `/origo/sdkcredentialmanager/login`, `/origo/sdkcredentialmanager/registerdevice`

## 3. Crypto
- `MelSdsCipher.java`: AES/CBC/PKCS7Padding, AndroidKeyStore keys, Base64 IV handling
- `MelApiFacade.java`: wrapper for MEL (mel) analytics SDK
- BouncyCastle.Crypto.dll bundled in .NET store

## 4. .NET assembly store (libassembly-store.so) — format RE
- ELF; payload section at 0x4000 (17,144,877 bytes)
- XABA header @0x4000: magic `XABA`, version 0x80010003, entry_count=270, index_entry_count=540, index_size=7020
- Index @0x401C: 540 × 13 bytes
- Descriptors @0x5B84: 270 × 28 bytes = [data_offset(u32, rel 0x4000), data_size(u32), 0,0,0,0, name_index(u32, 1-based)]
- Names @0x7908: 270 × [u32 len][name]
- Each blob: 14-byte `XALZ` wrapper = `XALZ` + u32 idx + u32 usize + u16 flag(0x03F2) + raw PE
- PE inside: DOS header is SHORT (92 bytes); PE sig at MZ+0x5C
- All 270 extracted to `~/hid/dotnet_asms/`; key ones: HidGlobal.ArtemisManager(.Portable/.UI).dll, HidGlobal.Asn1(.Messaging.Artemis/.ConfigurationItems).dll, HidGlobal.SDI.SnmpV3.dll, HidGlobal_AppSettings.dll, HidGlobal.Transport.dll, HidGlobal.Artemis.DeviceModel.dll, Plugin.SeosAdmin.*.dll, EasyHttp.dll, AndHUD.dll

### PE quirk (current blocker)
Extracted PEs fail .NET metadata parsing (ilspycmd/dnfile/pefile):
- `e_lfanew` (0x3C) originally garbage → patched to 0x5C (real PE sig location); that fixed "Invalid PE signature"
- Next error: "Unknown PE Magic value". COFF parses as: machine=0x14c, nsec=3,
  tds ok, psym=0xe0e20058, nsym=0x0b212200, SizeOfOptionalHeader=0x3001(12289),
  Characteristics=0x0000, optmagic=0x000e
- PE32 magic 0x010B actually found at PE+19 (not PE+24) → 5-byte misalignment in COFF region
- .NET metadata root ("BSJB", ver "4.0.30319") IS present at file offset 0x14E
- Constant byte pattern `58 00 e2 e0 00 22 21 0b 01 30 00 00` appears at PE+12..PE+23 in ALL assemblies
  → likely a fixed XALZ template, not real psym/nsym.

## 4b. .NET assembly string extraction (HidGlobal core)

Because the PE headers are malformed, I extracted strings directly from the .NET
metadata (#Strings stream) of each HidGlobal assembly. Key findings:

### HidGlobal.Asn1.dll (core ASN.1 / crypto)
**Crypto providers & algorithms referenced:**
- `RSACryptoServiceProvider`, `RijndaelManaged`, `SymmetricAlgorithm`
- `BouncyCastleRijndaelCryptoProvider`, `PaddedBufferedBlockCipher`
- `MD5`, `AES_ECB`, `CipherMode`, `CheckCrc`
- `snmpUserName`, `snmp` (SNMPv3 auth)

**Card / chip technology types:**
- `Mifare1`, `MifareDesfireEV1`, `Desfire`, `Picopass`, `Seos`, `Uhf`
- `Bluetooth`, `Mag` (magnetic stripe), `I2c`, `HF` (high frequency)

**Long base64/hex strings (likely crypto keys, IVs, or hashes):**
- `QE4O45wJ0otdl98x0SV`, `l8DY1MwdgwYJfpB9NsA`, `fCwSlHwwbfmeAZA6ySI`
- `OqMghNwkeRcGdp79yYt`, `o7D4TXw2rb12dy9MGsE`, `YjdEswwVkK2DdJd2lSW`
- `NgoG6SwAK5htXc88rfW`, `rn32qiwDrHjtMju0ds7`, `KAVXvckwaG6UT9avymPG`
- `TVpSXcwCn9aQSPPv5Ue`, `wjLsINwrKEpEPpsKJsE`, `PLJThbwOMMMmfBZA2cJ`
- `HkB0KwSkPBoiSABulj`, `usgnoZwYN3jOf4x4p7d`, `jD9dQbw3AmH4Z3nh7qy`

**Shared 40-hex-digit values (appear in ALL HidGlobal assemblies — likely GUIDs or shared constants):**
- `0E448EF5E5E60630BDDB19388CB6378436E3C65D03DD66DA7C6EBFF563BD857A`
- `4BED3ADC52D4904075F6BBF279EC4ACEDE079533B95E229A29809542EA324A7B`
- `7F535673D836D3D77A97DB03EB3D71EA780F44372F5AEBECEBEDD696AAEB8378`
- `97E613E5A3A47DEC76B7E50D47644B35EA4322F00D594D80D2F1C1F3644F8A4A`
- `C356AFF1A01C2B0DA472E584C8E3C8F875B9A24280435D42836A77B19F5A8C18`
- `C61B1941CF756EB7551F7C661743802362728B785ADC22E860D269713DFB01A6`
- `D5B7247C497788CF0031CEB06E3DF77A45FEF59F1E49633DC7159816D64759B5`
(These 8 values are identical across Asn1, Asn1.ConfigurationItems, Asn1.Messaging.Artemis, SDI.SnmpV3, and HidGlobal.dll — strong indicator of shared type-forwarded GUIDs or interop constants, NOT per-assembly secrets.)

**Per-assembly hex keys (likely field initializers / crypto constants):**
- Asn1: `a8ec354afe484d7a9e0eda3904385720F`, `4be193017574b1a8c38f1f9dc6a850`, `6d83b22845f54e91b8d7242c79f273`, `2e033bbdee45fe94008bac66aa09c`, `db132a0446794421bbe00bb40f7468e2`
- Asn1.ConfigurationItems: `2a4cc267748345eb89d68ecdbea4b3ff`, `e465acbfd2c24df7822ffacb7c405d05`, `ef2aacf5fadf44e18dbe00aa356e353b`, `9c212c2c122b42a598bd920c359f9af9`
- Asn1.Messaging.Artemis: `2f74a970d5de4a95915555d3c0ba723d`, `7191d94983d547d9a855fdae2acfcc00`, `5f3a1a985db44266ad438a14a7fc286`, `1becf7e9a1b3440c9668ac8b00e699e`
- SDI.SnmpV3: `20d8298dc39405abb8959d9b7675ae8`, `b5bce7c31244ddab918ea0d280fc4a4`, `3643d21195d4f6fbcbdf9921ccf494c`, `a7e476d77dd439f94f57592d7113c5b`
- HidGlobal.dll: `2b8e8eb4aec464e977a3ba45adffb72`, `62c198bdb5f4dbfb15feaa916eac7cF`, `af53bfb62254b569620dce4b2f7d83dF`, `34be95b0099f41e5837cdb9523c8997b`

**Base64-like tokens (22-char, likely encrypted/encoded secrets):**
- Asn1.Messaging.Artemis: `hePmUFr89R3VTrF0WCrj`, `yWQUwtr8QBpSy0c5XYim`, `aMZeRFr8DURfNSdGE3eB`, `EwOrjjDr800PbNAFbhq55`, `t65OZBr8ReJAhnBKbv2e`, `XGd17OrHmjr84wCsU1Ro`, `z3R9OcrHbYlqUPuGFcK5`
- SDI.SnmpV3: `z2knLWfMT57umoRnud`, `wvQDYHFEgab4SULby7`, `kifjX1nHsJhjGhPrb5m`, `uJlIv7nIqEtE3HZYpLm`, `cTTav6nfAPnI2xEU9lf`, `op0VeZnSj5iEIHBa76Y`
- HidGlobal.dll: `hXU8OkLcAUJAvDZGBJ`, `snHGccRfFdpENUgvQu`, `nJCQ4r1awPFIv7oqkCx`, `TYVKTf17PmS7LT2qxMZ`, `X1dqQX1kHtO9f8FhMx3`

### HidGlobal.SDI.SnmpV3.dll
- `AES_ECB`, `snmpUserName`, `ARTEMIS_SAMP`, `Token`, `HashAlgorithm`
- `OmnikeyReaderCore` (reader model)

### HidGlobal.ArtemisManager.dll
- `SignoSoftChargingLicenseDigest` (SignoSoft charging license — crypto)
- `FwEncryptedPackage` (firmware encryption)
- `InitFlashAccess`, `SNMPValue`, `pSeosCSN`
- `DataModelVsProtocol`, `ClearAndEnterEncodedAs0xEAnd0xFIfCheckedElse0xA`
- `GooglePDFViewerURL`, `isRequireContinue`
- GUID: `6990271E-6257-434A-9E3E-2C839F4E99CA`

### HidGlobal.ArtemisManager.Portable.dll
- URL: `https://doc.origo.hidglobal.com/legal/rm/en-US/EULA.html`
- `SHARE_ENABLED`, `IsFWUpgradeSupportedViaNFC`
- `SeosAdmin`, `Password`, `SIS_TOKEN`, `freshTokenIf`
- `CustomerReference`, `commandExecStatus`
- `+58a29e9631ecb47430289cc594e427b59982b225` (version hash)

### HidGlobal.Transport.dll
- URL fragment: `...toryUrl>https://c...` (likely a repository URL)
- `+89c503fffbe750dacd1f3567ade2f0a87076ed83` (hash)

### AndHUD.dll
- Hash: `4C87390A6A2BAC8F3F0318D6403361D0FCD4AF48049C6A3ADC1CAAD2239688CE`
- `SendEmptyMessageDelay`
- `5.Branch.main.Sha.31516de7e95bb75f51ed42da49df1a069bb61aad` (git commit)

### Plugin.SeosAdmin.Android.Binding.dll
- `Com.Hidglobal.Pacs.SE.Mobkeyswrap.I...` (SEOS MobileKey wrap interface)
- `uPassworD`, `bCipher`, `Sha1Ha` (SHA1 hash)
- `UseIpAddressForGeolocation`
- `/origo/analyt...` (analytics path)

### Plugin.Firebase.Auth.dll / Plugin.Firebase.Core.dll
- `GetIdTokenResult`, `AddAuthStateListener`, `AndPassword`
- `TokenExpired`, `WrongPassword`, `AccountExistsWithDifferent`
- Hash: `0103594baab0e59018245285c3ebb7384cee97a4`

## 4c. MobileKey + Reader NFC configuration (how it works)

The app wraps the Assa Abloy MobileKey (AAMK) SDK. Entry point:
`jadx_out/sources/com/hidglobal/pacs/se/mobkeyswrap/MobileKeysApiFacade.java`

**Identity constants (hardcoded):**
- `APP_ID = "READERMANAGER"`, `APPLICATION_DESCRIPTION = "HID Reader Manager"`
- Opening triggers registered at init: `TapOpeningTrigger`, `TwistAndGoOpeningTrigger`, `SeamlessOpeningTrigger` (BLE-based reader opening gestures)
- `ApiConfiguration(applicationId=READERMANAGER)` + `ScanConfiguration(triggers, maxReaders=1)`

**Lifecycle / reader-config flow (MobileKeysApiFacade):**
1. `initialize(context, apiConfig, scanConfig)` → `MobileKeysApi.getMobileKeys()`
2. `applicationStartup(callback)` — start the AAMK SDK (secure-element ready)
3. `personalize(endpointId, callback)` → `endpointSetup(...)` — **provisions/binds the reader (endpoint) to this phone's MobileKey**; the `String` arg is the endpoint ID
4. `isPersonalized()` → `isEndpointSetupComplete()`
5. `endpointUpdate(callback)` — re-sync endpoint
6. `processApdu(byte[])` → opens a `ReaderSession` (lazy) → `session.process(ApduCommand.parse(apdu)).toBytes()` — **all phone↔reader crypto happens over APDUs inside a ReaderSession**
7. `closeReaderSession()`, `getEndpointInfo()`, `getMobileKeys()`

**EndpointSetupConfiguration** (`assaabloy/mobilekeys/api/EndpointSetupConfiguration.java`):
- `SetupAkeKey` (AKE = Authentication Key Establishment key, used to bootstrap the secure session with the reader)
- `Region` (default `Region.US`)
- `ApplicationProperty[]`
- The class has an obfuscated helper (`AnonymousClass4`) that decodes/derives strings at runtime (char-substitution + XOR `0x3582`/13722) — likely hides AKE key material / endpoint names

**NFC path (Host Card Emulation)** — `assaabloy/mobilekeys/api/hce/`:
- `NfcConfiguration.Builder` defaults:
  - `attemptNfcWithScreenOff = false`
  - `timeout = 2000` ms
  - `transactionBackOff = 2000` ms (0–2000)
  - `numberOfNfcTransactionsNeeded = 1`
  - `attemptNfcPredicate` = always-true by default
- `ReaderConnectionController` (interface) exposes both transports:
  - NFC/HCE: `enableHce()` / `disableHce()`, `getNfcParameters()`, `enableNetworkOpeningsViaNfc()`
  - BLE: `startScanning()`, `stopScanning()`, `listReaders()`, `openReader(Reader, OpeningType)`, `getScanConfiguration()`
  - Network: `openNetworkReader(String)`, `getNetworkParameters()`

**Crypto algorithms (SEOS access layer)** — `seos/access/crypto/`:
- Encryption: `TRIPLE_DES_2K` (3DES 2-key, "DESede") or `AES_128`, both `/CBC/NoPadding`
- MAC/Hash: `CMAC_AES`, `SHA_1`, `SHA_256`
- `EndpointInfo` exposes per-endpoint `getEncryptionAlgorithm()`, `getHashAlgorithm()`, `getSeosId()`, `getJavaCardVersion()`, `getServer()` (TSM), `getUsername()`, `getDirectDownloadURL()`, `isPersonalized()`

**NFC support detection** — `hce/NfcSupportHelper.java`:
- Requires device feature `android.hardware.nfc.hce`, NFC adapter enabled, `android.permission.NFC`, and the SDK `HceService` component enabled
- NFC transport = Android Host Card Emulation (phone emulates the credential card to the reader)

**Reader transports (3 ways):**
1. **NFC/HCE** — phone emulates card; reader polls; governed by `NfcConfiguration` (timeout/backoff/tx-count)
2. **BLE** — `ScanConfiguration` + opening triggers (Tap / TwistAndGo / Seamless); `listReaders()`/`openReader()`
3. **Network** — `openNetworkReader(id)`; `NetworkParameters` = `connectionTimeout()` + `packetTimeout()`

**How a MobileKey open works (end to end):**
- Phone stores the MobileKey credential in the secure element (SEOS); blobs in
  `assets/com/assaabloy/mobilekeys/api/internal/{79974d41f9d592ea-,fc275f3f44b3c7a4b-}`
  are encrypted serialized `java/lang/StringBuffer` credential stores (13 KB + 539 KB).
- On tap (NFC/HCE) or BLE proximity, the reader initiates; the app opens a
  `ReaderSession` and runs the APDU-based mutual auth using the MobileKey +
  `SetupAkeKey` (AKE) to establish a secure session, then the reader unlocks.
- `MobileKeys.ADMIN_SESSION_PARAMS` = `Select.selectGdf()` + `GenesisPrivacyKeyset()` — admin SEOS session params.
- `generateOtp(mobileKey)` / `getOtpCounter(mobileKey)` — OTP-based challenge auth.

**Security notes (MobileKey/NFC):**
- [MED] `SetupAkeKey` material is derived/hidden by an obfuscated runtime decoder rather than a constant, but it lives in the app image; combined with `APP_ID`/region it is a fixed per-app endpoint-identity.
- [LOW] NFC `timeout`/`transactionBackOff` are 2 s defaults; `attemptNfcWithScreenOff` off by default (reduces screen-off replay window).
- [INFO] Reader binding is per-endpoint (endpointSetup with endpoint ID) — a phone is personalized to a specific reader/endpoint, not global.

## 5. Other assets
- `unpacked/assets/com/assaabloy/mobilekeys/api/internal/` — binary blobs (pending)
- `liba7a2.so`, `libxamarin-app.so` — string sweep pending
- Assa Abloy MobileKey SDK present (Assa Abloy and HID Global = same group)

## 6. Tools
- ilspycmd 8.2.0: `/tmp/opencode/ilspy/pkg/tools/net6.0/any/ilspycmd.dll`
  (run with `DOTNET_ROLL_FORWARD=LatestMajor dotnet <dll> <asm>`)
- Python venv: `/tmp/opencode/venv` (androguard, dnfile, pefile, lz4)
- jadx: `/tmp/opencode/jadx/bin/jadx`

## 7. Preliminary severity notes (to be expanded in final report)
- [MED] Analytics "client secret" + login token hardcoded in shipped code (ConstantsKt)
- [LOW/MED] Firebase API key exposed (normal for mobile, but combined with bucket name is enumerable)
- [TBD] .NET layer (ArtemisManager) — likely contains reader protocol endpoints, SEOS admin, SNMPv3 creds
- [TBD] Assa Abloy MobileKey blobs

## 8. BLE SEOS reader client (Python, Linux) — implemented & verified live

**Goal:** configure a HID MultiClass SE reader over BLE from Linux. Implemented and
tested against a live reader (`C0:60:33:15:2B:31` "Seos").

**Confirmed GATT layout (via live discovery, bleak 3.0.2 / BlueZ):**
- service        `00009800-0000-1000-8000-00177a000002`
- data char      `0000aa00-0000-1000-8000-00177a000002`  [write-without-response, notify]
- CCCD           `00002902-...`  (enable notify)
- device name    "Seos"; default MTU 23 (20-byte payload)

**Protocol (REVISED — from live probing + `mobilekeys/api/ble` decompile):** the BLE
data channel is NOT raw SEOS APDUs. Each frame = `[1-byte header][payload]`:
- **Reader → phone headers observed:**
  - `0x81` = SELECT (reader's own auto-select of the SEOS applet on connect).
    Payload = a SELECT-AID APDU: `00 A4 04 00 10 <16-byte AID>`.
    **[CORRECTED — see AAMK.md §6/leak.py]** The 16-byte AID here is actually
    `A0 00 00 04 40 00 01 01 00 01 00 00 47 05 2B 03` (this entry undercounted it
    by 2 bytes, dropping the trailing `2B 03`; recomputed precisely off the APDU's
    own Lc=0x10 field against a live capture). It is `Constants.AID.STANDARD_SEOS`
    (10 bytes, `A0000004400001010001`) + a 6-byte qualifier `00 00 47 05 2B 03`.
  - `0x40` = FCI / selection-result object (SEOS TLV: tag 0x40, len 0x2B=43, truncated
    to `03 00` because MTU=23 → 20-byte payload; full object needs 3 BLE frames).
  - `0xC0` = SELECT-AID response (payload = `00 A4 04 00 0A <10-byte AID>`).
    AID returned by the `0x40` poll = `A0 00 00 03 82 00 <NN> 00 01 01`, where
    `<NN>` is an incrementing nonce/counter (observed 0x2D → 0x2F, step 2).
  - `0xE1` = status. 2nd byte = OpeningStatus: 1=SUCCESS, 2=REJECTED,
    3=READER_ANTI_PASSBACK, 4/5/6=TIMED_OUT, 7=READER_FAILURE
    (from `mobilekeys/api/ble/b/u.java` + `OpeningStatus.java`).
    So `e1 05`/`e1 06` = TIMED_OUT, `e1 01` = SUCCESS, `e1 02` = REJECTED.
    These are **door-event / session status codes, NOT SEOS status words.**
- **Phone → reader commands observed:**
  - `0x40` (1 byte) = **poll / read** — the only command that reliably gets a
    data response. Each poll returns a SELECT-AID with the next nonce; after ~2
    polls the reader answers `e1 02` (REJECTED) then disconnects.
  - raw SEOS APDUs (`00 A4 ...`) and `0x81`+APDU SELECTs are answered
    `e1 05` (TIMED_OUT) — the reader does not treat them as expected commands.
- The reader is a **door reader** (HID MultiClass SE). It reports door-opening
  events (OpeningResult = status + OpeningType + payload) and gates config reads
  behind a challenge/response (the nonce in the SELECT-AID) + AKE.
- SEOS APDU INS still relevant for the in-session commands: SELECT_AID=0xA4,
  SELECT_ADF=0xA5, AUTHENTICATE=0x87, CORE_ADMIN=0x15, FS_OPS=0xE6, GET_DATA=0xCD,
  PUT_DATA=0xDD, GEN_KEYPAIR=0x47, REMOVE=0xED, RESPONSE=0xC0, AMR=0x41.
  CLA 0x00 (std) / 0x80 (proprietary).
- AKE key material = `SymmetricAuthenticationKeyset` (per `GetChallenge` /
  `PseudoRandomGetChallenge`); the challenge is verified with the auth keys + a
  counter (the nonce). Real keyset comes from the MobileKeys blobs / a paired phone.

**Implementation:** `ble/seos_ble.py` (bleak-based):
- `SeosBle` — connect, enable notify, request MTU, `exchange(apdu)` with 0x61xx
  continuation; high-level `select_applet / get_data / put_data / get_challenge /
  ake / core_admin / init_filesystem / clear_filesystem / open_session / configure`.
- `ble/discover.py` — GATT service/characteristic enumeration (used to confirm layout).
- CLI: `scan`, `open`, `select`, `getdata`, `putdata`, `challenge`, `ake`,
  `initfs`, `clearfs`, `configure`.

**Live verification (readers `C0:60:33:15:2B:31` and `D0:FA:1B:EA:15:8A`):**
- On connect the reader spontaneously emits 1–3 frames (varies by state):
  - `81 00 a4 04 00 10 a0 00 00 04 40 00 01 01 00 01 00 00 47 05` (auto-SELECT of SEOS applet)
  - `40 2b 03 00` (FCI, truncated by MTU)
  - `e1 06` / `e1 01` (status: TIMED_OUT / SUCCESS)
- Reader 2 (`D0:FA:...`) often just reports `e1 01` (SUCCESS) and is ready;
  Reader 1 (`C0:60:...`) reports `e1 06` (TIMED_OUT) and is flakier.
- Sending `0x40` (poll) → reader answers `c0 00 a4 04 00 0a a0 00 00 03 82 00 <NN> 00 01 01 00`
  (SELECT-AID with nonce `NN` = 0x2D, then 0x2F). Repeated polls → `e1 02` (REJECTED)
  then disconnect.
- Raw SEOS APDUs (SELECT AID 10B/16B, LIST ADFs, GET DATA, GET RESPONSE, AUTH)
  all answered `e1 05` (TIMED_OUT) or `e1 06` — the reader is not in a state to
  accept them without the poll/challenge sequence first.
- **Conclusion:** transport + framing confirmed. The reader gates config reads behind
  (a) the `0x40` poll/challenge (nonce) and (b) AKE using the
  `SymmetricAuthenticationKeyset`. Next: complete the challenge/response and AKE to
  reach an authenticated session, then LIST ADFs / GET DATA to dump config.

**Files:**
- `ble/seos_ble.py` — main client + CLI
- `ble/discover.py` — GATT discovery helper
- `ble/probe.py` — APDU probe (diagnostic)

---

## 9. UNBLOCKED: full .NET decompile (root cause of PE "malformation") — by second agent

### Root cause: the blobs are LZ4-compressed (XALZ), they were never decompressed
Section 4's "PE quirk" was not a malformed PE — the extracted blobs in `dotnet_asms/`
are still **LZ4-block-compressed**. The XALZ header is **12 bytes**, not 14:
`"XALZ"(4) + descriptor_index(u32) + uncompressed_size(u32)`, immediately followed by
an **LZ4 block stream**. The bytes read as a "u16 flag 0x03F2" are the first LZ4 token:
`0xF2` = literal-length 15 + continuation `0x03` = **18 literal bytes** = the MZ preamble
(`4D 5A 90 00 … B8 00`), after which LZ4 match tokens resume. That is exactly why the
first ~18 bytes looked like a valid PE and everything after was "garbage", and why the
`58 00 e2 e0 …` pattern was constant across all assemblies (it's the compressed form of
the identical PE preamble). No PE patching is needed.

### Fix (self-contained, no network needed for this part)
Re-parse the store and LZ4-decompress each blob with the known `uncompressed_size`:
```python
import struct, lz4.block
usize = struct.unpack_from('<I', blob, 8)[0]
pe = lz4.block.decompress(blob[12:], uncompressed_size=usize)   # valid PE, e_lfanew=0x80, "PE\0\0"
```
All 270 assemblies re-extracted correctly → `dotnet_asms_fixed/` (267 LZ4 + 3 stored raw).

### Full C# decompiles now available → `decompiled/`
All 12 core HidGlobal assemblies decompiled (~660k lines total):
- HidGlobal.ArtemisManager.cs (204k lines) — **reader config protocol, BLE module, FW upgrade**
- HidGlobal.ArtemisManager.Portable.cs (309k) — endpoint/SIS, GetChallengeAsync (server-side)
- HidGlobal.Asn1.Messaging.Artemis.cs (98k) — ASN.1 message model
- HidGlobal.cs, HidGlobal.Asn1.cs, HidGlobal.Asn1.ConfigurationItems.cs,
  HidGlobal.SDI.SnmpV3.cs, HidGlobal.Transport.cs, HidGlobal.Artemis.DeviceModel.cs,
  HidGlobal_AppSettings.cs, Plugin.SeosAdmin.Abstractions.cs, Plugin.SeosAdmin.Android.Binding.cs
- Code is obfuscated (junk switch/goto control flow, garbage namespaces like `GCwWOP3lDjCJf5cgseb`)
  but fully readable — string literals, byte constants, method/type names are intact.

### Tooling note (fixes the "blocked: malformed COFF header" line)
The 4 largest/most-sensitive assemblies (ArtemisManager, ArtemisManager.Portable,
Plugin.SeosAdmin.*) are **net10.0-android**; they crash ilspycmd 8.2 with
`System.Version … fieldCount` because 8.2 predates .NET 10. Fix = newer decompiler:
- ilspycmd **9.1.0.7988** (net8.0), fetched from nuget flat-container, run under the
  installed .NET 10 runtime with `DOTNET_ROLL_FORWARD=LatestMajor`. Handles v10.0 fine.
- Local copy: `/tmp/claude-1000/-home-craig-hid/d5951f41-1a02-4d55-b13f-e035da2c6129/scratchpad/ilspy91/tools/net8.0/any/ilspycmd.dll`
- The old 8.2 still works for the .NET Framework 4.8 assemblies (Asn1, SnmpV3, etc.).

## 10. BLE reader-config protocol — CONFIRMED + CORRECTED from decompiled source
`HidGlobal.ArtemisManager.BleModule.BleMessages` (decompiled/HidGlobal.ArtemisManager.cs
~line 200065) defines the real framing on the `0000aa00` characteristic. This corrects
the hand-reversed guesses in §8:

- Frame header nibble math: `EXTENSION_TYPE = 7` → `7<<5 = 0xE0`.
  - message types: END_OF_TRANSACTION=1, FW_UPDATE=2, BOOTLOADER_READY=3,
    END_OF_IMAGE=4, CONFIGURATION=5.
  - `0xE1` (the status frames observed live) = **End-Of-Transaction** (`0xE0|1`) + 1 status byte.
  - `0xE2` = FW_UPDATE fragment (`0xE0|2`); `0xE5` = **CONFIGURATION fragment** (`0xE0|5`).
- **EOT status byte (2nd byte of an `0xE1` frame)** — authoritative map (supersedes the
  OpeningStatus.java guess in §8):
  `1=SUCCESS, 2=SAM_REJECTED, 3=SAM_ANTIPASS_BACK_REJECTED, 4=CON_TIMEOUT,
   5=FRAGMENT_TIMEOUT, 6=MESSAGE_TIMEOUT, 7=LENGTH_ERROR, 8=DFU_ERROR,
   9=FLASH_ERROR, 10=CONFIG_FORBIDDEN_ERROR`.
  So the live `e1 06` = MESSAGE_TIMEOUT (not "TIMED_OUT"), `e1 02` = SAM_REJECTED.
- **Command frames (phone→reader):**
  - `REQUEST_GET_PROPERTIES  = 84 00`  (0x84)   ← use THIS to read reader properties
  - `REQUEST_GET_PROPERTIES2 = 8C 00`  (0x8C)
  - `REQUEST_INIT_FLASH      = 84 00`, ACK `84 82 00 00`
  - `GET_NEXT_AVAILABLE_ADDRESS = 85 00`
  - `BEGIN_UPGRADE = A1 00`, ACK `E1 00`
  - `FRAGMENT_CONFIGURE_MODE = E5`, `FRAGMENT_FW_UPDATE = E2`
- **Actionable:** the `0x40` poll used in §8 is the SEOS *opening* applet path, not the
  Reader-Manager config path. To talk config, drive `SendBleFragmentV2(...)`
  (decompiled/HidGlobal.ArtemisManager.cs ~line 42424 / 68740): send `84 00` /`8C 00`,
  read the reply, terminate on an `E1 xx` EOT. `EOT_SAM_REJECTED(2)` /
  `CONFIG_FORBIDDEN(10)` indicate config is gated behind SAM/authorization — the AKE /
  SAM auth still applies before config writes are accepted.

NOTE: an earlier draft of the "§8 Files" block in this file contained a prompt-
injection artifact (a fake `</think>`/`<system-reminder>`/`<bash>` block) picked up
from untrusted RE output during analysis. It was identified, never acted on, and
has since been removed from this document.

---

## 11. Config-pull feasibility + Python reimplementation (second agent)

**Question: pull full reader config over BLE without auth? → NO (for the real config).**
The reader config is an **SNMPv3 MIB** (enterprise 1.3.6.1.4.1.29240). Reading config
OIDs needs an SNMPv3 auth+priv key, and those keys are **not in the app** — they are
computed **server-side by HID Origo cloud** (SDS/SDI: UpdateCredential /
FetchELITEConfiguration / iCLASSKeyManagement / KeyRoll), released to an authed user
for their own org's readers. HID's USM is custom (auth=SMAC/SHA-1, priv=AES-128-CBC
MsCrypto padding), so stock SNMP won't interoperate.

Recovered by RUNNING the app (SDK harness): hardcoded **Genesis/factory SNMP
identities** (engineId+username, OID-encoded, NO keys) for OmnikeyReaderCoreHID/AA and
CredentialRoller; other families load the cloud `AppSettings.xml` (not shipped in APK).

**Only genuinely no-auth exchange = SNMPv3 discovery** → reader engineId/boots/time.
Also unauthenticated: BLE/GATT identity + the SEOS auto-select frames on connect.

**Full protocol stack (validated):**
BLE aa00 → Artemis frame `[u16 len BE][ISO7816 APDU][u16 CRC16]` (CRC-16/CCITT-Kermit
0x8408, byte-swapped) → APDU (GET_DATA 0xCA / PUT_DATA 0xDA) → DATA = BER `Payload`
(core/HF/LF cmds) OR SNMPv3 message (config MIB).

**Deliverables added:**
- `PROTOCOL.md` — full spec + supported card-technology list.
- `hid_rm/` — Python client: `crc16` (validated vs decompiled table), `framing`
  (validated round-trip), `artemis` (ground-truth core command bytes from the app's
  BinaryNotes encoder), `snmpv3` (discovery byte-identical to app; secured-path notes),
  `cli` (`show` / `scan` / `snmp-discover` / `send` / `decode-snmp`).
- Ground-truth via SDK harness: e.g. GetReaderInfo Payload = `a5039f2300`; SNMPv3
  discovery = `3037020103300d0201010202...3000`.

**Supported card technologies (from the app):** Seos; iCLASS Legacy/SE/SR + Picopass;
MIFARE Classic/Plus/Ultralight; DESFire EV1/EV2/EV3 (SIO + ProxCheck); FeliCa; CEPAS;
ISO14443A/B, ISO15693/NFC (HF). HID Prox, Indala, EM410x, AWID (LF). UHF. Interfaces:
Wiegand, OSDP, Clock&Data, MagStripe, BLE Mobile Access, NFC-HCE.

**Tooling:** .NET SDK 10 installed at
`/tmp/claude-1000/-home-craig-hid/d5951f41-1a02-4d55-b13f-e035da2c6129/scratchpad/dotnet-sdk`;
encoder harness at `.../scratchpad/enc` (Artemis) and `.../scratchpad/snmp` (SNMP identity/discovery).

---

## 12. Exhaustive sweep: manifest, native libs, all-assembly URL scan, DCID schema

Continuation pass covering the remaining open items (broad secret sweep, native
lib inventory, MobileKey blob structure, full manifest). New material below;
everything from §1-§11 stands except where noted.

### 12a. Broad secret sweep — negative result (validates earlier work)
Swept all of `jadx_out/sources` for AWS/Google/Slack/Stripe key formats, JWTs, PEM
private-key headers, and `*SECRET*/*API_KEY*/*TOKEN*="..."`-shaped assignments.
No new hardcoded secrets found — the only real hit is the already-documented
`ConstantsKt.CLIENT_SECRET = "DPFKaKQegG1MKFQJ"` (§2). No embedded `.p12/.jks/.pem/
.key/.keystore` files in the APK. This is a validating negative, not a gap.

### 12b. Native library inventory (arm64-v8a)
Full list: `liba7a2.so`, `libarc.bin.so`, `libassembly-store.so`, `libe_sqlite3.so`,
`libmono-component-marshal-ilgen.so`, `libmonodroid.so`, `libmonosgen-2.0.so`,
`libSystem.{Globalization,IO.Compression,IO.Ports,Native,Security.Cryptography.Native.Android}.so`,
`libxamarin-app.so`.

- `libarc.bin.so` — legitimate: a stub `.so` wrapping a `dotnet_for_android_data_payload`
  (the .NET-for-Android runtime feature-switch config), a known, documented packaging
  technique. Not a secret container.
- `liba7a2.so` (1.48 MB) — **inconclusive, flagged for anyone continuing this**.
  `file` reports a malformed ELF note and no section headers; byte entropy is 7.90
  bits/byte, above the 6.68 of the legitimate `libmonosgen-2.0.so` in the same APK
  (real compiled ARM64 code normally reads lower). **Correction/tempering**: an
  APK-wide entropy scan (§12f) shows 7.90 is NOT unusual in this specific app —
  ordinary compressed PNGs and BouncyCastle's post-quantum (Picnic/LowMC) constant
  tables in the very same APK sit at 7.98-8.0, higher than this file. So the entropy
  signal alone is weak evidence of anything hidden; it's equally consistent with
  `liba7a2.so` simply being a legitimately-compressed data resource rather than
  machine code. No `System.loadLibrary("a7a2")` call exists anywhere in the Java
  sources, and no `DllImport` references it. `libxamarin-app.so`'s string pool
  contains the literal `"liba7a2.so"`, but sitting in a generic pool of unrelated
  JNI/binding type names — consistent with a hash-named native stub from standard
  .NET-for-Android packaging (some assemblies get short hashed `.so` names).
  **Not resolved either way from static analysis alone** — the next step
  would be dynamic (does `dlopen("liba7a2.so")` ever get called; Frida would show
  it, or dumping process maps on a rooted test device) or a proper unstripped-ELF
  diff against a known-clean .NET-for-Android APK to see if this naming/entropy
  pattern is normal or unique to this app.

### 12c. MobileKey credential-store blobs — precise structure (refines §5)
Both `assets/com/assaabloy/mobilekeys/api/internal/{79974d41f9d592ea-,fc275f3f44b3c7a4b-}`
share an exact structure: a **22-byte plaintext ASCII tag `"java/lang/StringBuffer"`**
followed immediately by ciphertext at ~8.0 bits/byte entropy (13 KB and 539 KB
respectively). This refines the earlier "serialized StringBuffer" description — it's
a fixed type-discriminator header, not a real Java serialization stream (no `0xACED
0x0005` magic). The third blob (`assets/9b7a2e0f.../046b1e1d-...`, 11.3 KB) has **no**
header at all — pure ciphertext from byte 0, entropy 7.98. No decryption keys
available from the app (see AAMK.md) so contents remain opaque; documented here for
completeness.

### 12d. NEW: reader-configuration cloud API + full DCID/key-management schema
A full URL sweep across **all 270** assemblies (previous passes only covered the
HidGlobal ones; this needed UTF-16LE-aware `strings -e l`, since .NET string
literals are UTF-16 and a plain byte-grep silently finds nothing) turned up a
previously-undocumented endpoint in `HidGlobal.ArtemisManager.Portable.dll`:

```
https://configuration.device.api.origo.hidglobal.com/HID_Signo_Reader/v2.3/
```
used as the `SchemaVersion` of a **DCID (Device Configuration ID)** JSON template
the app builds when creating a new reader configuration. This is the cloud schema
that ultimately becomes the SNMP-OID config values gated behind auth (§3/§6 of
PROTOCOL.md) — reading the template class (`KeyGenerationConfiguration`) gives a
complete, precise map of HID's credential/key-management structure that wasn't
visible from the wire protocol alone:

```
KeyGenerationConfiguration.config.Features.Credentials.Media:
  hidApp                          Keyset=Standard
  hidMifare                       Keyset=Standard
  mifareMadPublic                 Keyset=Standard
  iclass                          Keyset=Elite      (+ICEReference)
  iclassLegacy                    Keyset=Elite      (+ICEReference)
  sio.desfire                     Keyset=Elite      (+ICEReference)
  sio.mifare                      Keyset=Elite      (+ICEReference)
  sio.secureObject.license        Keyset=Elite      (+ICEReference)
  sio.secureObject.privacy        Keyset=Elite      (+ICEReference)
  sio.secureObject.signature      Keyset=Elite      (+ICEReference)
  sio.seos            3 variants: Keyset=ECP (+EcpEliteReference),
                                   Keyset=Elite (+ICEReference),
                                   Keyset=EliteSoft (+ICEReference)
  sio.seosAdmin        2 variants: Keyset=Elite (+ICEReference), Keyset=EliteSoft (+ICEReference)
KeyGenerationConfiguration.config.DeviceAdmin.snmp   Keyset=Elite (+ICEReference)
metadata: DeviceType="HID_SIGNO_READER", Status="PUBLISHED"
```
**This directly confirms and closes the loop on §3/§6's central finding**: the
reader's SNMP admin/config keys (`DeviceAdmin.snmp`) are explicitly **Elite-tier**
keys, generated cloud-side and scoped by `ICEReference` (the customer/issuer
identifier — ties to the already-known `GetIceNumberAsync`/`CustomerReference`).
There are exactly **4 key-management tiers** in this app: `Standard`, `Elite`,
`EliteSoft`, and `ECP` (this last one keyed by a distinct `EcpEliteReference` rather
than `ICEReference` — likely a separate/adjacent program, not confirmed further).
No static path exists to obtain Elite/EliteSoft/ECP key material without calling
this cloud API as an authenticated, provisioned customer.

Also newly found in the same sweep: a 4th, previously undocumented analytics
region — `https://test-eventlogger-api.origo.hidglobal.cn` (alongside the
already-known dev/preprod/prod × US/CN endpoints in §2).

### 12e. AndroidManifest — full permissions + exported components
Decoded the raw AXML (`unpacked/AndroidManifest.xml`) with androguard — matches
`analysis_manifest_full.xml` already in the workdir (prior agent had already done
this; cross-verified). Permissions include the expected BLE/NFC/location set,
plus a few worth flagging: `READ_LOGS` (unusual for a 3rd-party app — restricted
on modern Android to system/signature apps, so likely a no-op unless the app is
a system app on some deployments), `ACCESS_MOCK_LOCATION`, `DETECT_SCREEN_CAPTURE`.

**Exported components:**
- `crc64bbf373d6810e19ef.InvitationCodeActivity` — exported, **no permission
  required**, with a **deep-link intent-filter**: `rdrmgr://invitationcode`
  (scheme `rdrmgr`, host `invitationcode`, category `BROWSABLE`). Any web page or
  other app on the device can launch this by opening that URL — this is how
  invitation-code links (email/SMS/QR) are handled. Not a vulnerability by itself
  (the security boundary is the invite code's server-side validity/expiry, not
  this launch path) but worth knowing: a malicious page could silently deep-link
  into this activity for UI-confusion/phishing purposes, and it's the concrete
  mechanism behind invite codes like the one provided for this research (redacted;
  a one-time enrollment code), still unused per the preference to stay unauthenticated.
- `com.assaabloy.mobilekeys.api.network.NfcTagNetworkReaderActivity` — exported,
  no permission, handles `NDEF_DISCOVERED` for scheme **`seosnetworkreader`**
  (resolved from resource `@7F1000BF`). Any NFC tag written with a
  `seosnetworkreader://...` NDEF record will offer to launch Reader Manager into
  its network-reader-connect flow — this is the tap-a-tag provisioning path for
  the "Network" reader transport mentioned in §4c.
- `crc646d3e20952b8e3b48.NFCService` and `com.assaabloy.mobilekeys.api.hce.HceService`
  are `exported=true` but require the system-only `android.permission.BIND_NFC_SERVICE`
  and are `enabled=false` by default — not a practical attack surface (only the
  platform NFC subsystem can bind to them, and they're off until NFC/HCE is
  actually enabled in-app).
- Everything else exported (`MainActivity`, `ProfileInstallReceiver`, Firebase Auth's
  `GenericIdpActivity`/`RecaptchaActivity`) is standard framework/SDK boilerplate,
  not app-specific.

### Net for this pass
No new hardcoded secrets, no smoking-gun in `liba7a2.so` (flagged, unresolved),
but a genuinely new and significant find: the **cloud DCID schema** that
definitively confirms the SNMP config keys are Elite-tier and cloud-issued (closing
the loop opened in PROTOCOL.md §3/§6), the two deep-link entry points, and a
corrected precise structure for the encrypted MobileKey blobs.

### 12f. APK-wide entropy scan (context for §12b's correction)
Ranked every file in the unpacked APK by byte-entropy to check for other disguised
containers (the way `libassembly-store.so`'s XABA trick would show up). Top results
are all explainable: PNG resources (~7.98-8.0, already DEFLATE-compressed by design),
`org/bouncycastle/pqc/crypto/picnic/lowmcL{1,3,5}.bin.properties` (7.99-8.0 — the
Picnic post-quantum signature scheme's precomputed LowMC cipher constant tables,
a legitimate BouncyCastle PQC resource, not a secret), `okhttp3/.../publicsuffixes.gz`
(a real gzip file), and the two MobileKey ciphertext blobs (§12c, expected to be
high-entropy since they're genuinely encrypted). `liba7a2.so` (7.90) sits *below*
several of these legitimate entries — no other hidden high-entropy container found.
