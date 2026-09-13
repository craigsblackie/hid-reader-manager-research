# AAMK / SEOS deep dive (static, no Frida) + KeyChangeGenerator analysis

Method: `classes*.dex` → `dex2jar` → `javap -c` (bytecode disassembly, nothing executed)
plus jadx cross-reference. This bypasses the control-flow obfuscation for the parts
that matter (constructors, key setup) because their bytecode is not obfuscated.

## 1. Genesis (factory-default) SEOS PRIVACY key = 16 zero bytes  ✅ CONFIRMED

`GenesisPrivacyKeyset$GenesisSymmetricKey.<init>` bytecode:
```
getstatic EncryptionAlgorithm.AES_128
aload_1; invokevirtual EncryptionAlgorithm.blockSize()   // = 16
newarray byte                                            // new byte[16]  (zeros)
invokespecial SymmetricKeyBc.<init>(EncryptionAlgorithm,[B)  // super(AES_128, zeros)
```
So the Genesis privacy key is **AES-128, all zeros, no diversification**. Its
`encrypt()` returns `byte[0]` and `cmac()` returns null → **Genesis "privacy" is
effectively plaintext**: a factory / un-provisioned reader has no transport-privacy
protection on its SEOS applet. (In `hid_rm.seos.GENESIS_PRIVACY_KEY`.)

Impact: with the zero key you can SELECT the reader's SEOS GDF and read
`AlgorithmInfo` / object metadata **with no cloud auth**. APDUs (from
`SeosApduFactory`, now in `hid_rm.seos`):
```
select SEOS AID   : 00 A4 04 00 0A A0000004400001010001
select GDF        : 80 A5 07 00
read all metadata : 80 15 01 00 06 00        (INS_CORE_ADMINISTRATION)
get challenge      : 00 87 00 <keyref> <data> (starts AKE)
```

## 2. What the zero key does NOT get you

- **SEOS ADF data** needs an AUTHENTICATION keyset. Both the symmetric master keyset
  (`PlainMasterAuthenticationKeyset.globalMaster(keyNumber, keyBytes, oid, div)` →
  `SeosMasterKeyDeriver.deriveFromMasterKey`) and the asymmetric keyset
  (`GenesisAsymmetricAuthenticationKeyset(keyNumber, EccPrivateKey, …)`) take the key
  material as **constructor arguments** — it is NOT hardcoded in the app; it is
  provided by the credential/cloud provisioning. (`$$a`/`EMPTY_OID_AND_DIVERSIFIER`
  constants are obfuscation salts, not keys.)
- **Reader configuration** is a separate SNMPv3-gated MIB whose auth/priv keys are
  cloud-held (see PROTOCOL.md §3/§6). The SEOS zero key does not unlock it.

Net: the zero privacy key is a real unauthenticated *SEOS-transport / identity* read
on factory readers, but it is not a path to the config MIB.

## 3. KeyChangeGenerator weakness — what it does and does not reveal

`KeyChangeGenerator` (HidGlobal.SDI.SnmpV3) builds the SNMPv3 USM key-change SET that
re-keys a reader (Genesis → customer). Two non-CSPRNG uses of
`new Random(DateTime.Now.Millisecond)` (seed 0–999, ≤1000 states):

1. **Default ctor** — generates the NEW `authKey` and `privKey` (16 bytes each) from
   the weak RNG. ⇒ only **1000 possible (authKey,privKey) pairs**.
2. **`R51JiMmuC`** (the keyChange value builder, used in `GenerateMessage`) — the
   16-byte keyChange nonce is also from the weak RNG.

keyChange construction (recovered):
```
keyChange = random ‖ ( newKey ⊕ CMAC_oldKey( context ‖ random ) )   // OMAC/CMAC-AES
```

Exploitability:
- The default ctor is **not called anywhere in the shipped app** (key-change is done
  server-side), so the app does not itself emit weak reader keys.
- The keyChange SET is sent `Reportable|Priv|Auth`, i.e. encrypted+authed with the
  CURRENT (old) session keys, so you cannot read a keyChange plaintext unless you
  already hold `oldKey` (the Genesis SNMP key).
- ⇒ As shipped, this is a **latent** weakness, not a live break. It becomes real only
  IF some HID tool/older build actually used the default ctor to key readers — in
  which case a reader's SNMP `authKey`/`privKey` is one of just 1000 values.

Concrete artifact: `hid_rm/keychange_candidates.csv` — all 1000 `(seed,authKey,privKey)`
pairs, generated with the real .NET seeded `Random` (its legacy algorithm is stable
across Mono/.NET, so these match the app). If you want to rule this in/out on YOUR
readers, an SNMPv3 auth attempt against each of the 1000 pairs (1000 tries) is a
bounded test — success would be a serious finding; failure rules the theory out.
(That the SEOS/USM auth here uses SMAC/CMAC over the key means each try is one MAC.)

## 4. Bottom line on getting past the auth-gated MIB, unauthenticated

- Recovered for free: SEOS Genesis privacy key (zeros) → factory-reader SEOS identity
  reads; SNMP discovery; pre-auth Artemis device/capability reads.
- Still walled: the config MIB (SNMPv3 keys are cloud-held) and SEOS ADF data
  (auth keyset is cloud/credential-provided). Neither key set is in the APK.
- Real remaining break paths (owned-hardware research): (a) test the 1000 weak-RNG
  candidate keys against your readers; (b) a firmware crash that fails open (fuzzer);
  (c) recovering a reader's provisioned keys from the cloud with your own account.

## 5. Live test of the 1000 candidates (reader C0:60:33:15:2B:31)

Ran against the reader in range. Result: **the candidate keys could not be tested,
blocked at the SEOS/session layer, NOT the crypto.** Details:

1. **BLE fragmentation solved** (ProtocolV1Fragment). Raw frame writes get `e1 05`
   FRAG_TIMEOUT; with the 1-byte fragment header (`0xC0` single / `0x80|n` / `0x40`)
   the reader accepts writes and responds. (Now in `hid_rm.framing.ble_fragment`.)
2. Over BLE the reader acts as the **terminal running the credential-read (door-open)
   flow**, treating the phone as a card:
   - spontaneous: `81..` SELECT SEOS AID + `40..` FCI
   - on our `9000`: it sends `80 A5 04 00 66 ...` = **SELECT ADF** with a list of
     credential ADF OIDs, and `00 A4 04 00 0A A0000003820<nonce>00 01 01` with an
     **incrementing nonce** (challenge).
   - it never exposes the SNMP management plane to an unauthenticated peer.
3. To reach SNMP (where the candidate keys apply) the phone must first complete the
   reader's SEOS **admin** authentication (provisioned MobileKey / AKE keys — cloud).
   So the SNMP config plane is upstream-gated; the 1000 candidate SNMP keys are
   **unreachable** without admin credentials. The weak-RNG theory can't be exercised
   from an unauthenticated position, and (as established) the default ctor isn't used
   by the app anyway.

Unauthenticated intel obtained for free during the attempt — the reader's configured
credential **ADF OIDs** (what it is provisioned to read), decoded from its SELECT ADF:
```
1.3.6.1.4.1.29240.1.1.2.1.24.1.6.1.1.10664
1.3.6.1.4.1.29240.1.1.2.1.24.1.1.11571.2
1.3.6.1.4.1.29240.1.1.2.1.24.1.1.11571.7
1.3.6.1.4.1.29240.1.1.2.1.24.1.1.163.11433.2
1.3.6.1.4.1.29240.1.1.2.1.24.1.1.2.2
```
(PEN 29240 = HID Global; 1.1.2.1.24 = PACS/SEOS application subtree.)

Net: to test the candidates you would need to reach SNMP, which needs admin creds;
the honest conclusion is the theory is untestable unauthenticated and the app never
uses the weak generator, so it does not reveal usable keys for these readers.

## 6. CORRECTION: the "incrementing nonce" was misread — it's a fixed AID discovery list

Live testing (implementing a proper card-emulation responder, `hid_rm.emulate`)
revealed that the earlier interpretation (§8 of FINDINGS.md, "AID returned by the
0x40 poll ... incrementing nonce/counter") is **wrong**. Those values are not a
nonce — they are **real, fixed, hardcoded AIDs** from `HidGlobal.ArtemisManager
Constants.AID` (decompiled) that the reader tries in a fixed discovery sequence on
every connection, interleaved with SEOS credential-ADF candidates:

```
a000000382002d000101 = MOBILE_SEOS_ADMIN_CARD   (2D=45)
a000000382002f000101 = OPERATION_SELECTOR       (2F=47)
```
(full table: SAM_UPDATER=28, BLE_CORE_UPDATER=29, NFC_CORE_UPDATER=21,
NFC_OEM_CORE_UPDATER=25, DOTNETAPP_ADMIN=2B, PASSTHROUGH=2C,
MOBILE_SEOS_ADMIN_CARD=2D, OPERATION_SELECTOR=2F,
OPERATION_SELECTOR_POST_RESET=31, LEGACY_PASSTHROUGH=30 — see `hid_rm/emulate.py`)

The app's own `ReaderStateAnalyzer.AnalyseAID()` classifies these into `ReaderState`
(`MobileSeosAdminCardAuthentication`, `NfcCoreBootloadMode`, `BleUartPassThrough`,
`StandardSeosAuthentication`, etc.) — i.e. **this AID IS the reader's mode signal**,
confirming there is a real "admin mode" concept, and that
`MOBILE_SEOS_ADMIN_CARD`/`OPERATION_SELECTOR` are its gateways.

### Live protocol behaviour (reader C0:60:33:15:2B:31, your desk unit)

Captured a full transaction by building a proper ISO7816 card-emulation responder
(reply with a status word to whatever the reader sends) plus the correct BLE
fragmentation (`ProtocolV1Fragment`, `0xC0`/`0x80|n`/`0x40` headers — without this
every write reads as a bad fragment count and gets `e1 05 FRAG_TIMEOUT`):

```
reader -> SELECT ADF (5 credential OIDs offered)
us     -> 9000
reader -> SELECT AID = MOBILE_SEOS_ADMIN_CARD
us     -> 9000
reader -> SELECT ADF (2 OIDs, down-selected)
us     -> 9000
reader -> SELECT AID = OPERATION_SELECTOR
us     -> 9000
reader -> EOT status=SAM_REJECTED (0x02)
```

Findings from this:
- **Only one GATT service/characteristic exists** (`00009800`/`0000aa00`) — config,
  firmware, and credential-read all multiplex over it via the `EXTENSION_TYPE`
  header; there is no separate "management" channel to find.
- **The reader always drives the exchange** (it is the ISO7816 terminal/PCD role);
  the connected BLE central only supplies status words (+ optional FCI data). It is
  never waiting for us to send it an Artemis/SNMP command — our writes are only ever
  interpreted as replies to its own SELECT.
- **The status word matters**: `9000` advances to the next discovery candidate;
  `6A82` (file/app not found) makes it restart from the top (re-SELECT
  STANDARD_SEOS); `61FF` (more data available) correctly triggers a `GET RESPONSE`
  (`00 C0 00 00 FF`) — the reader implements real ISO7816 response chaining.
- **Claiming the admin AID (SW=9000, even with a plausible echoed FCI) did not
  shift the reader into a command-accepting mode** — it continued down its fixed
  candidate list and rejected. Whatever actually flips a reader into
  `MobileSeosAdminCardOperation` (a physical admin-card tap, a cert-backed AKE, or
  internal firmware state) was not reproduced from a passive BLE central alone.
- **Rate limiting observed**: after several rapid connect/reply/disconnect cycles,
  the reader started responding with an immediate EOT (`MSG_TIMEOUT`/`SAM_REJECTED`)
  without offering the discovery sequence at all — consistent with an
  anti-passback/cooldown guard. Space out live tests (`hid_rm.cli emulate <MAC>
  <cooldown_sec>`).
- **Unauthenticated intel leak, reconfirmed**: the SELECT ADF candidate lists reveal
  the reader's configured PACS credential OIDs (§ "Live test" above) to anyone who
  simply connects and replies 9000 — no authentication needed to learn *what
  credential profiles a reader is configured to accept*.

### Open item for further research
To reach `MobileSeosAdminCardOperation` for real, the next static lead is
`SeosApduFactory`/`SessionImpl.authenticate()` — after SELECT AID succeeds, a real
admin session issues `GET CHALLENGE` (`00 87 00 <keyref>`) and mutual authentication
using an authentication keyset. Try completing that handshake (not just SW=9000) to
see whether the reader then offers `CORE_ADMINISTRATION` — this needs either the
Genesis symmetric/asymmetric auth keys (not found hardcoded — see §2) or a captured
real admin-card exchange to compare against.

### Note on retesting cadence
A retest 30s after the last capture still got an immediate `MSG_TIMEOUT` with no
discovery sequence at all (not even the usual SELECT ADF offers) — the cooldown/
backoff persisted longer than 30s, or accumulated from the number of connects this
session. Recommend power-cycling the reader (or waiting a few minutes) before your
next `hid_rm.cli emulate` run, and spacing subsequent attempts out — repeated rapid
reconnects are themselves worth noting as a low-effort availability lever (see
PROTOCOL.md §7 fuzzing) but shouldn't be run against your own hardware more than
needed to characterise it.
