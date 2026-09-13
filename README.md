# HID Reader Manager — protocol research & tooling

Reverse-engineering of the **HID Reader Manager** Android app (v1.33.1,
`com.hidglobal.pacs.readermanager`) and its BLE/NFC protocol for talking to
HID Signo / iCLASS SE / MultiClass SE access-control readers, plus a from-scratch
Python + Flipper Zero reimplementation for **unauthenticated** protocol testing
against a reader you own.

**Scope and authorization.** All live testing here was done against a reader the
author owns, in a personal lab, with a stated preference throughout for staying
unauthenticated (no cloud credentials, no invitation codes used, no attempt to
authenticate as or clone a real access credential). This is defensive/protocol
research, not a tool for attacking access-control systems you don't own or
operate. See [PROTOCOL.md](PROTOCOL.md) §6 for the explicit finding that a full,
authenticated config read is **not** achievable from the app alone — the relevant
keys are cloud-issued per organisation.

## What's here

- **[`hid_rm/`](hid_rm/)** — Python package: BLE client for the reader's Artemis/
  SNMP/SEOS protocol (`framing.py`, `artemis.py`, `snmpv3.py`, `seos.py`,
  `crc16.py`), an unauthenticated "config leak" collector with a human-readable
  OID/AID decoder (`leak.py`, `oid.py`, `oid_db.py`), a card-emulation responder
  (`emulate.py`), a corrected robustness/fuzz harness (`fuzz.py`), a unified
  recon command (`recon.py`), and a Flipper Zero serial-CLI bridge
  (`flipper_cli.py`). Entry point: `python -m hid_rm.cli --help`.
- **[`flipper_app/`](flipper_app/)** — a from-scratch Flipper Zero application
  (`hid_recon.c`, built against Momentum firmware's `ufbt` SDK) implementing the
  same protocol logic as a real ISO14443-4A NFC card-emulation listener, so
  readers without BLE can be tested too. Plain-English on-device report; see
  `application.fam` for the build manifest.
- **[`ble/`](ble/)** — an earlier, lower-level BLE APDU client
  (`seos_ble.py`/`discover.py`/`probe.py`) used during initial protocol mapping.
- **[`PROTOCOL.md`](PROTOCOL.md)** — the full protocol writeup: BLE/NFC framing,
  the Artemis BER command set, the SNMPv3 config MIB, card-technology support
  matrix, the AAMK/SEOS findings, live test results (including cross-transport
  corroboration between the BLE and NFC implementations), and the Flipper Zero
  build notes.
- **[`AAMK.md`](AAMK.md)** — deep dive on the Assa Abloy Mobile Keys / SEOS
  crypto layer found via static analysis of the app (no dynamic
  instrumentation): the Genesis (factory-default) privacy key, the
  `KeyChangeGenerator` weak-RNG finding, and why neither yields a practical
  break of a real deployment.
- **[`MOBILE_KEYS.md`](MOBILE_KEYS.md)** — feasibility review of *using* or
  *removing* HID mobile keys: what they are (`KeyType` model, AAMK endpoint,
  SEOS admin key), how Reader Manager uses one to authenticate reader
  management, and why neither using nor removing them is reachable from this
  tooling (cloud-issued, device-bound, non-exportable). Includes what the
  unauthenticated discovery loop *can* still tell you about a reader's
  mobile-key posture.
- **[`FINDINGS.md`](FINDINGS.md)** — the raw research log: APK/manifest
  analysis, the `.NET` assembly store format (XABA/LZ4), hardcoded
  analytics/Firebase secrets found in the shipped app, and the full sequence of
  static-analysis findings that fed into `PROTOCOL.md`.
- **[`leak_reports/`](leak_reports/)** — example output from live runs against
  the author's own reader (both the Python/BLE and Flipper/NFC paths),
  demonstrating the unauthenticated config-disclosure finding.

## What this is *not*

The proprietary decompiled Java/.NET source extracted from the APK during this
research (jadx/ilspy output, extracted assemblies, the APK itself) is **not**
included here — it's HID Global's copyrighted code, kept locally only. This repo
contains original tooling and a written analysis of what was found in it, which
is the normal form for publishing this kind of research.

## Headline findings

- The reader's BLE/NFC channel only ever exposes an **unauthenticated
  credential-read/discovery loop** — connecting and replying with a plain
  ISO7816 success code is enough to enumerate which PACS credential objects
  (OIDs) and application/admin modes (AIDs) a specific reader is configured
  for. No keys, certificates, or invitation codes required. See `PROTOCOL.md`
  §6–§9 and `leak_reports/`.
- The actual reader **configuration/management plane (SNMP-based) is properly
  gated** behind cloud-issued, per-organisation keys (HID's "Elite"/"EliteSoft"
  key-management tiers) — confirmed by finding and reading the cloud
  provisioning schema in the decompiled app (§12 of `PROTOCOL.md`). This is not
  bypassable from the app or from passive protocol analysis alone.
- A from-scratch Flipper Zero NFC implementation of the same protocol logic
  independently reproduced the BLE-derived findings against the same physical
  reader — two unrelated code paths, two different radios, identical result.

## Disclosure

If you find something here that looks like it should be reported to HID Global,
look up their current PSIRT/security-disclosure contact on hidglobal.com rather
than relying on a link pasted here going stale.
