# Mobile keys — using and removing them (feasibility review)

Research note answering: *can this tooling use, or remove, HID "mobile keys",
and what would that take?* Grounded in the decompiled HID Reader Manager app
(`HidGlobal.ArtemisManager`, `Plugin.SeosAdmin.*`) and the live protocol
behaviour documented in [PROTOCOL.md](PROTOCOL.md) / [AAMK.md](AAMK.md). No
invitation code was spent and no mobile key was enrolled to produce this — it is
a static + protocol analysis.

## 1. What "mobile keys" actually are here

The app models every credential/key the reader deals with as a
`KeyListConfiguration.KeyType` (from `HidGlobal.ArtemisManager`):

```
ReaderAdmin, MobileAdmin, MobileAccess, Seos, IClass, IClassSE, IClassSR,
MifareDesfireEV3, MifareDesfireEV1, GoogleWallet, AppleWallet, SamsungWallet
```

"Mobile keys" spans several of these, and they are two different things that are
easy to conflate:

- **Mobile *access* credential** (`MobileAccess`, plus the wallet types
  `GoogleWallet`/`AppleWallet`/`SamsungWallet`) — the phone acting as a **badge**
  to open a door. This is a HID Mobile Access / Assa Abloy Mobile Keys (AAMK)
  credential (a SEOS "endpoint" provisioned onto the phone's secure element).
- **Mobile *admin* credential** (`MobileAdmin`, and the reader-side
  `MobileSeosAdminCard*` states) — the phone acting as the **admin card** that
  authenticates *reader management*. This is the one that matters for "getting
  past the auth gate": it's what lets Reader Manager write configuration.

Both are delivered through the same AAMK plumbing (`Plugin.SeosAdmin`), whose
public surface is:

```csharp
interface IMobileKeysApi {
    bool IsPersonalized();
    EndpointInfo GetEndpointInfo();
    Task<bool> InitializeAsync();
    Task<bool> SecureEndpointAsync(string inviteCode);   // <-- enrolment
    Task<bool> UpdateEndpointAsync();                      // sync with cloud
    byte[]     ProcessCommand(byte[] command);            // SEOS crypto session
    void       CloseSeosCryptoSession();
    List<SeosAdminKeyInfo> ListKeys();                    // the issued admin keys
}
interface ISeosSecureElement { bool IsAuthenticated; byte[] Dispatch(byte[] cmd, out bool); ... }
```

## 2. How the app *uses* a mobile key (the flow)

1. The user enters an **invitation code** (the `BNQ3-…`-style code). The app
   calls `IMobileKeysApi.SecureEndpointAsync(inviteCode)`
   (`InvitationCodeViewModel`), which contacts the AAMK/Origo cloud and
   **provisions a SEOS credential ("endpoint") into the phone's secure element**.
   This is one-time: the code is consumed on redemption.
2. `IsPersonalized()` becomes true; `ListKeys()` returns the issued
   `SeosAdminKeyInfo` entries (each has `Type`, `Oid`, `Issuer`, `ExternalId`,
   `IsActivated`).
3. When managing a reader, the reader drives a **SEOS mutual authentication
   (AKE)**. The reader's discovery loop selects the mobile SEOS admin AID; the
   app answers via `ISeosSecureElement.Dispatch()` / `ProcessCommand()`, which
   run the SEOS crypto **inside the AAMK secure element** using the provisioned
   admin key.
4. Once that SEOS AKE succeeds, the reader unlocks its **authenticated
   management plane** — the SNMPv3 config MIB — and the app can then
   `ReadConfigurationItemsAsync` / `WriteConfigurationItemsAsync` /
   `WriteDCIDConfigurationItemsAsync` / `WriteKeyRollingSNMPMessageAsync`, i.e.
   read and change the reader's full configuration (see PROTOCOL.md §12 and the
   ArtemisManager operation list in §21 below).

So: **the mobile (admin) key is the credential that authenticates reader
management.** Everything gated in PROTOCOL.md §9 is gated behind this.

## 3. Can *this* tooling USE a mobile key? — No (and why)

Using a mobile key to reach the authenticated plane from `hid_rm`/the Flipper is
**not feasible**, for reasons that are structural, not incidental:

- **The key is cloud-provisioned and device-bound.** `SecureEndpointAsync`
  mints the SEOS admin key server-side (Origo) and stores it in the phone's
  hardware secure element / keystore. It is issued *to a specific enrolled
  device*, not handed to the app as bytes.
- **The key material is non-exportable.** All SEOS crypto happens *inside* the
  AAMK secure element via `ProcessCommand`/`Dispatch`. The app itself never sees
  the key; there is nothing for us to read out and replay. (This is the same
  wall AAMK.md §7 hit from the AKE side.)
- **The AAMK SDK is Android-only and attested.** It refuses debug/rooted/
  emulator environments (`DebugSdkDetectedError`, `DeviceEligibilityException`,
  `DeviceEligibility` seen in the binding) — so we can't host it under
  instrumentation to borrow its crypto session either.
- **Enrolment consumes the invitation code.** Redeeming `SecureEndpointAsync`
  spends the one-time code — the thing the engagement has deliberately avoided.

The **only** way to "use" a mobile key is to run the genuine app (or the AAMK
SDK) on an eligible stock Android device and redeem the code — which is simply
*being* Reader Manager, with a real cloud-issued credential. That would work (it
is the designed path), but it is neither unauthenticated nor reproducible from
our tooling, and it burns the code. Net: **the authenticated management plane
stays out of reach for `hid_rm`/Flipper**, consistent with PROTOCOL.md §6 and
AAMK.md §4.

## 4. Can this tooling REMOVE mobile keys? — Two senses, both gated

"Removing mobile keys" can mean two different operations:

**(a) Un-enrol the credential from the phone.** AAMK exposes endpoint
termination/`unregister` (SDK-side); it just de-provisions *that phone*. It
touches no reader, needs the app + cloud, and is irrelevant to our tooling.

**(b) Remove mobile-access configuration from a *reader*** — i.e. deconfigure
the reader so it no longer accepts mobile credentials (delete the
`MobileAccess`/SEOS keyset or ADF from the reader). This is a **configuration
write** (`WriteConfigurationItemsAsync` / key-rolling against the SNMP MIB), and
it is behind the exact same SEOS-admin authentication as everything else. So it
is **not reachable unauthenticated**, and not reachable from our tooling at all
(§3). It also *requires the admin mobile key to remove the access mobile key* —
you must authenticate as admin before you can strip anything.

**Safety note.** Removing/rolling a reader's mobile-access keyset is a
destructive, availability-affecting change (it can lock out every mobile
credential that reader trusts, and key-rolling is meant to be coordinated with
the org's key-management tier). Even with a valid admin key, this is not
something to do to any reader you don't own and operate — flagged here so the
capability is never treated as casual.

## 5. What we *can* determine about mobile keys unauthenticated

The reader's unauthenticated discovery loop (PROTOCOL.md §6–§9,
`hid_rm leak`/`enumerate`) is still informative about mobile-key *posture*,
without any credential:

- The reader **selects the SEOS PACS ADF** and offers its configured PACS
  credential OIDs → the reader is provisioned for **SEOS / mobile-style PACS
  credentials** (as opposed to a bare legacy-only reader).
- The reader cycles the **`MobileSeosAdminCard*` admin AIDs**
  (`a000000382002d…` = `MOBILE_SEOS_ADMIN_CARD`, plus the operation-selector
  AIDs) → the reader is **configured to be managed by a mobile admin card**,
  i.e. it *expects* a mobile key for administration.
- A **HID credential-family AID** (`A0000006 76…`, seen live as
  `A00000067660091E052B03`) is probed during discovery. RID `A0000006 76` is a
  HID application family (distinct from `STANDARD_SEOS` = `A0000004 40…`); this
  is the reader looking for a HID mobile/SEOS *access* credential. (No public
  RID-registry match was found for the full AID; identified here by family, not
  confirmed against a registry.)

So unauthenticated we can honestly answer *"is this reader set up to use mobile
keys (for access and for admin)?"* — yes/no from the discovery loop — even
though we cannot enumerate the full key list or change anything. That capability
is wired into the technology report in §6.

## 6. Tooling: report it like Reader Manager does

`hid_rm/technology.py` maps what the discovery loop observes onto Reader
Manager's own `KeyType` technology names and prints a "credential technologies"
summary (confirmed-from-discovery vs. requires-authenticated-read), so the
Linux tool answers the original question — *what card technologies is this
reader configured for* — in the app's own vocabulary. See §21 in PROTOCOL.md for
the full Reader-Manager-vs-tooling operation parity table.
