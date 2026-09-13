"""Robustness / crash test-case generator for HID Artemis readers -- CORRECTED.

Authorized robustness testing of YOUR OWN readers only.

CORRECTION (from live testing, see PROTOCOL.md §9): the original version of this
module generated malformed `[len][APDU][CRC]` Artemis/SNMP frames, but two things
proven live make that the wrong target for an unauthenticated attacker:
  1. Those frames must be split into `ProtocolV1Fragment`-headed BLE writes or the
     reader just reads the first byte as a bogus fragment header and answers
     `FRAG_TIMEOUT` without looking at the content at all (fixed here via
     framing.ble_fragment).
  2. Even correctly fragmented and well-formed, the reader IGNORES Artemis/SNMP
     GET_DATA content outright when not already in an authenticated session --
     proven by sending a byte-valid SNMP discovery frame and getting a plain
     restart-from-top, identical to sending garbage. So fuzzing the Artemis/BER/
     SNMP parsers via this path cannot reach that code from an unauthenticated
     connection on this firmware; a real attacker would need the SNMP/session
     layer already open (out of scope for an unauthenticated PoC) or a different
     reader/firmware that doesn't gate this the same way.

The layer that IS live and reachable unauthenticated is the ISO7816 credential-read
exchange itself -- the reader is the active party (PCD role) and parses OUR replies
(status words + optional FCI/response data) to its own SELECT commands. That is
the real crash surface for an unauthenticated BLE central, so these cases target
IT: malformed status words, malformed/oversized FCI TLVs, GET RESPONSE (0x61xx)
length-field abuse, and BLE-fragment-reassembly abuse (bad fragment count/order).

Run one case per fresh connection and watch for a disconnect (possible reboot), a
stall (no reply), or a device that stops advertising (BLE stack crash) --
`hid_rm.cli fuzz2 <MAC> [case]`.
"""
from . import framing, seos


def _frag(payload: bytes):
    """Correctly BLE-fragment a reply (unlike the old module, this always does)."""
    return framing.ble_fragment(payload)


def cases():
    """Yield (name, list_of_ble_fragments, note) -- each item is what to write,
    in order, on ONE fresh connection, replacing the normal '9000' reply."""

    # --- malformed ISO7816 status words (2nd/3rd byte of our reply) ---
    yield ("sw_truncated_1byte", _frag(b"\x90"), "1-byte reply, no SW2")
    yield ("sw_zero_len", _frag(b""), "zero-byte reply to a pending SELECT")
    yield ("sw_all_zero", _frag(b"\x00\x00"), "SW=0000 (undefined)")
    yield ("sw_all_ff", _frag(b"\xff\xff"), "SW=FFFF (undefined)")
    yield ("sw_61_max", _frag(bytes.fromhex("61ff")), "GET RESPONSE, claims 255 more bytes")
    yield ("sw_61_zero", _frag(bytes.fromhex("6100")), "GET RESPONSE, claims 0 more bytes")
    yield ("sw_6c_wronglen", _frag(bytes.fromhex("6c05")), "wrong-Le retry code")

    # --- malformed FCI/response data ahead of the SW (BER-TLV abuse) ---
    yield ("fci_len_overflow", _frag(bytes.fromhex("6fff") + b"\xaa" * 20 + bytes.fromhex("9000")),
           "FCI claims 255 bytes, only 20 present")
    yield ("fci_len_zero_tag", _frag(bytes.fromhex("6f00") + bytes.fromhex("9000")),
           "empty FCI template")
    yield ("fci_deep_nest", _frag(bytes([0x6F, 40]) + bytes([0x84, 38]) + b"\xaa" * 38 + bytes.fromhex("9000")),
           "84-tag (AID) longer than the template itself")
    yield ("fci_negative_len", _frag(bytes.fromhex("6f81ff") + b"\xaa" * 10 + bytes.fromhex("9000")),
           "long-form length byte (0x81) claims 255, only 10 present")
    yield ("fci_huge_single_write", _frag(bytes([0x6F, 0xFE]) + b"\xaa" * 250 + bytes.fromhex("9000")),
           "large (>MTU) FCI forcing many BLE fragments in one reply")

    # --- BLE ProtocolV1Fragment reassembly abuse (our own framing layer) ---
    yield ("frag_claims_more_never_sends", [bytes([0x80 | 5]) + b"\xaa" * 19],
           "INIT claims 5 more fragments, we only send 1 (reader waits/times out)")
    yield ("frag_final_only_no_init", [bytes([0x40]) + b"\xaa" * 10],
           "a bare FINAL with no preceding INIT")
    yield ("frag_intermediate_only", [bytes([0x05]) + b"\xaa" * 19],
           "a bare intermediate(rem=5) fragment with no INIT")
    yield ("frag_double_init", [bytes([0x80 | 1]) + b"\xaa" * 19, bytes([0x80 | 1]) + b"\xbb" * 19,
                                 bytes([0x40]) + b"\x90\x00"],
           "two INIT fragments back-to-back before FINAL")
    yield ("frag_zero_len", [bytes([0xC0])], "SINGLE fragment with zero payload bytes")

    # --- reconnect-storm style (availability, not parser) ---
    yield ("reply_then_immediate_disconnect", _frag(bytes.fromhex("9000")),
           "normal reply, but caller should disconnect() within <50ms of writing")
