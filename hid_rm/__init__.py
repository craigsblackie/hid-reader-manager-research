"""hid_rm - a from-scratch Python client for HID Reader Manager readers.

Reverse-engineered from HID Reader Manager 1.33.1. Modules:
  crc16    - CRC-16/CCITT (Kermit) used by the frame checksum          [validated]
  framing  - Artemis BLE frame  [len][apdu][crc] + ISO7816 APDU        [validated]
  artemis  - BinaryNotes/BER `Payload` command bytes (core reads)      [ground-truth]
  snmpv3   - config-MIB SNMPv3 discovery (+ secured-path notes)        [validated]

Transport/GATT (HID Signo / MultiClass SE over BLE):
  service  00009800-0000-1000-8000-00177a000002
  data chr 0000aa00-0000-1000-8000-00177a000002  (write-no-response + notify)
"""
from . import crc16, framing, artemis, snmpv3   # noqa: F401

SERVICE_UUID = "00009800-0000-1000-8000-00177a000002"
DATA_CHAR_UUID = "0000aa00-0000-1000-8000-00177a000002"
