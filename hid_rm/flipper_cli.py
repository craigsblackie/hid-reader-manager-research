"""Serial-CLI transport for a Flipper Zero (tested against Momentum firmware
mntm-012, connected at /dev/ttyACM1).

Ground truth from live probing of the actual connected device (not assumed):

  nfc apdu -p {4a,4b,15} -d "<bytes>"   -- Flipper as READER: sends an APDU to
                                           a card already in its field. Requires
                                           a target card, not useful against our
                                           access-control reader (which is itself
                                           a reader/PCD, not a card).
  nfc scanner                            -- Flipper as READER: passive scan for
                                           any ISO14443/15693 target in the field.
                                           LIVE-TESTED against the physical HID
                                           reader: "Protocols detected:" (empty) --
                                           the reader does not respond to being
                                           polled as a passive NFC tag.
  nfc emulate -f <path>                  -- emulate a STATIC previously-saved
                                           .nfc dump. No dynamic/scripted response
                                           logic -- cannot run our Artemis/SEOS
                                           protocol responder (leak.py/emulate.py)
                                           through this primitive.
  nfc field / nfc raw / nfc dump         -- also reader-mode / one-shot capture.
  bt hci_info                            -- the ONLY bt CLI subcommand found; no
                                           general BLE GATT-central scripting
                                           surface exists over this CLI.

CONCLUSION (see PROTOCOL.md "Flipper Zero integration" section): the reader only
ever acts as an NFC/BLE *initiator* (PCD / GATT central-is-not-needed-it's-the-
peripheral-driving-things). To talk to it over NFC the far side must emulate a
card *dynamically* (react differently depending on what the reader sends, exactly
like hid_rm.emulate's BLE responder) -- Momentum's stock CLI does not expose that;
it needs either the already-installed community apps (seos.fap / seader.fap,
operated by hand on the device) or a custom C FAP using the NFC HAL's ISO14443-4
listener API. Neither is a serial-CLI scripting task, so this module focuses on
what the CLI genuinely offers: device info, storage browsing (e.g. reading back
result files that seader/seos.fap produce), and reader-mode NFC probing (useful
against other targets, and to keep re-confirming the "not a tag" result above).
"""
import time

DEFAULT_PORT = "/dev/ttyACM1"
BAUD = 115200


class FlipperCLI:
    def __init__(self, port=DEFAULT_PORT, baud=BAUD, timeout=1.0):
        import serial
        self.ser = serial.Serial(port, baud, timeout=timeout)
        time.sleep(0.3)
        self.ser.read(self.ser.in_waiting or 1)  # discard any startup banner leftovers
        self.in_subshell = None

    def close(self):
        try:
            if self.in_subshell:
                self.abort()
                self.run("exit")
        except Exception:
            pass
        self.ser.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def run(self, command: str, wait: float = 0.6) -> str:
        """Send one line, return decoded output. Does not handle interactive
        (Ctrl+C-terminated) commands -- use run_interactive for those."""
        self.ser.write((command + "\r\n").encode())
        time.sleep(wait)
        return self.ser.read(self.ser.in_waiting or 8192).decode(errors="replace")

    def run_interactive(self, command: str, settle: float = 2.0) -> str:
        """For commands that enter a Ctrl+C-terminated mode (scanner/field/raw):
        run it, wait `settle` seconds, then abort and return whatever it printed."""
        self.ser.write((command + "\r\n").encode())
        time.sleep(settle)
        out = self.ser.read(self.ser.in_waiting or 8192).decode(errors="replace")
        out += self.abort()
        return out

    def abort(self) -> str:
        self.ser.write(b"\x03")
        time.sleep(0.4)
        return self.ser.read(self.ser.in_waiting or 4096).decode(errors="replace")

    def enter_nfc(self):
        self.run("nfc", 0.5)
        self.in_subshell = "nfc"

    def exit_subshell(self):
        self.run("exit", 0.3)
        self.in_subshell = None

    # --- convenience wrappers -------------------------------------------------
    def device_info(self) -> str:
        return self.run("device_info", 1.0)

    def nfc_scanner(self, settle=3.0) -> str:
        """Passive reader-mode scan. Against our access-control reader this
        returns 'Protocols detected: ' (empty) -- live-verified; the reader
        doesn't answer as a passive tag. Useful against other/unknown targets."""
        self.enter_nfc()
        out = self.run_interactive("scanner", settle)
        self.exit_subshell()
        return out

    def storage_list(self, path: str) -> list:
        out = self.run(f"storage list {path}", 1.0)
        entries = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("[F]") or line.startswith("[D]"):
                kind, rest = line[1], line[4:]
                if kind == "F" and " " in rest:
                    name, size = rest.rsplit(" ", 1)
                    entries.append({"type": "file", "name": name, "size": size})
                else:
                    entries.append({"type": "dir", "name": rest})
        return entries

    def storage_read(self, path: str) -> bytes:
        """Read a file's raw bytes off the Flipper's storage over the CLI.
        NOTE: only use this on files you have a clear reason and permission to
        read -- e.g. NOT on other people's captured `.credential`/`.picopass`
        files without being asked (see flipper_cli.py module docstring)."""
        out = self.run(f"storage read {path}", 1.0)
        return out.encode()


def probe_capabilities(port=DEFAULT_PORT) -> dict:
    """One-shot capability report: what this specific Flipper/firmware exposes,
    confirmed live rather than assumed. Safe to call repeatedly."""
    with FlipperCLI(port) as f:
        info = f.device_info()
        fw_line = next((l for l in info.splitlines() if "firmware" in l.lower()
                         or "version" in l.lower()), "")
        top_help = f.run("help", 0.6)
        bt_help = f.run("bt", 0.5)
        return {
            "port": port,
            "device_info_excerpt": fw_line.strip(),
            "top_level_commands": top_help,
            "bt_subcommands": bt_help,
            "nfc_present": "nfc" in top_help,
        }
