import asyncio
import sys
from bleak import BleakClient, BleakScanner

TARGET = sys.argv[1] if len(sys.argv) > 1 else "Seos"


async def main():
    print(f"Scanning for '{TARGET}' ...")
    found = await BleakScanner.find_device_by_name(TARGET, timeout=12)
    if not found:
        found = await BleakScanner.find_device_by_address(TARGET, timeout=12)
    if not found:
        print("Not found by name; scanning all for 12s and printing names")

        def cb(_, ad):
            print("  candidate:", ad.address, ad.local_name, ad.rssi)

        await BleakScanner.with_callback(cb, timeout=12)
        return
    print("Found:", found.address, getattr(found, "name", None))
    print(f"Connecting to {found.address} ...")
    async with BleakClient(found.address, timeout=30) as client:
        print("Connected:", client.is_connected)
        print("MTU:", client.mtu_size)
        for svc in client.services:
            if svc is None:
                continue
            print(f"\n  SERVICE {svc.uuid}")
            for ch in svc.characteristics:
                if ch is None:
                    continue
                props = ",".join(ch.properties)
                print(f"    CHAR {ch.uuid}  [{props}]")
                for d in ch.descriptors:
                    print(f"        DESC {d.uuid}  [{getattr(d, 'properties', [])}]")


asyncio.run(main())
