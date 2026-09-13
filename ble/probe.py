import asyncio
from seos_ble import SeosBle, build_apdu, CLA_STD, CLA_PROP, INS_SELECT_AID, INS_SELECT_ADF, INS_GET_DATA, INS_FS_OPS, INS_CORE_ADMINISTRATION, SEOS_AID, FILE_SYSTEM_AID, _sw_name

ADDR="C0:60:33:15:2B:31"
async def probe(s, label, apdu):
    try:
        data, sw = await s.exchange(apdu)
        print(f"[{label}] {apdu.hex(' ')} -> SW={sw:04X} data={data.hex(' ')}")
    except Exception as e:
        print(f"[{label}] {apdu.hex(' ')} -> EXC {e}")

async def main():
    async with SeosBle(ADDR) as s:
        print("MTU", s._client.mtu_size if s._client else "?")
        await probe(s,"sel SEOS AID P1=04",   build_apdu(CLA_STD, INS_SELECT_AID, 0x04, 0x00, SEOS_AID, 0x00))
        await probe(s,"sel FS AID  P1=04",    build_apdu(CLA_STD, INS_SELECT_AID, 0x04, 0x00, FILE_SYSTEM_AID, 0x00))
        await probe(s,"sel MF      P1=00",    build_apdu(CLA_STD, INS_SELECT_AID, 0x00, 0x00, b"", 0x00))
        await probe(s,"getdata tag06",        build_apdu(CLA_STD, INS_GET_DATA, 0x3F, 0xFF, b"\x06"))
        await probe(s,"getdata tag00",        build_apdu(CLA_STD, INS_GET_DATA, 0x3F, 0xFF, b"\x00"))
        await probe(s,"coreadmin 80 15 03 00",build_apdu(CLA_PROP, INS_CORE_ADMINISTRATION, 0x03, 0x00))
        await probe(s,"fsops 80 E6 00 00",    build_apdu(CLA_PROP, INS_FS_OPS, 0x00, 0x00))
asyncio.run(main())
