import struct
from asyncio import StreamReader
from typing import cast, final
from uuid import UUID

from ji.protocol.common import VARINT_CONTINUE_BIT, VARINT_SEGMENT_BITS


@final
class PacketReader:
    def __init__(self, reader: StreamReader) -> None:
        self._reader = reader

    async def varint(self) -> int:
        val, pos, byte = 0, 0, 0

        while True:
            byte = (await self._reader.readexactly(1))[0]
            val |= (byte & VARINT_SEGMENT_BITS) << pos

            if (byte & VARINT_CONTINUE_BIT) == 0:
                break

            pos += 7

            max_pos = 32
            if pos >= max_pos:
                msg = "VarInt is too big"
                raise ValueError(msg)

        return val

    async def boolean(self) -> bool:
        return bool((await self._reader.readexactly(1))[0])

    async def string(self) -> str:
        length = await self.varint()
        return (await self._reader.readexactly(length)).decode()

    async def uuid(self) -> UUID:
        return UUID(bytes=await self._reader.readexactly(16))

    async def byte(self) -> int:
        return int.from_bytes(await self._reader.readexactly(1), signed=True)

    async def unsigned_byte(self) -> int:
        return int.from_bytes(await self._reader.readexactly(1), signed=False)

    async def unsigned_short(self) -> int:
        return int.from_bytes(await self._reader.readexactly(2), signed=False)

    async def long(self) -> int:
        return int.from_bytes(await self._reader.readexactly(8), signed=True)

    async def float_(self) -> float:
        return cast("float", struct.unpack(">f", await self._reader.readexactly(8))[0])

    async def double(self) -> float:
        return cast("float", struct.unpack(">d", await self._reader.readexactly(8))[0])

    async def bytes_(self, maximum: int) -> bytes:
        return await self._reader.read(maximum)
