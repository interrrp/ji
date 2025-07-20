import struct
from asyncio import StreamWriter
from typing import Self, final
from uuid import UUID

from ji.protocol.common import VARINT_CONTINUE_BIT, VARINT_SEGMENT_BITS


@final
class PacketWriter:
    def __init__(self, writer: StreamWriter) -> None:
        self._pkt_id: int
        self._writer = writer
        self._buf = b""

    def __call__(self, pkt_id: int) -> Self:
        self._pkt_id = pkt_id
        return self

    def _varint(self, val: int) -> bytes:
        buf = b""

        while True:
            if (val & ~VARINT_SEGMENT_BITS) == 0:
                return buf + bytes([val])

            buf += bytes([(val & VARINT_SEGMENT_BITS) | VARINT_CONTINUE_BIT])

            val &= 0xFFFFFFFF
            val = (val >> 7) & (0xFFFFFFFF >> 7)

    def varint(self, val: int) -> None:
        self._buf += self._varint(val)

    def string(self, val: str) -> None:
        self.varint(len(val))
        self._buf += val.encode()

    def uuid(self, val: UUID) -> None:
        self._buf += val.bytes

    def long(self, val: int) -> None:
        self._buf += val.to_bytes(8, signed=True)

    def integer(self, val: int) -> None:
        self._buf += val.to_bytes(4, signed=True)

    def boolean(self, val: bool) -> None:  # noqa: FBT001
        self._buf += bytes([val])

    def unsigned_byte(self, val: int) -> None:
        self._buf += val.to_bytes(1, signed=False)

    def short(self, val: int) -> None:
        self._buf += val.to_bytes(2, signed=True)

    def float_(self, val: float) -> None:
        self._buf += struct.pack("f", val)

    def double(self, val: float) -> None:
        self._buf += struct.pack("d", val)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object, **kwargs: object) -> None:
        self._writer.write(self._varint(len(self._buf) + 1))
        self._writer.write(self._varint(self._pkt_id))
        self._writer.write(self._buf)
        await self._writer.drain()
        self._buf = b""
