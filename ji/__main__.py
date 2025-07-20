import asyncio
import json
import struct
from asyncio import IncompleteReadError, StreamReader, StreamWriter
from typing import Literal, Self, cast, final
from uuid import UUID

from scapy.all import Raw, rdpcap

VARINT_SEGMENT_BITS = 0x7F
VARINT_CONTINUE_BIT = 0x80

status_response = json.dumps(
    {
        "version": {"name": "1.21.8", "protocol": 772},
        "players": {"max": 20, "online": 0, "sample": ["interrrp"]},
        "description": {"text": "Ji"},
    },
)


@final
class ClientHandler:
    def __init__(self, reader: StreamReader, writer: StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

        self._state: Literal[
            "handshaking",
            "status",
            "login",
            "configuration",
            "play",
        ] = "handshaking"

    async def start(self) -> None:
        while True:
            try:
                await self._handle_packet()
            except IncompleteReadError:
                print("Client disconnected")
                break

    async def _handle_packet(self) -> None:  # noqa: C901, PLR0912
        pkt_len = await self._read_varint()
        pkt_id = await self._read_varint()

        print(f"{self._state} 0x{pkt_id:02X}")

        match pkt_id:
            case 0x00 if self._state == "handshaking":
                await self._handshake()

            case 0x00 if self._state == "status":
                await self._status_request()
            case 0x01 if self._state == "status":
                await self._status_ping_request()

            case 0x00 if self._state == "login":
                await self._login_start()
            case 0x03 if self._state == "login":
                await self._login_acknowledged()

            case 0x00 if self._state == "configuration":
                await self._client_information()
            case 0x02 if self._state == "configuration":
                await self._serverbound_plugin_message()
            case 0x07 if self._state == "configuration":
                await self._serverbound_known_packs()
            case 0x03 if self._state == "configuration":
                await self._acknowledge_finish_configuration()

            case 0x0C if self._state == "play":
                # Client Tick End
                pass
            case 0x2A if self._state == "play":
                # Player Input
                pass
            case 0x1D if self._state == "play":
                await self._set_player_position()

            case _:
                print(f"Unhandled packet ID 0x{pkt_id:02X}")
                _ = await self.reader.readexactly(pkt_len - 1)  # Read remaining bytes

    async def _handshake(self) -> None:
        _protocol_ver = await self._read_varint()
        _server_address = await self._read_string()
        _server_port = await self._read_unsigned_short()
        intent = await self._read_varint()

        match intent:
            case 1:
                self._state = "status"
            case 2 | 3:
                self._state = "login"
            case _:
                print(f"Unknown intent {intent}")

    async def _status_request(self) -> None:
        async with PacketWriter(0x00, self) as p:
            p.string(status_response)

    async def _status_ping_request(self) -> None:
        payload = await self._read_long()
        async with PacketWriter(0x01, self) as p:  # Ping Response
            p.long(payload)
            self._state = "handshaking"

    async def _login_start(self) -> None:
        username = await self._read_string()
        uuid = await self._read_uuid()

        # Login Success
        async with PacketWriter(0x02, self) as p:
            p.uuid(uuid)
            p.string(username)
            p.varint(0)

    async def _login_acknowledged(self) -> None:
        self._state = "configuration"

        # Clientbound Known Packs
        async with PacketWriter(0x0E, self) as p:
            p.varint(1)
            p.string("minecraft")
            p.string("core")
            p.string("1.21.8")

    async def _client_information(self) -> None:
        _locale = await self._read_string()
        _view_distance = await self._read_byte()
        _chat_mode = await self._read_varint()
        _chat_colors = await self._read_boolean()
        _displayed_skin_parts = await self._read_unsigned_byte()
        _main_hand = await self._read_varint()
        _enable_text_filtering = await self._read_boolean()
        _allow_server_listings = await self._read_boolean()
        _particle_status = await self._read_varint()

    async def _serverbound_plugin_message(self) -> None:
        _channel = await self._read_string()
        _data = await self.reader.read(32767)

    async def _serverbound_known_packs(self) -> None:
        num_packs = await self._read_varint()
        for _ in range(num_packs):
            _namespace = await self._read_string()
            _pack_id = await self._read_string()
            _version = await self._read_string()

        # Clientbound Plugin Message
        async with PacketWriter(0x01, self) as p:
            p.string("minecraft:brand")
            p.string("Ji")

        # Registry Data
        # Way too complicated to send all of them so just replay captured ones
        registry_data_pkts = rdpcap("registry_data.pcap")
        for pkt in registry_data_pkts:
            self.writer.write(bytes(cast("Raw", pkt[Raw])))
            await self.writer.drain()

        async with PacketWriter(0x03, self):
            pass

    async def _acknowledge_finish_configuration(self) -> None:
        self._state = "play"
        print("x")

        # Login
        async with PacketWriter(0x2B, self) as p:
            p.integer(1)  # Entity ID
            p.boolean(False)  # Hardcore

            # Dimensions
            p.varint(1)
            p.string("minecraft:overworld")

            p.varint(20)  # Max players
            p.varint(8)  # View distance
            p.varint(8)  # Simulation distance
            p.boolean(False)  # Reduced debug info
            p.boolean(True)  # Respawn screen
            p.boolean(False)  # Limited crafting
            p.varint(1)  # Dimension type
            p.string("minecraft:overworld")  # Dimension name
            p.long(0x42)  # Hashed seed
            p.unsigned_byte(1)  # Game mode (creative)
            p.unsigned_byte(1)  # Previous game mode (creative)
            p.boolean(False)  # Debug mode
            p.boolean(False)  # Flat world
            p.boolean(False)  # Has death location
            p.varint(0)  # Portal cooldown
            p.varint(0)  # Sea level
            p.boolean(False)  # Enforces secure chat

        # Game Event (Start waiting for level chunks)
        async with PacketWriter(0x22, self) as p:
            p.unsigned_byte(13)
            p.float_(0)

        # Synchronize Player Position
        async with PacketWriter(0x41, self) as p:
            p.varint(42)  # Teleport ID
            p.double(0)  # X
            p.double(0)  # Y
            p.double(0)  # Z
            p.double(0)  # Velocity X
            p.double(0)  # Velocity Y
            p.double(0)  # Velocity Z
            p.float_(0)  # Yaw
            p.float_(0)  # Pitch
            p.integer(0)  # Teleport flags

    async def _set_player_position(self) -> None:
        _x = await self._read_double()
        _y = await self._read_double()
        _z = await self._read_double()
        _flags = await self._read_byte()

    async def _read_varint(self) -> int:
        val, pos, byte = 0, 0, 0

        while True:
            byte = (await self.reader.readexactly(1))[0]
            val |= (byte & VARINT_SEGMENT_BITS) << pos

            if (byte & VARINT_CONTINUE_BIT) == 0:
                break

            pos += 7

            max_pos = 32
            if pos >= max_pos:
                msg = "VarInt is too big"
                raise ValueError(msg)

        return val

    async def _read_boolean(self) -> bool:
        return bool((await self.reader.readexactly(1))[0])

    async def _read_string(self) -> str:
        length = await self._read_varint()
        return (await self.reader.readexactly(length)).decode()

    async def _read_uuid(self) -> UUID:
        return UUID(bytes=await self.reader.readexactly(16))

    async def _read_byte(self) -> int:
        return int.from_bytes(await self.reader.readexactly(1), signed=True)

    async def _read_unsigned_byte(self) -> int:
        return int.from_bytes(await self.reader.readexactly(1), signed=False)

    async def _read_unsigned_short(self) -> int:
        return int.from_bytes(await self.reader.readexactly(2), signed=False)

    async def _read_long(self) -> int:
        return int.from_bytes(await self.reader.readexactly(8), signed=True)

    async def _read_double(self) -> float:
        return cast("float", struct.unpack(">d", await self.reader.readexactly(8))[0])


@final
class PacketWriter:
    def __init__(self, pkt_id: int, handler: ClientHandler) -> None:
        self._pkt_id = pkt_id
        self._writer = handler.writer
        self._buf = b""

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


async def handle_client(reader: StreamReader, writer: StreamWriter) -> None:
    await ClientHandler(reader, writer).start()


async def main() -> None:
    host, port = "127.0.0.1", 25565
    server = await asyncio.start_server(handle_client, host, port)
    print(f"Listening on {host}:{port}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
