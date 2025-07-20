import asyncio
import json
from asyncio import IncompleteReadError, StreamReader, StreamWriter, sleep
from random import randint
from typing import Literal, cast, final

from scapy.all import Raw, rdpcap

from ji.protocol.reader import PacketReader
from ji.protocol.writer import PacketWriter

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
        self._read = PacketReader(reader)
        self._send_packet = PacketWriter(writer)
        self._writer = writer

        self._state: Literal[
            "handshaking",
            "status",
            "login",
            "configuration",
            "play",
        ] = "handshaking"

        self._keepalive_payload = 0
        self._keepalive_task = asyncio.create_task(self._send_keepalives())

    async def start(self) -> None:
        while True:
            try:
                await self._handle_packet()
            except IncompleteReadError:
                print("Client disconnected")
                break

    async def _handle_packet(self) -> None:  # noqa: C901, PLR0912
        pkt_len = await self._read.varint()
        pkt_id = await self._read.varint()

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

            case 0x00 if self._state == "play":
                # Confirm Teleportation
                pass
            case 0x0C if self._state == "play":
                # Client Tick End
                pass
            case 0x2A if self._state == "play":
                # Player Input
                pass
            case 0x1D if self._state == "play":
                await self._set_player_position()
            case 0x1E if self._state == "play":
                await self._set_player_position_and_rotation()
            case 0x1B if self._state == "play":
                await self._serverbound_keep_alive()

            case _:
                print(f"Unhandled packet ID 0x{pkt_id:02X} ({self._state})")
                _ = await self._read.bytes_(pkt_len - 1)  # Read remaining bytes

    async def _handshake(self) -> None:
        _protocol_ver = await self._read.varint()
        _server_address = await self._read.string()
        _server_port = await self._read.unsigned_short()
        intent = await self._read.varint()

        match intent:
            case 1:
                self._state = "status"
            case 2 | 3:
                self._state = "login"
            case _:
                print(f"Unknown intent {intent}")

    async def _status_request(self) -> None:
        async with self._send_packet(0x00) as p:
            p.string(status_response)

    async def _status_ping_request(self) -> None:
        payload = await self._read.long()
        async with self._send_packet(0x00) as p:
            p.long(payload)

    async def _login_start(self) -> None:
        username = await self._read.string()
        uuid = await self._read.uuid()

        # Login Success
        async with self._send_packet(0x02) as p:
            p.uuid(uuid)
            p.string(username)
            p.varint(0)

    async def _login_acknowledged(self) -> None:
        self._state = "configuration"

        # Clientbound Known Packs
        async with self._send_packet(0x0E) as p:
            p.varint(1)
            p.string("minecraft")
            p.string("core")
            p.string("1.21.8")

    async def _client_information(self) -> None:
        _locale = await self._read.string()
        _view_distance = await self._read.byte()
        _chat_mode = await self._read.varint()
        _chat_colors = await self._read.boolean()
        _displayed_skin_parts = await self._read.unsigned_byte()
        _main_hand = await self._read.varint()
        _enable_text_filtering = await self._read.boolean()
        _allow_server_listings = await self._read.boolean()
        _particle_status = await self._read.varint()

    async def _serverbound_plugin_message(self) -> None:
        _channel = await self._read.string()
        _data = await self._read.bytes_(32767)

    async def _serverbound_known_packs(self) -> None:
        num_packs = await self._read.varint()
        for _ in range(num_packs):
            _namespace = await self._read.string()
            _pack_id = await self._read.string()
            _version = await self._read.string()

        # Clientbound Plugin Message
        async with self._send_packet(0x01) as p:
            p.string("minecraft:brand")
            p.string("Ji")

        # Registry Data
        # Way too complicated to send all of them so just replay captured ones
        registry_data_pkts = rdpcap("registry_data.pcap")
        for pkt in registry_data_pkts:
            self._writer.write(bytes(cast("Raw", pkt[Raw])))
            await self._writer.drain()

        # Finish Configuration
        async with self._send_packet(0x03):
            pass

    async def _acknowledge_finish_configuration(self) -> None:
        self._state = "play"

        # Login
        async with self._send_packet(0x2B) as p:
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
        async with self._send_packet(0x22) as p:
            p.unsigned_byte(13)
            p.float_(0)

        # Synchronize Player Position
        async with self._send_packet(0x41) as p:
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

        # Chunk Data and Update Light
        cd_pkts = rdpcap("chunk_data_and_update_light.pcap")
        for pkt in cd_pkts:
            self._writer.write(bytes(cast("Raw", pkt[Raw])))
            await self._writer.drain()

    async def _set_player_position(self) -> None:
        _x = await self._read.double()
        _y = await self._read.double()
        _z = await self._read.double()
        _flags = await self._read.byte()

    async def _set_player_position_and_rotation(self) -> None:
        _x = await self._read.double()
        _y = await self._read.double()
        _z = await self._read.double()
        _yaw = await self._read.float_()
        _pitch = await self._read.float_()
        _flags = await self._read.byte()

    async def _serverbound_keep_alive(self) -> None:
        payload = await self._read.long()
        if payload != self._keepalive_payload:
            print(f"Client responded with wrong keep-alive payload {payload}")

    async def _send_keepalives(self) -> None:
        while True:
            if self._state == "play":
                self._keepalive_payload = randint(0, 0x7FFFFFFFFFFFFFFF)  # noqa: S311
                async with self._send_packet(0x26) as p:
                    p.long(self._keepalive_payload)
            await sleep(1)


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
