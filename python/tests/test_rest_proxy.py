"""Socket-level REST egress tests; no browser or external network is needed."""

import asyncio
import socket
import struct

import pytest

from camoufox import _rest_proxy


async def connect(gateway, host, port=80, command=1):
    reader, writer = await asyncio.open_connection("127.0.0.1", gateway.port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    name = host.encode("ascii")
    writer.write(b"\x05" + bytes([command, 0, 3, len(name)]) + name + struct.pack("!H", port))
    await writer.drain()
    return reader, writer, await reader.readexactly(10)


@pytest.mark.parametrize("host", [
    "127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1",
    "0.0.0.0", "224.0.0.1", "fe80::1%lo", "fc00::1",
])
def test_private_targets_never_reach_connect(host, monkeypatch):
    async def run():
        loop = asyncio.get_running_loop()
        real_connect = loop.sock_connect
        async def forbidden(sock, address):
            if address == ("127.0.0.1", gateway.port):
                return await real_connect(sock, address)
            pytest.fail("a private socket connection was attempted")
        monkeypatch.setattr(loop, "sock_connect", forbidden)
        async with _rest_proxy.PublicGateway() as gateway:
            _, writer, reply = await connect(gateway, host)
            assert reply[1] != 0
            writer.close()
            await writer.wait_closed()
    asyncio.run(run())


def test_all_dns_answers_are_validated_before_any_connection(monkeypatch):
    async def run():
        loop = asyncio.get_running_loop()
        real_connect = loop.sock_connect
        async def resolve(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80))
                    for ip in ("93.184.215.14", "127.0.0.1")]
        async def forbidden(sock, address):
            if address == ("127.0.0.1", gateway.port):
                return await real_connect(sock, address)
            pytest.fail("mixed DNS answers reached connect")
        monkeypatch.setattr(loop, "getaddrinfo", resolve)
        monkeypatch.setattr(loop, "sock_connect", forbidden)
        async with _rest_proxy.PublicGateway() as gateway:
            _, writer, reply = await connect(gateway, "rebinding.example")
            assert reply[1] != 0
            writer.close()
            await writer.wait_closed()
    asyncio.run(run())


def test_rebinding_after_a_public_preflight_is_refused_before_connect(monkeypatch):
    async def run():
        loop = asyncio.get_running_loop()
        real_connect = loop.sock_connect
        resolutions = []
        async def resolve(*_args, **_kwargs):
            resolutions.append(True)
            ip = "93.184.215.14" if len(resolutions) == 1 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80))]
        async def forbidden(sock, address):
            if address == ("127.0.0.1", gateway.port):
                return await real_connect(sock, address)
            pytest.fail("rebound destination reached connect")
        monkeypatch.setattr(loop, "getaddrinfo", resolve)
        monkeypatch.setattr(loop, "sock_connect", forbidden)
        assert await _rest_proxy.resolve_public("rebinding.example", 80)
        async with _rest_proxy.PublicGateway() as gateway:
            _, writer, reply = await connect(gateway, "rebinding.example")
            assert reply[1] != 0
            writer.close()
            await writer.wait_closed()
        assert len(resolutions) == 2
    asyncio.run(run())


def test_connection_attempts_share_the_overall_deadline(monkeypatch):
    async def run():
        async def echo(reader, writer):
            try:
                writer.write(await reader.read(4096))
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        loop = asyncio.get_running_loop()
        real_connect = loop.sock_connect
        real_getaddrinfo = loop.getaddrinfo
        attempts = []

        async def resolve(host, requested_port, **kwargs):
            if host == "127.0.0.1":
                return await real_getaddrinfo(host, requested_port, **kwargs)
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                for ip in ("93.184.215.14", "1.1.1.1")
            ]

        async def pinned(sock, address):
            if address == ("127.0.0.1", gateway.port):
                return await real_connect(sock, address)
            attempts.append(address[0])
            if address[0] == "93.184.215.14":
                await asyncio.Event().wait()
            await real_connect(sock, ("127.0.0.1", port))

        monkeypatch.setattr(loop, "getaddrinfo", resolve)
        monkeypatch.setattr(loop, "sock_connect", pinned)
        try:
            async with _rest_proxy.PublicGateway(timeout=0.4) as gateway:
                reader, writer, reply = await connect(gateway, "multiple.example", port)
                assert reply[1] == 0
                writer.write(b"hello")
                await writer.drain()
                assert await asyncio.wait_for(reader.readexactly(5), 1) == b"hello"
                writer.close()
                await writer.wait_closed()
            assert attempts == ["93.184.215.14", "1.1.1.1"]
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


@pytest.mark.parametrize("payload", [
    b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"GET /redirect-to-private HTTP/1.1\r\n\r\n",
    b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",
    b"\x16\x03\x01encrypted-wss",
])
def test_numeric_pinning_tunnels_tcp_without_second_resolution(payload, monkeypatch):
    async def run():
        closed = asyncio.Event()
        async def echo(reader, writer):
            try:
                while data := await reader.read(4096):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                closed.set()
        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        loop = asyncio.get_running_loop()
        resolutions, destinations = [], []
        real_connect = loop.sock_connect
        async def resolve(host, requested_port, **kwargs):
            resolutions.append(host)
            ip = "93.184.215.14" if len(resolutions) == 1 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, requested_port))]
        async def pinned(sock, address):
            if address == ("127.0.0.1", gateway.port):
                return await real_connect(sock, address)
            destinations.append(address)
            # Substitute a local echo server only after inspecting the actual numeric target.
            assert address == ("93.184.215.14", port)
            await real_connect(sock, ("127.0.0.1", port))
        monkeypatch.setattr(loop, "getaddrinfo", resolve)
        monkeypatch.setattr(loop, "sock_connect", pinned)
        try:
            async with _rest_proxy.PublicGateway() as gateway:
                reader, writer, reply = await connect(gateway, "rebinding.example", port)
                assert reply[1] == 0
                writer.write(payload)
                await writer.drain()
                assert await reader.readexactly(len(payload)) == payload
            assert await asyncio.wait_for(reader.read(), 1) == b""
            await asyncio.wait_for(closed.wait(), 1)
            writer.close()
            await writer.wait_closed()
            assert resolutions == ["rebinding.example"]
            assert destinations == [("93.184.215.14", port)]
        finally:
            server.close()
            await server.wait_closed()
    asyncio.run(run())


@pytest.mark.parametrize("command", [2, 3, 255])
def test_only_connect_is_supported(command):
    async def run():
        async with _rest_proxy.PublicGateway() as gateway:
            _, writer, reply = await connect(gateway, "127.0.0.1", command=command)
            assert reply[1] == 7
            writer.close()
            await writer.wait_closed()
    asyncio.run(run())


@pytest.mark.parametrize("greeting, reply", [
    (b"\x04\x01\x00", b""),
    (b"\x05\x01\x02", b"\x05\xff"),
    (b"\x05\x00", b"\x05\xff"),
])
def test_malformed_or_unsupported_greetings(greeting, reply):
    async def run():
        async with _rest_proxy.PublicGateway() as gateway:
            reader, writer = await asyncio.open_connection("127.0.0.1", gateway.port)
            writer.write(greeting)
            await writer.drain()
            assert await reader.read() == reply
            writer.close()
            await writer.wait_closed()
    asyncio.run(run())


def test_connection_limit_timeout_and_shutdown():
    async def run():
        gateway = _rest_proxy.PublicGateway(max_connections=1, timeout=0.1)
        async with gateway:
            first, writer = await asyncio.open_connection("127.0.0.1", gateway.port)
            excess, other = await asyncio.open_connection("127.0.0.1", gateway.port)
            assert await asyncio.wait_for(excess.read(), 1) == b""
            assert len(gateway._tasks) <= 1
            assert await asyncio.wait_for(first.read(), 1) == b""
            other.close()
            writer.close()
            await other.wait_closed()
            await writer.wait_closed()
            final, last = await asyncio.open_connection("127.0.0.1", gateway.port)
        assert await final.read() == b""
        last.close()
        await last.wait_closed()
        assert not gateway._tasks
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", gateway.port)
    asyncio.run(run())


def test_active_response_stream_outlives_the_idle_timeout(monkeypatch):
    async def run():
        async def stream(reader, writer):
            await reader.read(4096)
            for chunk in b"stream":
                writer.write(bytes([chunk]))
                await writer.drain()
                await asyncio.sleep(0.06)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(stream, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        loop = asyncio.get_running_loop()
        real_connect = loop.sock_connect
        real_getaddrinfo = loop.getaddrinfo

        async def resolve(host, requested_port, **kwargs):
            if host == "example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", requested_port))]
            return await real_getaddrinfo(host, requested_port, **kwargs)

        async def pinned(sock, address):
            if address == ("93.184.215.14", port):
                return await real_connect(sock, ("127.0.0.1", port))
            return await real_connect(sock, address)

        monkeypatch.setattr(loop, "getaddrinfo", resolve)
        monkeypatch.setattr(loop, "sock_connect", pinned)
        try:
            async with _rest_proxy.PublicGateway(timeout=0.1) as gateway:
                reader, writer, reply = await connect(gateway, "example.com", port)
                assert reply[1] == 0
                writer.write(b"request")
                await writer.drain()
                assert await asyncio.wait_for(reader.readexactly(6), 1) == b"stream"
                writer.close()
                await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


def test_stream_shutdown_aborts_transports_that_do_not_close():
    async def run():
        class Transport:
            aborted = False

            def abort(self):
                self.aborted = True

        class Stream:
            def __init__(self):
                self.transport = Transport()
                self.closed = False

            def close(self):
                self.closed = True

            async def wait_closed(self):
                await asyncio.Event().wait()

        streams = (Stream(), Stream())
        await _rest_proxy.PublicGateway(timeout=0.01)._close_streams(*streams)
        assert all(stream.closed and stream.transport.aborted for stream in streams)

    asyncio.run(run())


@pytest.mark.parametrize("packet", [
    b"\x04\x01\x00\x01" + socket.inet_aton("127.0.0.1") + b"\x00\x50",
    b"\x05\x01\x01\x01" + socket.inet_aton("127.0.0.1") + b"\x00\x50",
    b"\x05\x01\x00\xff",
    b"\x05\x01\x00\x03\x00\x00\x50",
    b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + b"\x00\x50",
    b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, "::ffff:127.0.0.1") + b"\x00\x50",
])
def test_malformed_requests_and_numeric_private_targets_are_refused(packet):
    async def run():
        async with _rest_proxy.PublicGateway() as gateway:
            reader, writer = await asyncio.open_connection("127.0.0.1", gateway.port)
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            assert await reader.readexactly(2) == b"\x05\x00"
            writer.write(packet)
            await writer.drain()
            assert (await reader.readexactly(10))[1] != 0
            writer.close()
            await writer.wait_closed()
    asyncio.run(run())
