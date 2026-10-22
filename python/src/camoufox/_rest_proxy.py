"""CONNECT-only SOCKS5 egress for REST contexts, with DNS pinned to numeric sockets."""

import asyncio
import ipaddress
import socket
import struct
from typing import Any, List, Optional, Set, Tuple


class InvalidDestination(ValueError):
    """A destination has no exclusively public TCP addresses."""


async def resolve_public(host: str, port: int) -> List[Tuple[Any, ...]]:
    """Resolve once and validate the entire answer before opening any socket."""
    if not host or "%" in host or not 1 <= port <= 65535:
        raise InvalidDestination("invalid destination")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            answers = await asyncio.get_running_loop().getaddrinfo(
                host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )
        except (OSError, ValueError, UnicodeError) as error:
            raise InvalidDestination(f"cannot resolve {host!r}") from error
    else:
        family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        sockaddr = (str(address), port) if address.version == 4 else (str(address), port, 0, 0)
        answers = [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)]
    if not answers:
        raise InvalidDestination(f"no addresses for {host!r}")
    for family, _, _, _, sockaddr in answers:
        address = ipaddress.ip_address(sockaddr[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if family not in (socket.AF_INET, socket.AF_INET6) or not address.is_global or address.is_multicast:
            raise InvalidDestination(f"non-public destination {host!r}")
    return answers


class PublicGateway:
    """One bounded, loopback-only gateway per job; its sockets die with the context."""

    def __init__(self, *, max_connections: int = 32, timeout: float = 10.0) -> None:
        self.max_connections = max_connections
        self.timeout = timeout
        self.port = 0
        self._server: Optional[asyncio.AbstractServer] = None
        self._tasks: Set[asyncio.Task] = set()
        self._closing = False

    async def __aenter__(self) -> "PublicGateway":
        self._server = await asyncio.start_server(self._accept, "127.0.0.1", 0, limit=65536)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        self._closing = True
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._closing or len(self._tasks) >= self.max_connections:
            writer.close()
            return
        task = asyncio.create_task(self._serve(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _open(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        version, count = await reader.readexactly(2)
        if version != 5:
            return None
        methods = await reader.readexactly(count)
        writer.write(b"\x05\x00" if 0 in methods else b"\x05\xff")
        await writer.drain()
        if 0 not in methods:
            return None
        version, command, reserved, kind = await reader.readexactly(4)
        if version != 5 or reserved != 0:
            raise InvalidDestination("malformed SOCKS request")
        if command != 1:
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return None
        if kind == 3:
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode("ascii")
        elif kind in (1, 4):
            host = str(ipaddress.ip_address(await reader.readexactly(4 if kind == 1 else 16)))
        else:
            raise InvalidDestination("unsupported address type")
        port = struct.unpack("!H", await reader.readexactly(2))[0]
        answers = await resolve_public(host, port)
        loop = asyncio.get_running_loop()
        for family, socktype, proto, _, sockaddr in answers:
            sock = socket.socket(family, socktype, proto)
            sock.setblocking(False)
            try:
                # sockaddr contains a validated numeric address, never the original hostname.
                await loop.sock_connect(sock, sockaddr)
                return await asyncio.open_connection(sock=sock, limit=65536)
            except OSError:
                sock.close()
            except BaseException:
                sock.close()
                raise
        raise OSError("all public destination addresses failed")

    async def _pump(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            data = await asyncio.wait_for(reader.read(65536), self.timeout)
            if not data:
                return
            writer.write(data)
            await asyncio.wait_for(writer.drain(), self.timeout)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream = None
        pumps: List[asyncio.Task] = []
        try:
            remote = await asyncio.wait_for(self._open(reader, writer), self.timeout)
            if remote is None:
                return
            remote_reader, upstream = remote
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await asyncio.wait_for(writer.drain(), self.timeout)
            pumps = [
                asyncio.create_task(self._pump(reader, upstream)),
                asyncio.create_task(self._pump(remote_reader, writer)),
            ]
            await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        except (OSError, ValueError, UnicodeError):
            writer.write(b"\x05\x02\x00\x01" + b"\x00" * 6)
        finally:
            for task in pumps:
                task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            for stream in (upstream, writer):
                if stream:
                    stream.close()
                    try:
                        await stream.wait_closed()
                    except OSError:
                        pass
