import asyncio
import importlib.util
import os
import socket
from pathlib import Path

from playwright.async_api import Error, async_playwright


def _gateway_module():
    source = (
        Path(os.environ["CAMOUFOX_REPO_ROOT"])
        / "python"
        / "src"
        / "camoufox"
        / "_rest_proxy.py"
    )
    spec = importlib.util.spec_from_file_location("camoufox_rest_proxy", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_rest_gateway_blocks_browser_private_egress(monkeypatch):
    gateway_module = _gateway_module()
    private_connections = []
    requested_hosts = []

    async def private_listener(reader, writer):
        private_connections.append(True)
        writer.close()
        await writer.wait_closed()

    private_server = await asyncio.start_server(private_listener, "127.0.0.1", 0)
    private_port = private_server.sockets[0].getsockname()[1]
    private_url = f"http://127.0.0.1:{private_port}/private"

    async def origin(reader, writer):
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            path = request.split(b" ", 2)[1]
            if path == b"/redirect":
                response = (
                    f"HTTP/1.1 302 Found\r\nLocation: {private_url}\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n"
                ).encode()
            else:
                if path == b"/subresource":
                    body = f'<img src="{private_url}">'.encode()
                elif path == b"/websocket":
                    body = (
                        f"<script>const ws = new WebSocket("
                        f"'ws://127.0.0.1:{private_port}/socket');"
                        "ws.onerror = () => window.wsResult = 'error';"
                        "ws.onopen = () => window.wsResult = 'open';</script>"
                    ).encode()
                else:
                    body = b"<title>Public control</title>"
                response = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body
                )
            writer.write(response)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    origin_server = await asyncio.start_server(origin, "127.0.0.1", 0)
    origin_port = origin_server.sockets[0].getsockname()[1]
    loop = asyncio.get_running_loop()
    real_connect = loop.sock_connect
    real_resolve = gateway_module.resolve_public

    async def resolve(host, port):
        requested_hosts.append(host)
        if host == "gateway.test":
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.215.14", port))
            ]
        return await real_resolve(host, port)

    async def connect(sock, address):
        if address == ("93.184.215.14", origin_port):
            return await real_connect(sock, ("127.0.0.1", origin_port))
        return await real_connect(sock, address)

    monkeypatch.setattr(gateway_module, "resolve_public", resolve)
    monkeypatch.setattr(loop, "sock_connect", connect)

    try:
        async with gateway_module.PublicGateway(timeout=3) as gateway:
            async with async_playwright() as playwright:
                browser = await playwright.firefox.launch(
                    executable_path=os.environ["CAMOUFOX_EXECUTABLE_PATH"],
                    proxy={"server": f"socks5://127.0.0.1:{gateway.port}"},
                    firefox_user_prefs={
                        "network.proxy.allow_hijacking_localhost": True,
                        "network.proxy.no_proxies_on": "",
                        "network.proxy.socks_remote_dns": True,
                    },
                )
                try:
                    page = await browser.new_page()
                    base_url = f"http://gateway.test:{origin_port}"
                    await page.goto(base_url)
                    assert await page.title() == "Public control"

                    for path in ("/redirect", "/subresource", "/websocket"):
                        before = len(requested_hosts)
                        try:
                            await page.goto(base_url + path)
                        except Error:
                            pass
                        if path == "/subresource":
                            await page.wait_for_function(
                                "document.querySelector('img').complete"
                            )
                        elif path == "/websocket":
                            await page.wait_for_function(
                                "window.wsResult !== undefined", timeout=5000
                            )
                            assert await page.evaluate("window.wsResult") == "error"
                        assert "127.0.0.1" in requested_hosts[before:]
                        await asyncio.sleep(0.1)
                        assert not private_connections
                finally:
                    await browser.close()
    finally:
        origin_server.close()
        private_server.close()
        await origin_server.wait_closed()
        await private_server.wait_closed()
