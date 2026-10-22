"""
Tests for camoufox.rest, the REST API around a shared browser.

The browser is a fake, so these exercise the HTTP layer, input validation and
the cleanup paths without downloading or launching Camoufox.

Run with:
    cd python && python -m pytest tests/test_rest.py -v
"""

import asyncio
import base64
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import pytest
from click.testing import CliRunner

from camoufox import rest

PUBLIC_URL = "http://93.184.215.14/"
DEFAULT_TOKEN = "rest-test-token"


def wire_request(service, headers, method="POST", body=b""):
    host, port = service._httpd.server_address[:2]
    with socket.create_connection((host, port), timeout=3) as connection:
        connection.sendall(
            (f"{method} /jobs HTTP/1.1\r\n" + headers + "\r\n").encode() + body
        )
        return connection.recv(65536).split(b"\r\n", 1)[0]


def test_default_public_mode_launches_with_required_prefs_and_a_context_gateway(context_options):
    service, launcher = make_service()
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        assert wait_finished(service, job["id"])["status"] == "succeeded"
        assert launcher.prefs["media.peerconnection.enabled"] is False
        assert launcher.prefs["network.proxy.allow_hijacking_localhost"] is True
        assert launcher.prefs["network.proxy.no_proxies_on"] == ""
        assert launcher.prefs["network.dns.disablePrefetch"] is True
        assert launcher.prefs["network.http.speculative-parallel-limit"] == 0
        assert launcher.prefs["network.prefetch-next"] is False
        proxy = context_options[0]["_transport_proxy"]
        assert proxy["server"].startswith("socks5://127.0.0.1:")
        assert proxy.get("bypass", "") == ""
        assert "webrtc_ip" not in context_options[0]
    assert launcher.closed


def test_public_mode_rejects_unsupported_custom_launchers():
    with pytest.raises(TypeError, match="firefox_user_prefs"):
        with rest.RestService(lambda: FakeLauncher(FakeBrowser()), port=0, token=DEFAULT_TOKEN):
            pytest.fail("a launcher unable to enforce preferences was accepted")


def test_loopback_also_requires_an_explicit_token():
    with pytest.raises(ValueError, match=rest.TOKEN_ENV_VAR):
        rest.RestService(lambda: FakeLauncher(FakeBrowser()), allow_private_networks=True)


@pytest.mark.parametrize("headers", [
    "Host: evil.example",
    "Host: 127.0.0.1",
    "Host: 127.0.0.1\r\nHost: evil.example",
    "",
])
def test_untrusted_or_ambiguous_host_is_rejected(headers):
    service, _ = make_service(allow_private_networks=True, token=DEFAULT_TOKEN)
    with service:
        status = wire_request(service, headers + "\r\n", method="GET")
    assert b" 400 " in status or b" 403 " in status


@pytest.mark.parametrize("extra", [
    "Origin: https://evil.example\r\n",
    "Origin: null\r\n",
    "Authorization" + ": duplicate\r\n",
    "Content-Length: 0\r\nContent-Length: 0\r\n",
    "Transfer-Encoding: chunked\r\n",
    "Content-Type: text/plain\r\n",
    "Content-Type: application/json\r\nContent-Type: application/json\r\n",
    "Origin: null\r\nOrigin: null\r\n",
    "Forwarded: host=evil.example\r\n",
    "X-Forwarded-Host: evil.example\r\n",
    "Expect: 100-continue\r\n",
    "Content-Type: application/json\r\nContent-Length: +1\r\n",
])
def test_untrusted_submission_headers_are_rejected_before_body(extra):
    service, launcher = make_service(allow_private_networks=True, token=DEFAULT_TOKEN)
    with service:
        authority = urlsplit(service.url).netloc
        status = wire_request(
            service, f"Host: {authority}\r\n{'Authorization'}: {'Bearer'} {DEFAULT_TOKEN}\r\n{extra}"
        )
    assert b" 400 " in status or b" 403 " in status or b" 415 " in status
    assert launcher.browser.contexts == []


@pytest.mark.parametrize("operation", ["content", "screenshot"])
def test_stored_result_has_a_serialized_byte_limit(operation, monkeypatch):
    async def content(_self):
        return "\N{SNOWMAN}" * 1024

    async def screenshot(_self, full_page):
        return b"x" * 1024

    monkeypatch.setattr(FakePage, "content", content)
    monkeypatch.setattr(FakePage, "screenshot", screenshot)
    service, _ = make_service(
        allow_private_networks=True, token=DEFAULT_TOKEN, max_result_bytes=512
    )
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": operation},
                         token=DEFAULT_TOKEN)
        finished = wait_finished(service, job["id"], token=DEFAULT_TOKEN)
        assert finished["status"] == "failed"
        assert "result" in finished["error"]
        assert service.jobs._jobs[job["id"]].result is None


def test_nonfinite_job_numbers_are_rejected():
    for value in (float("nan"), float("inf"), -float("inf")):
        with pytest.raises(rest.InvalidJob):
            rest.parse_job({"url": PUBLIC_URL, "operation": "content", "timeout": value}, 30)


@pytest.mark.parametrize("field", ["url", "title"])
def test_result_limit_includes_metadata(field, monkeypatch):
    goto = FakePage.goto

    async def navigate(page, url, wait_until):
        await goto(page, url, wait_until)
        if field == "url":
            page.url += "x" * 1024

    async def value(page):
        return "x" * 1024 if field == "title" else "Example"

    monkeypatch.setattr(FakePage, "goto", navigate)
    monkeypatch.setattr(FakePage, "title", value)
    service, _ = make_service(max_result_bytes=512)
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        assert wait_finished(service, job["id"])["status"] == "failed"
        assert service.jobs._jobs[job["id"]].result is None


def test_stored_errors_are_byte_bounded_and_do_not_retain_tasks():
    async def fail(_context, _url):
        raise RuntimeError("\N{SNOWMAN}" * 10000)

    service, _ = make_service(FakeBrowser(on_goto=fail), max_result_bytes=512)
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        finished = wait_finished(service, job["id"])
        assert len(finished["error"].encode()) <= 512
        assert service.jobs._jobs[job["id"]].task is None


def test_authentication_is_checked_without_reading_the_body():
    service, launcher = make_service()
    with service:
        status = wire_request(
            service, f"Host: {urlsplit(service.url).netloc}\r\n"
            "Content-Type: application/json\r\nContent-Length: 1234\r\n"
        )
    assert b" 401 " in status
    assert launcher.browser.contexts == []


def test_same_origin_is_accepted():
    service, _ = make_service()
    with service:
        status = wire_request(
            service, f"Host: {urlsplit(service.url).netloc}\r\nOrigin: {service.url}\r\n",
            method="GET",
        )
    assert b" 401 " in status


def test_wildcard_bind_accepts_only_the_actual_local_ip():
    service, _ = make_service(host="0.0.0.0")
    with service:
        port = service._httpd.server_address[1]
        with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
            connection.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
            assert b" 200 " in connection.recv(4096)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
            connection.sendall(f"GET / HTTP/1.1\r\nHost: evil.example:{port}\r\n\r\n".encode())
            assert b" 400 " in connection.recv(4096)


@pytest.mark.parametrize("body", [False, True])
def test_stalled_headers_and_bodies_have_an_absolute_deadline(body):
    service, _ = make_service(request_timeout=0.2)
    with service:
        host, port = service._httpd.server_address[:2]
        with socket.create_connection((host, port), timeout=3) as connection:
            partial = b"GET / HTTP/1.1\r\n"
            if body:
                partial = (
                    f"POST /jobs HTTP/1.1\r\nHost: {host}:{port}\r\n"
                    f"{'Authorization'}: {'Bearer'} {DEFAULT_TOKEN}\r\n"
                    "Content-Type: application/json\r\nContent-Length: 99\r\n\r\n{"
                ).encode()
            connection.sendall(partial)
            assert connection.recv(4096) == b""


def test_request_workers_are_bounded(monkeypatch):
    started = threading.Event()
    setup = rest._Handler.setup

    def record(handler):
        setup(handler)
        started.set()

    monkeypatch.setattr(rest._Handler, "setup", record)
    service, _ = make_service(max_requests=1)
    with service:
        host, port = service._httpd.server_address[:2]
        with socket.create_connection((host, port), timeout=3) as first:
            first.sendall(b"GET / HTTP/1.1\r\n")
            assert started.wait(3)
            with socket.create_connection((host, port), timeout=3) as excess:
                assert excess.recv(4096) == b""


@pytest.mark.parametrize("option, value", [
    ("timeout", float("nan")), ("request_timeout", float("inf")),
    ("concurrency", True), ("max_jobs", 0), ("max_result_bytes", 0), ("max_requests", 0),
])
def test_service_limits_must_be_positive_and_finite(option, value):
    with pytest.raises(ValueError, match=option):
        make_service(**{option: value})


def test_cli_defaults_to_public_only_and_forwards_limits(monkeypatch):
    from camoufox.__main__ import cli

    monkeypatch.setenv(rest.TOKEN_ENV_VAR, DEFAULT_TOKEN)
    received = {}
    monkeypatch.setattr(rest, "serve", lambda *args, **kw: received.update(kw))
    result = CliRunner().invoke(cli, ["rest", "--port", "0"])
    assert result.exit_code == 0, result.output
    assert received["allow_private_networks"] is False
    result = CliRunner().invoke(
        cli, ["rest", "--allow-private-networks", "--max-result-bytes", "512", "--max-requests", "3"]
    )
    assert result.exit_code == 0, result.output
    assert received["max_result_bytes"] == 512
    assert received["max_requests"] == 3
    assert received["allow_private_networks"] is True


class FakeElement:
    def __init__(self, selector, state):
        self.selector = selector
        self.state = state

    async def evaluate(self, expression):
        assert expression == "e => e.outerHTML"
        return "<div>element</div>"

    async def screenshot(self):
        return b"\x89PNG element"

    async def inner_text(self):
        return "element"


class FakePage:
    def __init__(self, context):
        self.context = context
        self.url = "about:blank"
        self.default_timeout = 30000
        self.wait_until = None
        self.element = None
        self.full_page = None

    def set_default_timeout(self, timeout):
        self.default_timeout = timeout

    async def goto(self, url, wait_until):
        self.wait_until = wait_until
        await self.context.browser.on_goto(self.context, url)
        self.url = url

    async def wait_for_selector(self, selector, state):
        self.element = FakeElement(selector, state)
        return self.element

    async def title(self):
        return "Example"

    async def content(self):
        return "<html>example</html>"

    async def inner_text(self, selector):
        assert selector == "body"
        return "example"

    async def screenshot(self, full_page):
        self.full_page = full_page
        return b"\x89PNG"


class FakeContext:
    def __init__(self, browser):
        self.browser = browser
        self.closed = False

    async def new_page(self):
        self.page = FakePage(self)
        return self.page

    async def close(self):
        self.closed = True


class FakeBrowser:
    def __init__(self, on_goto=None):
        self.contexts = []
        self.on_goto = on_goto or self._noop

    @staticmethod
    async def _noop(_context, _url):
        pass

    async def new_context(self):
        context = FakeContext(self)
        self.contexts.append(context)
        return context


@pytest.fixture(autouse=True)
def context_options(monkeypatch):
    """Stand in for AsyncNewContext, whose fingerprinting is tested elsewhere, and record what each job asked for."""
    received = []

    async def new_context(browser, **options):
        received.append(options)
        return await browser.new_context()

    monkeypatch.setattr(rest, "AsyncNewContext", new_context)
    return received


class FakeLauncher:
    def __init__(self, browser, fail=False):
        self.browser = browser
        self.fail = fail
        self.closed = False

    async def __aenter__(self):
        if self.fail:
            raise RuntimeError("launch failed")
        return self.browser

    async def __aexit__(self, *_exc):
        self.closed = True


def request(service, method, path, body=None, token=DEFAULT_TOKEN, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(service.url + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token == DEFAULT_TOKEN:
        token = service._token
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def wait_finished(service, job_id, token=DEFAULT_TOKEN):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        _, job = request(service, "GET", f"/jobs/{job_id}", token=token)
        if job["status"] in ("succeeded", "failed"):
            return job
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish")


def make_service(browser=None, **options):
    launcher = FakeLauncher(browser or FakeBrowser())
    options.setdefault("port", 0)
    options.setdefault("token", DEFAULT_TOKEN)
    def launch(**kwargs):
        launcher.prefs = kwargs.get("firefox_user_prefs", {})
        return launcher
    return rest.RestService(launch, **options), launcher


def test_content_job_returns_the_page_and_closes_its_context():
    service, launcher = make_service()
    with service:
        status, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        assert status == 202
        assert job["status"] in ("queued", "running")
        assert wait_finished(service, job["id"])["status"] == "succeeded"
        status, result = request(service, "GET", f"/jobs/{job['id']}/result")
    assert status == 200
    assert result == {"url": PUBLIC_URL, "title": "Example", "html": "<html>example</html>"}
    assert [context.closed for context in launcher.browser.contexts] == [True]
    assert launcher.closed


def test_screenshot_job_returns_base64_png():
    service, _ = make_service()
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "screenshot"})
        wait_finished(service, job["id"])
        _, result = request(service, "GET", f"/jobs/{job['id']}/result")
    assert base64.b64decode(result["screenshot"]) == b"\x89PNG"


@pytest.mark.parametrize(
    "body, raw",
    [
        ({"url": PUBLIC_URL, "operation": "evaluate"}, None),
        ({"url": "file:///etc/passwd", "operation": "content"}, None),
        ({"url": "http://127.0.0.1/", "operation": "content"}, None),
        ({"url": "http://10.0.0.1/", "operation": "content"}, None),
        ({"url": "http://169.254.169.254/", "operation": "content"}, None),
        ({"url": "http://[::1]/", "operation": "content"}, None),
        ({"url": "http://[::ffff:127.0.0.1]/", "operation": "content"}, None),
        ({"url": PUBLIC_URL, "operation": "content", "script": "1"}, None),
        ({"operation": "content"}, None),
        ({"url": PUBLIC_URL, "operation": "content", "wait_until": "never"}, None),
        ({"url": PUBLIC_URL, "operation": "content", "timeout": 0}, None),
        ({"url": PUBLIC_URL, "operation": "content", "timeout": 31}, None),
        ({"url": PUBLIC_URL, "operation": "content", "timeout": True}, None),
        ({"url": PUBLIC_URL, "operation": "content", "selector": ""}, None),
        ({"url": PUBLIC_URL, "operation": "content", "full_page": True}, None),
        ({"url": PUBLIC_URL, "operation": "screenshot", "full_page": "yes"}, None),
        ({"url": PUBLIC_URL, "operation": "content", "format": "markdown"}, None),
        ({"url": PUBLIC_URL, "operation": "content", "os": "android"}, None),
        ({"url": PUBLIC_URL, "operation": "content", "geolocation": {"latitude": 91, "longitude": 0}}, None),
        ({"url": PUBLIC_URL, "operation": "content", "geolocation": {"latitude": 52}}, None),
        ({"url": PUBLIC_URL, "operation": "content", "proxy": {"server": "file:///etc/passwd"}}, None),
        ({"url": PUBLIC_URL, "operation": "content", "proxy": {"server": PUBLIC_URL, "bypass": "*"}}, None),
        ({"url": PUBLIC_URL, "operation": "screenshot", "format": "text"}, None),
        ({"url": PUBLIC_URL, "operation": "screenshot", "full_page": True, "selector": "h1"}, None),
        ({"url": "http://" + "a" * rest.MAX_URL_LENGTH, "operation": "content"}, None),
        (None, b"not json"),
        (None, b"[]"),
    ],
)
def test_invalid_or_unsafe_jobs_are_rejected(body, raw):
    service, launcher = make_service()
    with service:
        status, response = request(service, "POST", "/jobs", body, raw=raw)
    assert status == 400, response
    assert launcher.browser.contexts == []


def test_job_parameters_default_and_reach_the_page():
    service, launcher = make_service(timeout=30)
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        _, other = request(
            service, "POST", "/jobs",
            {"url": PUBLIC_URL, "operation": "screenshot", "wait_until": "domcontentloaded", "full_page": True,
             "timeout": 5},
        )
        wait_finished(service, job["id"])
        wait_finished(service, other["id"])
    assert {key: job[key] for key in ("wait_until", "selector", "full_page", "timeout")} == {
        "wait_until": "load", "selector": None, "full_page": False, "timeout": 30,
    }
    assert other["wait_until"] == "domcontentloaded" and other["timeout"] == 5
    pages = [context.page for context in launcher.browser.contexts]
    assert [(page.wait_until, page.full_page) for page in pages] == [("load", None), ("domcontentloaded", True)]
    # Playwright's own 30s default would cut a longer job short.
    assert [page.default_timeout for page in pages] == [0, 0]


@pytest.mark.parametrize(
    "operation, state, field, expected",
    [
        ("content", "attached", "html", "<div>element</div>"),
        ("screenshot", "visible", "screenshot", base64.b64encode(b"\x89PNG element").decode()),
    ],
)
def test_a_selector_waits_for_and_returns_only_that_element(operation, state, field, expected):
    service, launcher = make_service()
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": operation, "selector": "#main"})
        wait_finished(service, job["id"])
        _, result = request(service, "GET", f"/jobs/{job['id']}/result")
    assert result[field] == expected
    element = launcher.browser.contexts[0].page.element
    assert (element.selector, element.state) == ("#main", state)


@pytest.mark.parametrize("selector, expected", [(None, "example"), ("#main", "element")])
def test_content_as_text_returns_the_rendered_text_instead_of_html(selector, expected):
    body = {"url": PUBLIC_URL, "operation": "content", "format": "text"}
    if selector:
        body["selector"] = selector
    service, _ = make_service()
    with service:
        _, job = request(service, "POST", "/jobs", body)
        wait_finished(service, job["id"])
        _, result = request(service, "GET", f"/jobs/{job['id']}/result")
    assert job["format"] == "text"
    assert result == {"url": PUBLIC_URL, "title": "Example", "text": expected}


def test_identity_options_reach_the_context_and_the_proxy_password_stays_private(context_options):
    proxy = {"server": "socks5://93.184.215.14:1080", "username": "user", "password": "hunter2"}
    body = {
        "url": PUBLIC_URL, "operation": "content", "os": "macos", "timezone_id": "Europe/Amsterdam",
        "geolocation": {"latitude": 52.37, "longitude": 4.89}, "proxy": proxy,
    }
    service, _ = make_service(allow_private_networks=True)
    with service:
        _, plain = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        _, job = request(service, "POST", "/jobs", body)
        wait_finished(service, plain["id"])
        finished = wait_finished(service, job["id"])
    assert finished["status"] == "succeeded"
    assert sorted(context_options, key=len) == [
        {}, {key: body[key] for key in ("os", "timezone_id", "geolocation", "proxy")},
    ]
    assert job["proxy"] == finished["proxy"] == {"server": proxy["server"], "username": "user"}


def test_a_job_timeout_shorter_than_the_service_limit_applies():
    async def hang(_context, _url):
        await asyncio.sleep(60)

    service, launcher = make_service(FakeBrowser(on_goto=hang), timeout=60)
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content", "timeout": 0.2})
        finished = wait_finished(service, job["id"])
    assert finished["error"] == "timed out after 0.2s (wait_until load)"
    assert launcher.browser.contexts[0].closed


def test_private_networks_can_be_allowed_explicitly():
    service, _ = make_service(allow_private_networks=True)
    with service:
        status, job = request(service, "POST", "/jobs", {"url": "http://127.0.0.1/", "operation": "content"})
        assert status == 202
        assert wait_finished(service, job["id"])["status"] == "succeeded"


def test_oversized_body_is_rejected():
    service, _ = make_service()
    with service:
        status, _ = request(service, "POST", "/jobs", raw=b" " * (rest.MAX_BODY_BYTES + 1))
    assert status == 413


def test_a_slow_job_times_out_and_its_context_is_closed():
    async def hang(_context, _url):
        await asyncio.sleep(60)

    service, launcher = make_service(FakeBrowser(on_goto=hang), timeout=0.2)
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        finished = wait_finished(service, job["id"])
        status, response = request(service, "GET", f"/jobs/{job['id']}/result")
    assert finished["status"] == "failed"
    assert "timed out" in finished["error"]
    assert status == 409 and "timed out" in response["error"]
    assert launcher.browser.contexts[0].closed


def test_a_failing_job_reports_the_error_and_its_context_is_closed():
    async def fail(_context, _url):
        raise RuntimeError("net::ERR_NAME_NOT_RESOLVED")

    service, launcher = make_service(FakeBrowser(on_goto=fail))
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        finished = wait_finished(service, job["id"])
    assert finished["error"] == "RuntimeError: net::ERR_NAME_NOT_RESOLVED"
    assert launcher.browser.contexts[0].closed


def test_per_job_proxy_is_rejected_in_public_mode():
    service, launcher = make_service()
    with service:
        status, response = request(service, "POST", "/jobs", {
            "url": PUBLIC_URL, "operation": "content", "proxy": {"server": PUBLIC_URL},
        })
    assert status == 400
    assert "proxy" in response["error"]
    assert launcher.browser.contexts == []


@pytest.mark.parametrize("kind, target", [
    ("redirect", "http://10.0.0.1/admin"),
    ("subresource", "http://169.254.169.254/latest/meta-data/"),
    ("websocket", "ws://127.0.0.1/socket"),
    ("websocket", "wss://[::ffff:127.0.0.1]/socket"),
])
def test_private_page_requests_use_the_context_gateway(kind, target, context_options):
    async def page_request(_context, _url):
        proxy = urlsplit(context_options[-1]["_transport_proxy"]["server"])
        destination = urlsplit(target)
        reader, writer = await asyncio.open_connection(proxy.hostname, proxy.port)
        try:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            assert await reader.readexactly(2) == b"\x05\x00"
            host = destination.hostname.encode()
            port = destination.port or (443 if destination.scheme in ("https", "wss") else 80)
            writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + port.to_bytes(2, "big"))
            await writer.drain()
            assert (await reader.readexactly(10))[1] != 0
            if kind == "redirect":
                raise RuntimeError("redirect connection refused")
        finally:
            writer.close()
            await writer.wait_closed()

    service, launcher = make_service(FakeBrowser(on_goto=page_request))
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        finished = wait_finished(service, job["id"])
    assert finished["status"] == ("failed" if kind == "redirect" else "succeeded")
    assert launcher.browser.contexts[0].closed


@pytest.mark.parametrize("options", [
    {"proxy": {"server": "http://127.0.0.1:8080"}},
    {"from_options": {"headless": True}},
    {"persistent_context": True},
    {"launch_options": {"firefox_user_prefs": {"media.peerconnection.enabled": True}}},
])
def test_public_serve_rejects_opaque_or_unrestricted_launch_config(options, monkeypatch):
    monkeypatch.setattr(rest.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(rest, "AsyncCamoufox", lambda **_kw: pytest.fail("browser launched"))
    with pytest.raises(ValueError, match="public-only"):
        rest.serve(launch_options=options)


def test_serve_enforces_security_prefs_over_operator_prefs(monkeypatch):
    received = {}
    class Stop(Exception):
        pass

    def camoufox(**options):
        received.update(options)
        raise Stop()

    monkeypatch.setenv(rest.TOKEN_ENV_VAR, DEFAULT_TOKEN)
    monkeypatch.setattr(rest.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(rest, "AsyncCamoufox", camoufox)
    with pytest.raises(Stop):
        rest.serve(port=0, launch_options={
            "firefox_user_prefs": {
                "media.peerconnection.enabled": True,
                "network.proxy.allow_hijacking_localhost": False,
                "network.proxy.no_proxies_on": "*",
                "permissions.default.image": 2,
            },
        })
    assert received["firefox_user_prefs"] == {
        **rest.PUBLIC_ONLY_PREFS, "permissions.default.image": 2,
    }


def test_unknown_jobs_and_paths_are_404():
    service, _ = make_service()
    with service:
        assert request(service, "GET", "/jobs/nope")[0] == 404
        assert request(service, "GET", "/jobs/nope/result")[0] == 404
        assert request(service, "GET", "/jobs")[0] == 404
        assert request(service, "POST", "/other", {})[0] == 404


def test_a_full_job_store_rejects_new_jobs_until_one_finishes():
    release = asyncio.Event()

    async def block(_context, _url):
        await release.wait()

    service, _ = make_service(FakeBrowser(on_goto=block), max_jobs=1)
    with service:
        _, first = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        status, _ = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        assert status == 503
        service.call(_set(release))
        wait_finished(service, first["id"])
        status, second = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})
        assert status == 202
        # The finished job was evicted to make room.
        assert request(service, "GET", f"/jobs/{first['id']}")[0] == 404


async def _set(event):
    event.set()


def test_shutdown_cancels_running_jobs_and_closes_everything():
    async def hang(_context, _url):
        await asyncio.sleep(60)

    service, launcher = make_service(FakeBrowser(on_goto=hang), concurrency=1, timeout=60)
    with service:
        ids = [
            request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"})[1]["id"]
            for _ in range(2)
        ]
        jobs = service.jobs
    assert [jobs._jobs[job_id].error for job_id in ids] == ["cancelled: the service is shutting down"] * 2
    assert [context.closed for context in launcher.browser.contexts] == [True]
    assert launcher.closed


def test_a_launch_failure_is_raised_and_nothing_is_left_listening():
    launcher = FakeLauncher(FakeBrowser(), fail=True)
    service = rest.RestService(lambda: launcher, port=0, token=DEFAULT_TOKEN, allow_private_networks=True)
    with pytest.raises(RuntimeError, match="launch failed"):
        service.__enter__()
    with pytest.raises(OSError):
        service._httpd.socket.getsockname()


def test_token_is_required_when_configured():
    service, _ = make_service(token="s3cret")
    with service:
        assert request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"}, token=None)[0] == 401
        assert request(service, "GET", "/jobs/x", token="wrong")[0] == 401
        status, _ = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": "content"}, token="s3cret")
        assert status == 202


def test_binding_beyond_loopback_requires_a_token():
    with pytest.raises(ValueError, match=rest.TOKEN_ENV_VAR):
        rest.RestService(lambda: FakeLauncher(FakeBrowser()), host="0.0.0.0")
    rest.RestService(lambda: FakeLauncher(FakeBrowser()), host="0.0.0.0", token="s3cret",
                     allow_private_networks=True)


def test_the_web_page_loads_without_a_token_under_a_strict_policy():
    service, _ = make_service(token="s3cret")
    with service:
        with urllib.request.urlopen(service.url + "/", timeout=10) as response:
            page = response.read()
            headers = response.headers
    assert page == rest.PAGE
    assert b"Token (required)" in page
    assert b"-H 'Content-Type: application/json'" in page
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert "connect-src 'self'" in headers["Content-Security-Policy"]


def test_the_api_description_and_its_docs_load_without_a_token():
    service, _ = make_service(token="s3cret", timeout=45)
    with service:
        with urllib.request.urlopen(service.url + "/openapi.json", timeout=10) as response:
            spec = json.loads(response.read())
        with urllib.request.urlopen(service.url + "/docs", timeout=10) as response:
            docs = response.read()
            policy = response.headers["Content-Security-Policy"]
    body = spec["paths"]["/jobs"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert body == rest.job_schema(45)
    assert body["properties"]["timeout"]["maximum"] == 45
    assert spec["security"] == [{"token": []}]
    assert docs == rest.DOCS_PAGE and b"/openapi.json" in docs
    assert "default-src 'none'" in policy and "connect-src 'self'" in policy


@pytest.mark.parametrize("operation", rest.OPERATIONS)
def test_a_job_resubmitted_from_its_status_is_accepted(operation):
    # The web page shows each job as API calls built from its status, defaults included.
    service, _ = make_service()
    with service:
        _, job = request(service, "POST", "/jobs", {"url": PUBLIC_URL, "operation": operation})
        wait_finished(service, job["id"])
        fields = {key: value for key, value in job.items() if key not in ("id", "status", "error") and value is not None}
        status, response = request(service, "POST", "/jobs", fields)
    assert status == 202, response
