"""
A small REST API that runs page jobs on one shared Camoufox browser.

Clients submit a job (a URL and an operation), poll its status and fetch its
result. Every job runs in its own browser context, so jobs share no cookies or
storage, and that context is closed whether the job succeeds, fails, times out
or is cancelled by shutdown. Launch options and page scripts are deliberately
not reachable over HTTP. `GET /` serves a small web page for the same API,
`GET /openapi.json` describes it and `GET /docs` renders that description.
"""

import asyncio
import base64
import hmac
import json
import math
import os
import signal
import socket
import sys
import threading
import time
import uuid
from contextlib import AsyncExitStack
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, AsyncContextManager, Callable, Dict, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from playwright.async_api import Browser, BrowserContext

from ._rest_proxy import InvalidDestination, PublicGateway, resolve_public
from .async_api import AsyncCamoufox, AsyncNewContext

OPERATIONS = ('content', 'screenshot')
WAIT_UNTIL = ('commit', 'domcontentloaded', 'load', 'networkidle')
TOKEN_ENV_VAR = 'CAMOUFOX_REST_TOKEN'
MAX_BODY_BYTES = 16 * 1024
MAX_URL_LENGTH = 2048
MAX_SELECTOR_LENGTH = 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_ERROR_BYTES = 1024
MAX_REQUESTS = 16
REQUEST_TIMEOUT = 10.0
PROXY_SCHEMES = ('http', 'https', 'socks5')
# REST-only: close non-TCP transports and Firefox's built-in loopback proxy exemption.
PUBLIC_ONLY_PREFS = {
    'media.peerconnection.enabled': False,
    'network.proxy.allow_hijacking_localhost': True,
    'network.proxy.no_proxies_on': '',
    'network.proxy.socks_remote_dns': True,
    'network.dns.disablePrefetch': True,
    'network.prefetch-next': False,
    'network.http.speculative-parallel-limit': 0,
    'network.http.http3.enable': False,
    'network.webtransport.enabled': False,
}
PAGE = (Path(__file__).parent / 'rest.html').read_bytes()
# The page renders job results, so it may reach only this service and show only inline images.
PAGE_CSP = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
    "img-src data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
)
# Swagger UI, pinned and checked by Subresource Integrity, so the CDN can serve nothing else.
SWAGGER_UI = 'https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.33.1'
DOCS_PAGE = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Camoufox REST API</title>
<link rel="icon" href="data:,">
<link rel="stylesheet" href="{SWAGGER_UI}/swagger-ui.css"
  integrity="sha384-Ov4/wv3j2bmct8cDc5X4ngJZohVPzEmc6uDPH8WeljUxO5vtoykvMEfbu9Vh6RaW" crossorigin="anonymous">
</head>
<body>
<div id="docs"></div>
<script src="{SWAGGER_UI}/swagger-ui-bundle.js"
  integrity="sha384-ZPehFMQommnnuaZ4rpxgkgTT2DKFVp4hZC/7pLit+9Lek9T1YGSo23eHFbvNkXkw" crossorigin="anonymous"></script>
<script>
  // The web page keeps the token in this tab's sessionStorage; carry it into Authorize.
  const ui = SwaggerUIBundle({{
    url: '/openapi.json',
    dom_id: '#docs',
    onComplete: () => sessionStorage.getItem('token') && ui.preauthorizeApiKey('token', sessionStorage.getItem('token')),
  }});
</script>
</body>
</html>
""".encode()
DOCS_CSP = (
    f"default-src 'none'; script-src {SWAGGER_UI}/ 'unsafe-inline'; style-src {SWAGGER_UI}/ 'unsafe-inline'; "
    "img-src data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
)


class InvalidJob(ValueError):
    """The submitted job is malformed or not allowed."""


class BlockedURL(InvalidJob):
    """The URL does not use an allowed scheme or has no hostname."""


class JobStoreFull(RuntimeError):
    """Every job slot holds a job that has not finished yet."""


async def check_url(url: str, allow_private_networks: bool, schemes: Tuple[str, ...] = ('http', 'https')) -> None:
    """Reject bad submissions early; the gateway separately pins actual connections."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError as error:
        raise BlockedURL(f"{url!r} is not a valid URL: {error}") from error
    if parts.scheme not in schemes or not host:
        raise BlockedURL(f"{url!r} is not a {'/'.join(schemes)} URL")
    if not allow_private_networks:
        try:
            await asyncio.wait_for(resolve_public(host, port), REQUEST_TIMEOUT)
        except (InvalidDestination, asyncio.TimeoutError) as error:
            raise BlockedURL(f"blocked URL {url!r}: {error}") from error


def job_schema(max_timeout: float) -> Dict[str, Any]:
    """The JSON schema of a job submission: the one source for validation and the API docs."""
    return {
        'type': 'object',
        'required': ['url', 'operation'],
        'additionalProperties': False,
        'properties': {
            'url': {
                'type': 'string', 'minLength': 1, 'maxLength': MAX_URL_LENGTH,
                'description': 'The http(s) page to open.', 'example': 'https://example.com',
            },
            'operation': {
                'type': 'string', 'enum': list(OPERATIONS),
                'description': '`content` returns the HTML, `screenshot` a base64 PNG.',
            },
            'wait_until': {
                'type': 'string', 'enum': list(WAIT_UNTIL), 'default': 'load',
                'description': (
                    'When navigation counts as done. `domcontentloaded` does not wait for images, '
                    'frames or slow third-party resources; `networkidle` waits until no request '
                    'has run for 500 ms.'
                ),
            },
            'selector': {
                'type': 'string', 'minLength': 1, 'maxLength': MAX_SELECTOR_LENGTH,
                'description': (
                    'A Playwright selector to wait for after navigation. The result is then that '
                    'element alone: its outer HTML, or a screenshot of it, once visible.'
                ),
                'example': '#content',
            },
            'format': {
                'type': 'string', 'enum': ['html', 'text'], 'default': 'html',
                'description': (
                    'What `content` returns: `html`, the markup, or `text`, the text a reader sees '
                    '(its `innerText`), without tags, scripts or styles. Content only.'
                ),
            },
            'full_page': {
                'type': 'boolean', 'default': False,
                'description': 'Screenshot the whole scrollable page, not only the viewport. Screenshots only.',
            },
            'os': {
                'type': 'string', 'enum': ['windows', 'macos', 'linux'],
                'description': 'The OS the job\'s fingerprint claims. Every job draws its own fingerprint; '
                'by default from any OS.',
            },
            'timezone_id': {
                'type': 'string', 'minLength': 1, 'maxLength': 64,
                'description': 'An IANA timezone, e.g. `Europe/Amsterdam`. With a `proxy`, it defaults to the '
                'timezone of the proxy\'s exit IP.',
                'example': 'Europe/Amsterdam',
            },
            'geolocation': {
                'type': 'object', 'required': ['latitude', 'longitude'], 'additionalProperties': False,
                'description': 'The position the Geolocation API reports; permission to read it is granted.',
                'properties': {
                    'latitude': {'type': 'number', 'minimum': -90, 'maximum': 90},
                    'longitude': {'type': 'number', 'minimum': -180, 'maximum': 180},
                },
            },
            'proxy': {
                'type': 'object', 'required': ['server'], 'additionalProperties': False,
                'description': 'A proxy for this job only. The fingerprint\'s WebRTC IP and timezone follow its '
                'exit IP. Requires --allow-private-networks. The password is never shown in the job\'s status.',
                'properties': {
                    'server': {
                        'type': 'string', 'minLength': 1, 'maxLength': MAX_URL_LENGTH,
                        'description': f"{', '.join(PROXY_SCHEMES)} URL", 'example': 'http://proxy.example:3128',
                    },
                    'username': {'type': 'string', 'minLength': 1, 'maxLength': 256},
                    'password': {'type': 'string', 'minLength': 1, 'maxLength': 256},
                },
            },
            'timeout': {
                'type': 'number', 'exclusiveMinimum': 0, 'maximum': max_timeout, 'default': max_timeout,
                'description': 'Seconds the job may run once started, at most the service\'s `--timeout`.',
            },
        },
    }


def _check(name: str, value: Any, rule: Dict[str, Any]) -> None:
    """Validate `value` against the subset of JSON schema that `job_schema` uses."""
    if 'enum' in rule:
        if value not in rule['enum']:
            raise InvalidJob(f"{name} must be one of {', '.join(rule['enum'])}")
    elif rule['type'] == 'object':
        if not isinstance(value, dict):
            raise InvalidJob(f"{name} must be a JSON object")
        prefix = f"{name}." if name else ''
        unknown = sorted(set(value) - set(rule['properties']))
        if unknown:
            raise InvalidJob(f"unknown field(s): {', '.join(prefix + field for field in unknown)}; see /openapi.json")
        for field in rule['required']:
            if field not in value:
                raise InvalidJob(f"{prefix}{field} is required")
        for field, item in value.items():
            _check(prefix + field, item, rule['properties'][field])
    elif rule['type'] == 'string':
        if not isinstance(value, str) or not rule['minLength'] <= len(value) <= rule['maxLength']:
            raise InvalidJob(f"{name} must be a string of {rule['minLength']} to {rule['maxLength']} characters")
    elif rule['type'] == 'boolean':
        if not isinstance(value, bool):
            raise InvalidJob(f"{name} must be true or false")
    else:
        low = rule.get('minimum', rule.get('exclusiveMinimum'))
        if (
            isinstance(value, bool) or not isinstance(value, (int, float))
            or value < low or value > rule['maximum'] or not math.isfinite(value)
            or ('exclusiveMinimum' in rule and value == low)
        ):
            bound = 'above' if 'exclusiveMinimum' in rule else 'at least'
            raise InvalidJob(f"{name} must be a number {bound} {low:g} and at most {rule['maximum']:g}")


def parse_job(body: Any, max_timeout: float) -> Dict[str, Any]:
    """Validate a job submission against `job_schema` and fill in its defaults."""
    schema = job_schema(max_timeout)
    if not isinstance(body, dict):
        raise InvalidJob('body must be a JSON object')
    _check('', body, schema)
    if body.get('format') == 'text' and body['operation'] != 'content':
        raise InvalidJob('format applies only to content')
    if body.get('full_page') and (body['operation'] != 'screenshot' or 'selector' in body):
        raise InvalidJob('full_page applies only to a screenshot without a selector')
    defaults = {name: rule['default'] for name, rule in schema['properties'].items() if 'default' in rule}
    return {**defaults, 'selector': None, 'os': None, 'timezone_id': None, 'geolocation': None, 'proxy': None, **body}


def openapi(max_timeout: float, token_required: bool) -> Dict[str, Any]:
    """The OpenAPI description of this service, served at /openapi.json."""
    error = {'type': 'object', 'properties': {'error': {'type': 'string'}}}
    job = {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'status': {'type': 'string', 'enum': ['queued', 'running', 'succeeded', 'failed']},
            'error': {'type': ['string', 'null']},
            **{name: {'type': rule['type']} for name, rule in job_schema(max_timeout)['properties'].items()},
        },
    }
    result = {
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'The final URL, after redirects.'},
            'title': {'type': 'string'},
            'html': {'type': 'string', 'description': '`content` with `format` html.'},
            'text': {'type': 'string', 'description': '`content` with `format` text.'},
            'screenshot': {'type': 'string', 'contentEncoding': 'base64', 'description': '`screenshot` only: a PNG.'},
        },
    }

    def responses(codes: Dict[str, Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
        described: Dict[str, Any] = {
            code: {'description': text, 'content': {'application/json': {'schema': schema}}}
            for code, (text, schema) in codes.items()
        }
        if token_required:
            described['401'] = {'description': 'Missing or wrong bearer token.'}
        return described

    job_id = [{'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}]
    spec: Dict[str, Any] = {
        'openapi': '3.1.0',
        'info': {
            'title': 'Camoufox REST API',
            'version': '1',
            'description': (
                'Public-only page jobs through a DNS-pinned TCP gateway by default. Submit a job, '
                'poll its status, then fetch its bounded result.'
            ),
        },
        'paths': {
            '/jobs': {'post': {
                'summary': 'Submit a job',
                'requestBody': {'required': True, 'content': {'application/json': {'schema': job_schema(max_timeout)}}},
                'responses': responses({
                    '202': ('The job, queued.', job),
                    '400': ('The body is invalid, or the URL is blocked.', error),
                    '403': ('The browser Origin does not match the listener.', error),
                    '413': ('The submission exceeds the body limit.', error),
                    '415': ('Content-Type must be application/json.', error),
                    '503': ('Every job slot holds an unfinished job; retry later.', error),
                }),
            }},
            '/jobs/{id}': {'get': {
                'summary': "A job's status",
                'parameters': job_id,
                'responses': responses({'200': ('The job.', job), '404': ('No such job.', error)}),
            }},
            '/jobs/{id}/result': {'get': {
                'summary': "A job's result",
                'parameters': job_id,
                'responses': responses({
                    '200': ('The result.', result),
                    '404': ('No such job.', error),
                    '409': ('The job has not succeeded; its status and error.', job),
                }),
            }},
        },
    }
    if token_required:
        spec['components'] = {'securitySchemes': {'token': {'type': 'http', 'scheme': 'bearer'}}}
        spec['security'] = [{'token': []}]
    return spec


@dataclass
class Job:
    id: str
    params: Dict[str, Any]
    status: str = 'queued'  # queued -> running -> succeeded | failed
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    task: Optional['asyncio.Task[None]'] = None

    @property
    def finished(self) -> bool:
        return self.status in ('succeeded', 'failed')

    def describe(self) -> Dict[str, Any]:
        params = dict(self.params)
        if params['proxy']:
            params['proxy'] = {key: value for key, value in params['proxy'].items() if key != 'password'}
        return {'id': self.id, **params, 'status': self.status, 'error': self.error}


class JobRunner:
    """Owns the job records and runs them on `browser`. Lives on one event loop."""

    def __init__(
        self,
        browser: Browser,
        *,
        concurrency: int,
        max_jobs: int,
        timeout: float,
        allow_private_networks: bool,
        max_result_bytes: int = MAX_RESULT_BYTES,
    ) -> None:
        self._browser = browser
        self._slots = asyncio.Semaphore(concurrency)
        self._max_jobs = max_jobs
        self._timeout = timeout
        self._allow_private_networks = allow_private_networks
        self._max_result_bytes = max_result_bytes
        self._jobs: Dict[str, Job] = {}

    async def submit(self, body: Any) -> Dict[str, Any]:
        params = parse_job(body, self._timeout)
        await check_url(params['url'], self._allow_private_networks)
        if params['proxy']:
            if not self._allow_private_networks:
                raise InvalidJob('per-job proxy requires --allow-private-networks')
            await check_url(params['proxy']['server'], self._allow_private_networks, PROXY_SCHEMES)

        if len(self._jobs) >= self._max_jobs:
            oldest_finished = next((job for job in self._jobs.values() if job.finished), None)
            if oldest_finished is None:
                raise JobStoreFull(f"all {self._max_jobs} job slots are in use; retry later")
            del self._jobs[oldest_finished.id]

        job = Job(id=uuid.uuid4().hex, params=params)
        self._jobs[job.id] = job
        job.task = asyncio.create_task(self._run(job))
        return job.describe()

    async def describe(self, job_id: str) -> Optional[Dict[str, Any]]:
        job = self._jobs.get(job_id)
        return job.describe() if job else None

    async def result(self, job_id: str) -> Optional[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]]:
        job = self._jobs.get(job_id)
        return (job.describe(), job.result) if job else None

    async def close(self) -> None:
        """Cancel every unfinished job and wait for its context to close."""
        tasks = [job.task for job in self._jobs.values() if job.task and not job.task.done()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _run(self, job: Job) -> None:
        try:
            async with self._slots:
                job.status = 'running'
                job.result = await self._execute(job)
                job.status = 'succeeded'
        except asyncio.CancelledError:
            job.status, job.error = 'failed', 'cancelled: the service is shutting down'
            raise
        except asyncio.TimeoutError:
            waited = f"wait_until {job.params['wait_until']}"
            if job.params['selector']:
                waited += f" and selector {job.params['selector']!r}"
            job.status, job.error = 'failed', f"timed out after {job.params['timeout']:g}s ({waited})"
        except Exception as error:
            job.status, job.error = 'failed', f"{type(error).__name__}: {error}"
        finally:
            if job.error:
                job.error = job.error.encode('utf-8', errors='replace')[
                    :min(MAX_ERROR_BYTES, self._max_result_bytes)
                ].decode(
                    'utf-8', errors='ignore'
                )
            job.task = None

    async def _execute(self, job: Job) -> Dict[str, Any]:
        # The context is created outside the timeout so a timeout can never
        # orphan a context that was still being created.
        options = {name: job.params[name] for name in ('os', 'timezone_id', 'geolocation', 'proxy')}
        async with AsyncExitStack() as stack:
            if not self._allow_private_networks:
                gateway = await stack.enter_async_context(PublicGateway())
                options['_transport_proxy'] = {'server': f'socks5://127.0.0.1:{gateway.port}'}
            context = await AsyncNewContext(self._browser, **{name: value for name, value in options.items() if value})
            try:
                return await asyncio.wait_for(self._operate(context, job.params), job.params['timeout'])
            finally:
                await context.close()

    async def _operate(self, context: BrowserContext, params: Dict[str, Any]) -> Dict[str, Any]:
        page = await context.new_page()
        # The job's own timeout bounds every step, rather than Playwright's 30s default.
        page.set_default_timeout(0)
        await page.goto(params['url'], wait_until=params['wait_until'])
        screenshot = params['operation'] == 'screenshot'
        element = None
        if params['selector']:
            element = await page.wait_for_selector(
                params['selector'], state='visible' if screenshot else 'attached'
            )
        result: Dict[str, Any] = {'url': page.url, 'title': await page.title()}
        if params['format'] == 'text':
            result['text'] = await (element.inner_text() if element else page.inner_text('body'))
        elif not screenshot:
            result['html'] = await (element.evaluate('e => e.outerHTML') if element else page.content())
        else:
            image = await (element.screenshot() if element else page.screenshot(full_page=params['full_page']))
            result['screenshot'] = base64.b64encode(image).decode()

        if len(json.dumps(result).encode()) > self._max_result_bytes:
            raise InvalidJob(f"result exceeds {self._max_result_bytes} bytes")
        return result


def _authority_key(authority: str, *, require_port: bool = False) -> Tuple[str, int]:
    if not isinstance(authority, str):
        raise ValueError(f"invalid authority {authority!r}")
    try:
        parsed = urlsplit('http://' + authority)
        host = parsed.hostname
        port = parsed.port
        if (
            not authority or any(char.isspace() for char in authority)
            or parsed.username is not None or parsed.password is not None
            or parsed.netloc != authority or parsed.path or parsed.query or parsed.fragment or not host
            or (require_port and port is None) or port == 0
        ):
            raise ValueError("invalid authority")
    except ValueError as error:
        raise ValueError(f"invalid authority {authority!r}") from error
    return host.lower(), port if port is not None else 80


class RestService:
    """
    The REST API: an HTTP server plus the event loop that owns the browser.

    Use as a context manager. Entering binds the port and launches the browser;
    exiting stops accepting requests, cancels unfinished jobs and closes the
    browser.

    In public-only mode, `launcher` must accept `firefox_user_prefs` and forward
    them unchanged to a fresh AsyncCamoufox browser. It must not supply a
    persistent context, an existing browser, or a launch-level proxy.
    """

    def __init__(
        self,
        launcher: Callable[..., AsyncContextManager[Browser]],
        *,
        host: str = '127.0.0.1',
        port: int = 8000,
        token: Optional[str] = None,
        concurrency: int = 2,
        max_jobs: int = 100,
        timeout: float = 30.0,
        allow_private_networks: bool = False,
        max_result_bytes: int = MAX_RESULT_BYTES,
        max_requests: int = MAX_REQUESTS,
        request_timeout: float = REQUEST_TIMEOUT,
        trusted_authorities: Sequence[str] = (),
    ) -> None:
        if (
            not isinstance(token, str) or not token
            or any(not 33 <= ord(char) <= 126 for char in token)
        ):
            raise ValueError(
                f"Refusing to serve on {host!r} without an explicit printable ASCII token "
                f"(no whitespace). Set {TOKEN_ENV_VAR}."
            )
        for name, value in (
            ('concurrency', concurrency), ('max_jobs', max_jobs),
            ('max_result_bytes', max_result_bytes), ('max_requests', max_requests),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name, value in (('timeout', timeout), ('request_timeout', request_timeout)):
            if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        self._launcher = launcher
        self._address = (host, port)
        if isinstance(trusted_authorities, str):
            raise ValueError("trusted_authorities must be a sequence of host:port authorities")
        self._trusted_authorities: Set[Tuple[str, int]] = {
            _authority_key(authority, require_port=True) for authority in trusted_authorities
        }
        self._token = token
        self.max_requests = max_requests
        self.request_timeout = request_timeout
        self.openapi = openapi(timeout, token_required=bool(token))
        self._runner_options = dict(
            concurrency=concurrency,
            max_jobs=max_jobs,
            timeout=timeout,
            allow_private_networks=allow_private_networks,
            max_result_bytes=max_result_bytes,
        )
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None
        self._browser_cm: Optional[AsyncContextManager[Browser]] = None
        self._httpd: Optional['_HTTPServer'] = None
        self._http_thread: Optional[threading.Thread] = None
        self.jobs: Optional[JobRunner] = None

    @property
    def url(self) -> str:
        assert self._httpd is not None
        host, port = self._httpd.server_address[:2]
        return f"http://{'[' + host + ']' if ':' in host else host}:{port}"

    def authorizes(self, authorization: str) -> bool:
        """Whether an Authorization header value grants access."""
        assert self._token is not None
        return hmac.compare_digest(authorization.encode(), ('Bearer ' + self._token).encode())

    def call(self, coro: Any) -> Any:
        """Run `coro` on the service's event loop and return its result."""
        assert self._loop is not None
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def __enter__(self) -> 'RestService':
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._loop_thread.start()
        try:
            self._httpd = _HTTPServer(self._address, self)
            self.jobs = self.call(self._open())
            self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._http_thread.start()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *_exc: Any) -> None:
        try:
            if self._httpd is not None:
                if self._http_thread is not None:
                    self._httpd.shutdown()
                # Waits for in-flight requests, which still need the loop.
                self._httpd.server_close()
            self.call(self._close())
        finally:
            assert self._loop is not None and self._loop_thread is not None
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._loop_thread.join()
            self._loop.close()

    async def _open(self) -> JobRunner:
        # Custom public-only launchers must forward these prefs to a fresh Camoufox.
        prefs = {} if self._runner_options['allow_private_networks'] else PUBLIC_ONLY_PREFS
        self._browser_cm = self._launcher(**({'firefox_user_prefs': dict(prefs)} if prefs else {}))
        browser = await self._browser_cm.__aenter__()
        return JobRunner(browser, **self._runner_options)

    async def _close(self) -> None:
        try:
            if self.jobs is not None:
                await self.jobs.close()
        finally:
            if self._browser_cm is not None:
                await self._browser_cm.__aexit__(None, None, None)


class _HTTPServer(ThreadingHTTPServer):
    # Join request threads on close, so none outlives the event loop it calls into.
    daemon_threads = False

    def __init__(self, address: Any, service: RestService) -> None:
        self.service = service
        self._requests = threading.BoundedSemaphore(service.max_requests)
        if ':' in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, _Handler)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._requests.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._requests.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._requests.release()


class _Handler(BaseHTTPRequestHandler):
    server: _HTTPServer

    def setup(self) -> None:
        self.request.settimeout(self.server.service.request_timeout)
        super().setup()
        # A socket inactivity timeout alone lets a slow sender retain a worker forever.
        self._deadline = threading.Timer(
            self.server.service.request_timeout, self._expire
        )
        self._deadline.daemon = True
        self._deadline.start()

    def _expire(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self) -> None:
        self._deadline.cancel()
        super().finish()

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        self.close_connection = True
        if self.headers.defects or any(
            self.headers.get_all(name)
            for name in ('Forwarded', 'X-Forwarded-Host', 'X-Forwarded-Proto', 'X-Forwarded-Port')
        ):
            self._send(400, {'error': 'untrusted request headers'})
            return False
        for name in ('Host', 'Origin', 'Authorization', 'Content-Length', 'Content-Type'):
            if len(self.headers.get_all(name, [])) > 1:
                self._send(400, {'error': f"duplicate {name}"})
                return False
        if self.headers.get_all('Transfer-Encoding') or self.headers.get_all('Expect'):
            self._send(400, {'error': 'unsupported request framing'})
            return False
        try:
            authority = self.headers.get('Host', '')
            request_authority = _authority_key(authority)
            bound_host, bound_port = self.connection.getsockname()[:2]
            allowed = {(bound_host.lower(), bound_port)}
            configured = self.server.service._address[0].lower()
            if configured not in ('0.0.0.0', '::'):
                allowed.add((configured, bound_port))
            if (
                request_authority not in allowed
                and request_authority not in self.server.service._trusted_authorities
            ):
                raise ValueError("untrusted Host")
        except ValueError:
            self._send(400, {'error': 'Host must match this listener or a trusted authority'})
            return False
        origin = self.headers.get('Origin')
        if origin is not None and origin != 'http://' + authority:
            self._send(403, {'error': 'Origin must match this listener'})
            return False
        if not self.path.startswith('/') or self.path.startswith('//'):
            self._send(400, {'error': 'request target must be relative to this listener'})
            return False
        try:
            urlsplit(self.path)
        except ValueError:
            self._send(400, {'error': 'invalid request target'})
            return False
        return True

    def handle_expect_100(self) -> bool:
        self._send(400, {'error': 'Expect is unsupported'})
        return False

    def do_POST(self) -> None:
        if not self._authorized():
            return
        if urlsplit(self.path).path != '/jobs':
            return self._send(404, {'error': 'not found'})
        if self.headers.get_content_type() != 'application/json':
            return self._send(415, {'error': 'Content-Type must be application/json'})
        raw_length = self.headers.get('Content-Length')
        if raw_length is None:
            return self._send(411, {'error': 'Content-Length is required'})
        if not raw_length.isascii() or not raw_length.isdecimal():
            return self._send(400, {'error': 'invalid Content-Length'})
        if len(raw_length) > len(str(MAX_BODY_BYTES)):
            return self._send(413, {'error': f"body must be at most {MAX_BODY_BYTES} bytes"})
        length = int(raw_length)
        if length > MAX_BODY_BYTES:
            return self._send(413, {'error': f"body must be at most {MAX_BODY_BYTES} bytes"})
        try:
            data = self.rfile.read(length)
            if len(data) != length:
                return self._send(400, {'error': 'incomplete body'})
            body = json.loads(data)
        except ValueError:
            return self._send(400, {'error': 'body is not valid JSON'})

        service = self.server.service
        assert service.jobs is not None
        try:
            job = service.call(service.jobs.submit(body))
        except InvalidJob as error:
            return self._send(400, {'error': str(error)[:MAX_ERROR_BYTES]})
        except JobStoreFull as error:
            return self._send(503, {'error': str(error)})
        self._send(202, job)

    def do_GET(self) -> None:
        # These pages hold no data, so they load without a token; the API calls they make send one.
        path = urlsplit(self.path).path
        service = self.server.service
        if path == '/':
            return self._send_page(PAGE, PAGE_CSP)
        if path == '/docs':
            return self._send_page(DOCS_PAGE, DOCS_CSP)
        if path == '/openapi.json':
            return self._send(200, service.openapi)
        if not self._authorized():
            return
        parts = path.strip('/').split('/')
        assert service.jobs is not None
        if len(parts) == 2 and parts[0] == 'jobs':
            job = service.call(service.jobs.describe(parts[1]))
            if job is None:
                return self._send(404, {'error': 'no such job'})
            return self._send(200, job)
        if len(parts) == 3 and parts[0] == 'jobs' and parts[2] == 'result':
            found = service.call(service.jobs.result(parts[1]))
            if found is None:
                return self._send(404, {'error': 'no such job'})
            job, result = found
            if job['status'] != 'succeeded':
                return self._send(409, {**job, 'error': job['error'] or f"job is {job['status']}"})
            return self._send(200, result)
        self._send(404, {'error': 'not found'})

    def _authorized(self) -> bool:
        if self.server.service.authorizes(self.headers.get('Authorization', '')):
            return True
        self._send(401, {'error': 'missing or wrong bearer token'})
        return False

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_page(self, page: bytes, policy: str) -> None:
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(page)))
        self.send_header('Content-Security-Policy', policy)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(page)


def serve(
    host: str = '127.0.0.1',
    port: int = 8000,
    *,
    concurrency: int = 2,
    max_jobs: int = 100,
    timeout: float = 30.0,
    allow_private_networks: bool = False,
    max_result_bytes: int = MAX_RESULT_BYTES,
    max_requests: int = MAX_REQUESTS,
    launch_options: Optional[Dict[str, Any]] = None,
    trusted_authorities: Sequence[str] = (),
) -> None:
    """
    Run the REST API on a headless Camoufox until interrupted or terminated.

    `launch_options` go to AsyncCamoufox, so every SDK launch option can be set
    for the service; clients can never set them.
    """
    # SIGTERM (e.g. `docker stop`) unwinds like Ctrl-C, so the browser is closed.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    options = {'headless': True, **(launch_options or {})}
    if not allow_private_networks and any(
        options.get(key) for key in ('proxy', 'from_options', 'persistent_context', 'launch_options')
    ):
        raise ValueError(
            'public-only REST requires a fresh non-persistent browser without a launch proxy, '
            'from_options or nested launch_options'
        )

    def launcher(**required: Any) -> AsyncContextManager[Browser]:
        prefs = {**(options.get('firefox_user_prefs') or {}), **required.get('firefox_user_prefs', {})}
        return AsyncCamoufox(**{**options, 'firefox_user_prefs': prefs})

    with RestService(
        launcher,
        host=host,
        port=port,
        token=os.environ.get(TOKEN_ENV_VAR) or None,
        concurrency=concurrency,
        max_jobs=max_jobs,
        timeout=timeout,
        allow_private_networks=allow_private_networks,
        max_result_bytes=max_result_bytes,
        max_requests=max_requests,
        trusted_authorities=trusted_authorities,
    ) as service:
        print(f"Camoufox REST API listening on {service.url}", flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
