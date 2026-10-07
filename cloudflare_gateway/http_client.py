"""Minimal HTTP client for the Cloudflare Gateway API.

Built only on the standard library, but structured the way ``requests`` /
``urllib3`` are: a :class:`Session` that keeps connections alive across calls,
a :class:`Response` object instead of a raw tuple, and a :class:`Retry` policy
object instead of scattered constants.
"""

from __future__ import annotations

import atexit
import gzip
import http.client
import json
import random
import socket
import ssl
import time
import zlib
from functools import wraps
from io import BytesIO
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

from . import config
from .log import fatal, info, warn


class HTTPException(Exception):
    """Detailed HTTP error carrying request context."""

    def __init__(
        self,
        message: str = "",
        *,
        method: str = "",
        url: str = "",
        status_code: int = 0,
        reason: str = "",
        headers: Optional[dict] = None,
        body: str = "",
    ) -> None:
        super().__init__(message)
        self.method = method
        self.url = url
        self.status_code = status_code
        self.reason = reason
        self.headers = headers or {}
        self.body = body


class RateLimitException(HTTPException):
    """Raised on HTTP 429."""

    def __init__(
        self,
        message: str = "",
        *,
        retry_after: Optional[int] = None,
        method: str = "",
        url: str = "",
        status_code: int = 429,
        reason: str = "Too Many Requests",
        headers: Optional[dict] = None,
        body: str = "",
    ) -> None:
        super().__init__(
            message,
            method=method,
            url=url,
            status_code=status_code,
            reason=reason,
            headers=headers,
            body=body,
        )
        self.retry_after = retry_after


class NotFoundException(HTTPException):
    """Raised on HTTP 404.

    The list/rule id in our cache no longer exists on Cloudflare (for example
    because it was deleted manually). Recoverable: callers should evict the
    stale id and recreate the resource instead of treating it as fatal.
    """


def parse_retry_after(value: Optional[str]) -> Optional[int]:
    """Return the ``Retry-After`` header as whole seconds, or ``None``.

    Falls back to ``None`` for missing/unparseable values so callers can use
    their own default instead of guessing.
    """
    if not value:
        return None
    try:
        return max(1, int(float(value)))
    except (TypeError, ValueError):
        return None


class Response:
    """A small stand-in for :class:`requests.Response`."""

    def __init__(
        self, status_code: int, reason: str, header_pairs, raw_content: bytes
    ) -> None:
        self.status_code = status_code
        self.reason = reason
        self._headers = header_pairs
        self._decoded_content: Optional[bytes] = None
        self.raw_content = raw_content

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        name = name.lower()
        for key, value in self._headers:
            if key.lower() == name:
                return value
        return default

    @property
    def content(self) -> bytes:
        """Body bytes after undoing ``Content-Encoding``, if any."""
        if self._decoded_content is not None:
            return self._decoded_content

        data = self.raw_content
        encoding = self.get_header("Content-Encoding")
        if data and encoding == "gzip":
            with gzip.GzipFile(fileobj=BytesIO(data)) as buffer:
                data = buffer.read()
        elif data and encoding == "deflate":
            data = zlib.decompress(data)

        self._decoded_content = data
        return data

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="ignore")

    def json(self) -> dict:
        return json.loads(self.content.decode("utf-8"))

    @property
    def ok(self) -> bool:
        return self.status_code < 400


class Session:
    """A minimal ``requests.Session``-alike with keep-alive pooling.

    Connections are pooled per host and reused across calls. A pooled
    connection can be closed by the server or OS between calls, so a request
    is allowed exactly one silent reconnect-and-retry per host before the
    failure is surfaced to the caller.
    """

    _STALE_CONNECTION_ERRORS = (
        http.client.RemoteDisconnected,
        ConnectionResetError,
        BrokenPipeError,
    )
    _NETWORK_ERRORS = (
        http.client.HTTPException,
        ssl.SSLError,
        socket.timeout,
        OSError,
    )

    def __init__(self, default_timeout: int = 20) -> None:
        self.default_timeout = default_timeout
        self._connections: dict = {}

    def _get_connection(
        self, scheme: str, netloc: str, timeout: int
    ) -> http.client.HTTPConnection:
        key = (scheme, netloc)
        connection = self._connections.get(key)
        if connection is None:
            if scheme == "https":
                context = ssl.create_default_context()
                connection = http.client.HTTPSConnection(
                    netloc, context=context, timeout=timeout
                )
            else:
                connection = http.client.HTTPConnection(netloc, timeout=timeout)
            self._connections[key] = connection
        return connection

    def _drop_connection(self, scheme: str, netloc: str) -> None:
        connection = self._connections.pop((scheme, netloc), None)
        if connection is not None:
            connection.close()

    def close(self) -> None:
        for connection in self._connections.values():
            connection.close()
        self._connections.clear()

    def _request_once(
        self, scheme, netloc, method, path, body, headers, timeout
    ) -> Response:
        display_url = f"{scheme}://{netloc}{path}"
        for attempt in (1, 2):
            connection = self._get_connection(scheme, netloc, timeout)
            try:
                connection.request(method, path, body, headers)
                raw_response = connection.getresponse()
                data = raw_response.read()
                return Response(
                    raw_response.status,
                    raw_response.reason,
                    raw_response.getheaders(),
                    data,
                )
            except self._STALE_CONNECTION_ERRORS as exc:
                self._drop_connection(scheme, netloc)
                if attempt == 2:
                    message = (
                        f"Network error while requesting {method} {display_url}: {exc}"
                    )
                    warn(message)
                    raise HTTPException(
                        message, method=method, url=display_url
                    ) from exc
            except self._NETWORK_ERRORS as exc:
                self._drop_connection(scheme, netloc)
                message = f"Network error while requesting {method} {display_url}: {exc}"
                warn(message)
                raise HTTPException(message, method=method, url=display_url) from exc

        raise HTTPException(
            "Unreachable: Session._request_once retry loop exited without a result"
        )

    def request(
        self,
        method: str,
        url: str,
        body=None,
        headers: Optional[dict] = None,
        timeout: Optional[int] = None,
        follow_redirects: bool = False,
        max_redirects: int = 5,
    ) -> Response:
        timeout = timeout or self.default_timeout
        headers = dict(headers or {})
        redirects = 0

        while True:
            parsed = urlparse(url)
            scheme = parsed.scheme or "https"
            netloc = parsed.netloc
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"

            response = self._request_once(
                scheme, netloc, method, path, body, headers, timeout
            )

            if follow_redirects and response.status_code in (301, 302, 303, 307, 308):
                location = response.get_header("Location")
                if not location:
                    return response
                redirects += 1
                if redirects > max_redirects:
                    raise HTTPException(
                        f"Too many redirects ({redirects}) while fetching {url}"
                    )
                if not urlparse(location).netloc:
                    location = urljoin(url, location)
                url = location
                continue

            return response


_shared_session = Session(default_timeout=20)
atexit.register(_shared_session.close)


def get_session() -> Session:
    """Return the process-wide shared :class:`Session`."""
    return _shared_session


def cloudflare_gateway_request(
    method: str, endpoint: str, body: Optional[str] = None, timeout: int = 20
) -> tuple[int, dict]:
    """Call the Cloudflare Gateway API and return ``(status, json_body)``."""
    headers = {
        "Authorization": f"Bearer {config.CF_API_TOKEN}",
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate",
    }

    path = config.CLOUDFLARE_API_PATH.format(account_id=config.CF_IDENTIFIER)
    path = f"{path}{endpoint}"
    url = f"https://{config.CLOUDFLARE_HOST}{path}"

    response = get_session().request(
        method, url, body=body, headers=headers, timeout=timeout
    )

    if response.status_code >= 400:
        resp_headers = {key: value for key, value in response._headers}
        error_message = (
            f"Request failed: {response.status_code} {response.reason}, "
            f"Body: {response.text} "
            f"for URL: {url}"
        )
        if response.status_code == 429:
            retry_after = parse_retry_after(response.get_header("Retry-After"))
            warn(error_message)
            raise RateLimitException(
                error_message,
                retry_after=retry_after,
                method=method,
                url=url,
                status_code=429,
                reason="Too Many Requests",
                headers=resp_headers,
                body=response.text,
            )
        if response.status_code == 404:
            warn(error_message)
            raise NotFoundException(
                error_message,
                method=method,
                url=url,
                status_code=404,
                reason="Not Found",
                headers=resp_headers,
                body=response.text,
            )
        if response.status_code in (400, 403):
            fatal(error_message)
        else:
            warn(error_message)
        raise HTTPException(
            error_message,
            method=method,
            url=url,
            status_code=response.status_code,
            reason=response.reason,
            headers=resp_headers,
            body=response.text,
        )

    try:
        return response.status_code, response.json()
    except json.JSONDecodeError:
        error_message = f"Failed to decode JSON response from {method} {url}"
        warn(error_message)
        raise HTTPException(error_message, method=method, url=url)


class Retry:
    """A retry policy: how many attempts and how long to back off."""

    def __init__(
        self, total: int = 5, backoff_factor: float = 1.0, max_backoff: float = 10.0
    ) -> None:
        self.total = total
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff

    def is_exhausted(self, attempt_number: int) -> bool:
        return attempt_number >= self.total

    def get_backoff_time(self, attempt_number: int) -> float:
        exponent = max(attempt_number - 1, 0)
        return min(
            self.backoff_factor * (2 ** random.uniform(0, exponent)), self.max_backoff
        )


# Cloudflare Gateway CI jobs run with a 30-minute timeout. If 429s were
# retried forever, a persistent rate limit would hang the job until GitHub
# kills it instead of failing with a clear error. Ten attempts (~3-4 minutes,
# including the first Retry-After cooldown) gives Cloudflare a real chance to
# recover while staying well inside that timeout.
DEFAULT_RETRY = Retry(total=5, backoff_factor=1.0, max_backoff=10.0)
RATE_LIMIT_RETRY = Retry(total=10, backoff_factor=1.0, max_backoff=10.0)


def retry_if_exception_type(exceptions) -> Callable[[BaseException], bool]:
    return lambda exc: isinstance(exc, exceptions)


def custom_stop_condition(exception: BaseException, attempt_number: int) -> bool:
    if isinstance(exception, RateLimitException):
        return RATE_LIMIT_RETRY.is_exhausted(attempt_number)
    return DEFAULT_RETRY.is_exhausted(attempt_number)


retry_config = {
    "stop": custom_stop_condition,
    "wait": lambda attempt_number: DEFAULT_RETRY.get_backoff_time(attempt_number),
    "retry": retry_if_exception_type((HTTPException,)),
    "before_sleep": lambda retry_state: info(
        f"[·] Retrying (attempt {retry_state['attempt_number']})"
    ),
}


def retry(stop=None, wait=None, retry=None, after=None, before_sleep=None):
    """Retry decorator modelled loosely on ``urllib3.util.retry.Retry``."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt_number = 0
            first_rate_limit_encountered = False
            while True:
                try:
                    attempt_number += 1
                    return func(*args, **kwargs)
                except NotFoundException:
                    # Not transient: raise immediately so the caller can evict
                    # the stale id from cache and self-heal.
                    raise
                except RateLimitException as exc:
                    if not first_rate_limit_encountered:
                        # First 429: honour Cloudflare's Retry-After when
                        # present, otherwise fall back to a 2-minute cooldown.
                        first_rate_limit_encountered = True
                        wait_time = exc.retry_after or 120
                        info(
                            f"[·] Rate limited by Cloudflare — sleeping "
                            f"{wait_time}s before retrying"
                        )
                        time.sleep(wait_time)
                    else:
                        if stop and stop(exc, attempt_number):
                            raise
                        if before_sleep:
                            before_sleep({"attempt_number": attempt_number})
                        wait_time = wait(attempt_number) if wait else 1
                        time.sleep(wait_time)
                except Exception as exc:
                    if retry and not retry(exc):
                        raise
                    if after:
                        after({"attempt_number": attempt_number, "outcome": exc})
                    if stop and stop(exc, attempt_number):
                        raise
                    if before_sleep:
                        before_sleep({"attempt_number": attempt_number})
                    wait_time = wait(attempt_number) if wait else 1
                    time.sleep(wait_time)

        return wrapper

    return decorator


class RateLimiter:
    """Pace outgoing requests to stay under Cloudflare's list rate limit."""

    def __init__(self, interval: float = 1) -> None:
        self.interval = interval
        self.timestamp = 0.0

    def wait_for_next_request(self) -> None:
        elapsed = time.time() - self.timestamp
        sleep_time = max(0.0, self.interval - elapsed)
        if sleep_time > 0:
            time.sleep(sleep_time)
        self.timestamp = time.time()


# Cloudflare's rate limit is global per API token, not per endpoint, so one
# shared limiter measures the interval against the previous request.
_shared_rate_limiter = RateLimiter(interval=1)


def rate_limited_request(func):
    """Decorator that paces calls through the shared :class:`RateLimiter`."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        _shared_rate_limiter.wait_for_next_request()
        return func(*args, **kwargs)

    return wrapper
