"""One retry policy for every hosted provider request.

Retried: HTTP 429 (rate limit), 503 (unavailable), 529 (Anthropic overloaded) and 502 (a gateway got
no valid response, so generation did not start), and connection failures where the request was
never sent (connection refused, name resolution failure, connect timeout). Not retried: read
timeouts, a connection lost after the request was sent, 500 and 504 (the request may already have
been processed and billed), 408 and every other status. Waits grow 1 s, 2 s, 4 s with jitter; a
Retry-After header or a provider's own retry delay is honoured instead, within the caps below.
"""

from __future__ import annotations

import email.utils
import inspect
import random
import time
from typing import Any, Callable, Iterable

from scrutics.ai.provider import LLMConnectionError, LLMResponseError
from scrutics.ai.redact import describe_error

RETRY_STATUSES = (429, 502, 503, 529)
MAX_ATTEMPTS = 4
MAX_WAIT = 30.0          # longest single wait, seconds
MAX_TOTAL_WAIT = 60.0    # longest total wait over all attempts, seconds
BASE_DELAY = 1.0
MIN_SERVER_DELAY = 0.5

STATUS_TEXT = {429: "rate limit or quota reached", 502: "bad gateway", 503: "service unavailable",
               529: "overloaded"}
ADVICE_RATE_LIMIT = "Wait, or check your plan's rate limits and quota."
ADVICE_BUSY = "The service is busy: wait a few minutes and try again."

RetryCallback = Callable[..., None]


def request_not_sent(exc: BaseException) -> bool:
    """True if a requests exception shows the request never reached the server."""
    try:
        import requests
        from urllib3.exceptions import ConnectTimeoutError, MaxRetryError, NewConnectionError
    except ImportError:
        return False
    if isinstance(exc, (requests.exceptions.ProxyError, requests.exceptions.SSLError)):
        return False
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return True
    if isinstance(exc, requests.exceptions.ConnectionError) and exc.args:
        inner = exc.args[0]
        # NewConnectionError covers a refused connection and a name that does not resolve
        return isinstance(inner, MaxRetryError) and isinstance(inner.reason, (NewConnectionError, ConnectTimeoutError))
    return False


def retry_after_seconds(resp: Any) -> float | None:
    """Seconds from a Retry-After header (delta-seconds or HTTP-date), or None."""
    headers = getattr(resp, "headers", None)
    try:
        value = headers.get("Retry-After") if headers is not None else None
    except Exception:
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    return max(0.0, when.timestamp() - time.time())


def backoff_delay(attempt: int) -> float:
    """Wait before attempt + 1: 1 s, 2 s, 4 s ... plus up to half again as jitter, within MAX_WAIT."""
    base = BASE_DELAY * (2 ** (attempt - 1))
    return min(MAX_WAIT, base + random.uniform(0.0, base / 2))


def _notify(callback: RetryCallback | None, attempt: int, delay: float, reason: str) -> None:
    """Report progress to a callback taking (attempt, total, delay) and optionally a reason."""
    if callback is None:
        return
    try:
        params = inspect.signature(callback).parameters.values()
        takes_reason = any(p.kind == p.VAR_POSITIONAL for p in params) or len(list(params)) >= 4
    except (TypeError, ValueError):
        takes_reason = False
    try:
        if takes_reason:
            callback(attempt, MAX_ATTEMPTS, delay, reason)
        else:
            callback(attempt, MAX_ATTEMPTS, delay)
    except Exception:
        pass


def _close(resp: Any) -> None:
    try:
        resp.close()
    except Exception:
        pass


def _status_line(provider: str, status: int) -> str:
    return f"{provider} returned HTTP {status} ({STATUS_TEXT.get(status, 'error')})"


def _with_detail(message: str, detail: str) -> str:
    return f"{message} Details: {detail}" if detail else message


def send_with_retry(
    send: Callable[[], Any],
    provider: str,
    *,
    on_retry: RetryCallback | None = None,
    server_delay: Callable[[Any], float | None] | None = None,
    detail: Callable[[Any], str] | None = None,
    secrets: Iterable[str] = (),
) -> Any:
    """Call send() under the retry policy and return the first response not to be retried.

    A retried status that persists, or a wait longer than the caps, raises LLMResponseError naming
    the provider, the status, the attempts and what to do. A connection failure where the request
    was not sent raises LLMConnectionError after the last attempt. Any other requests exception is
    raised unchanged for the caller to describe.
    """
    secrets = tuple(secrets)
    waited = 0.0
    attempt = 1
    while True:
        unsent: BaseException | None = None
        try:
            resp = send()
        except Exception as exc:
            if not request_not_sent(exc):
                raise
            unsent = exc
        if unsent is not None:
            # Raised outside the except block so the requests exception is not kept as context
            reason = f"Could not connect to {provider} ({type(unsent).__name__})"
            delay = backoff_delay(attempt)
            if attempt >= MAX_ATTEMPTS or waited + delay > MAX_TOTAL_WAIT:
                message = (f"Cannot connect to {provider} after {attempt} attempts over {waited:.0f}s "
                           f"({describe_error(unsent, secrets)}). Check the network connection, then try again.")
                unsent = None
                raise LLMConnectionError(message)
        else:
            status = getattr(resp, "status_code", None)
            if status not in RETRY_STATUSES:
                return resp
            reason = _status_line(provider, status)
            advice = ADVICE_RATE_LIMIT if status == 429 else ADVICE_BUSY
            info = detail(resp) if detail else ""
            if attempt >= MAX_ATTEMPTS:
                _close(resp)
                raise LLMResponseError(_with_detail(
                    f"{provider} still returned HTTP {status} ({STATUS_TEXT[status]}) after {attempt} "
                    f"attempts over {waited:.0f}s. {advice}", info))
            requested = retry_after_seconds(resp)
            if requested is None and server_delay is not None:
                requested = server_delay(resp)
            if requested is not None:
                delay = max(MIN_SERVER_DELAY, float(requested))
                if delay > MAX_WAIT:
                    _close(resp)
                    raise LLMResponseError(_with_detail(
                        f"{reason} and asked to wait {delay:.0f}s, longer than Scrutics waits "
                        f"({MAX_WAIT:.0f}s). Try again later. {advice}", info))
            else:
                delay = backoff_delay(attempt)
            if waited + delay > MAX_TOTAL_WAIT:
                _close(resp)
                raise LLMResponseError(_with_detail(
                    f"{provider} still returned HTTP {status} ({STATUS_TEXT[status]}) after {attempt} "
                    f"attempts; waiting {delay:.0f}s more would pass Scrutics' {MAX_TOTAL_WAIT:.0f}s limit "
                    f"on retries. {advice}", info))
            _close(resp)

        _notify(on_retry, attempt + 1, delay, reason)
        time.sleep(delay)
        waited += delay
        attempt += 1
        _notify(on_retry, attempt, 0.0, reason)


def policy_for_browser() -> dict[str, Any]:
    """The same policy for the topology page's chat, which cannot tell whether a failed fetch was sent."""
    return {
        "statuses": list(RETRY_STATUSES),
        "maxAttempts": MAX_ATTEMPTS,
        "maxWait": MAX_WAIT,
        "maxTotalWait": MAX_TOTAL_WAIT,
        "baseDelay": BASE_DELAY,
        "minServerDelay": MIN_SERVER_DELAY,
        "statusText": {str(k): v for k, v in STATUS_TEXT.items()},
        "adviceRateLimit": ADVICE_RATE_LIMIT,
        "adviceBusy": ADVICE_BUSY,
    }
