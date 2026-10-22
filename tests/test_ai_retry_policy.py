"""One retry policy for Gemini, Anthropic, OpenAI and the topology chat.

Retried: 429, 502, 503, 529 and connection failures where the request was never sent. Not retried:
read timeouts, errors after the request was sent, 500, 504, 408 and other 4xx. At most 4 attempts,
30 s per wait and 60 s of waiting in total; Retry-After is honoured within those caps.
"""

from __future__ import annotations

import email.utils
import io
import json
import os
import re
import subprocess
import time
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import pytest
import requests
from urllib3.exceptions import ConnectTimeoutError, MaxRetryError, NewConnectionError, ProtocolError

from scrutics.ai import retry
from scrutics.ai.anthropic_provider import AnthropicProvider
from scrutics.ai.gemini_provider import GeminiProvider
from scrutics.ai.ollama_provider import OllamaProvider
from scrutics.ai.openai_provider import OpenAIProvider
from scrutics.ai.provider import LLMConnectionError, LLMProviderError, LLMResponseError, LLMTimeoutError
from tests.node_runtime import require_node

OK_BODY = {
    "gemini": {"candidates": [{"content": {"role": "model", "parts": [{"text": "ok"}]}}]},
    "anthropic": {"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"},
    "openai": {"choices": [{"message": {"role": "assistant", "content": "ok"}}]},
}
NAMES = {"gemini": "Gemini", "anthropic": "Anthropic", "openai": "OpenAI"}
PROVIDERS = list(OK_BODY)


def _provider(name):
    return {"gemini": lambda: GeminiProvider(api_key="k"),
            "anthropic": lambda: AnthropicProvider(api_key="k"),
            "openai": lambda: OpenAIProvider(api_key="k")}[name]()


def _response(status, body=None, headers=None):
    resp = mock.Mock(status_code=status, headers=headers or {}, text=json.dumps(body or {}))
    resp.json.return_value = body if body is not None else {"error": {"message": f"status {status}"}}
    return resp


def _refused():
    """The exception requests raises when the connection is refused (the request was never sent)."""
    reason = NewConnectionError(None, "Failed to establish a new connection: [Errno 111] Connection refused")
    return requests.exceptions.ConnectionError(MaxRetryError(None, "/v1", reason=reason))


def _after_send():
    """A connection lost after the request was sent."""
    return requests.exceptions.ConnectionError(ProtocolError("Connection aborted.", ConnectionResetError(104)))


class _Sequence:
    """requests.post stand-in returning (or raising) the given outcomes in turn, the last one repeated."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def __call__(self, *args, **kwargs):
        outcome = self.outcomes[min(self.calls, len(self.outcomes) - 1)]
        self.calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


@pytest.fixture
def sleeps():
    recorded = []
    with mock.patch("time.sleep", side_effect=recorded.append):
        yield recorded


def _chat(name, post, callback=None):
    provider = _provider(name)
    if callback is not None:
        provider.set_retry_callback(callback)
    with mock.patch("requests.post", post):
        return provider.chat([{"role": "user", "content": "hi"}])


def test_the_policy_matches_the_contract():
    assert retry.RETRY_STATUSES == (429, 502, 503, 529)
    assert (retry.MAX_ATTEMPTS, retry.MAX_WAIT, retry.MAX_TOTAL_WAIT) == (4, 30.0, 60.0)


@pytest.mark.parametrize("name", PROVIDERS)
@pytest.mark.parametrize("status", [429, 502, 503, 529])
def test_a_retried_status_then_success_returns_the_answer(name, status, sleeps):
    progress = []
    post = _Sequence(_response(status), _response(200, OK_BODY[name]))
    assert _chat(name, post, lambda a, t, d, reason="": progress.append((a, t, d, reason))) == "ok"
    assert post.calls == 2 and len(sleeps) == 1 and 0 < sleeps[0] <= retry.MAX_WAIT
    assert progress[0][:2] == (2, 4) and progress[0][2] == sleeps[0]
    assert f"{NAMES[name]} returned HTTP {status} ({retry.STATUS_TEXT[status]})" in progress[0][3]
    assert progress[1][2] == 0.0


@pytest.mark.parametrize("name", PROVIDERS)
def test_503_on_every_attempt_ends_with_a_message_inside_the_caps(name, sleeps):
    post = _Sequence(_response(503))
    with pytest.raises(LLMResponseError) as info:
        _chat(name, post)
    assert post.calls == retry.MAX_ATTEMPTS
    assert len(sleeps) == 3 and max(sleeps) <= retry.MAX_WAIT and sum(sleeps) <= retry.MAX_TOTAL_WAIT
    message = str(info.value)
    assert f"{NAMES[name]} still returned HTTP 503 (service unavailable) after 4 attempts over" in message
    assert "wait a few minutes and try again" in message


@pytest.mark.parametrize("name", PROVIDERS)
def test_429_on_every_attempt_points_to_quota(name, sleeps):
    with pytest.raises(LLMResponseError) as info:
        _chat(name, _Sequence(_response(429)))
    assert "HTTP 429 (rate limit or quota reached) after 4 attempts" in str(info.value)
    assert "rate limits and quota" in str(info.value)


@pytest.mark.parametrize("name", PROVIDERS)
@pytest.mark.parametrize("status", [400, 401, 403, 404, 408, 500, 504])
def test_other_statuses_fail_at_once(name, status, sleeps):
    post = _Sequence(_response(status))
    with pytest.raises(LLMResponseError):
        _chat(name, post)
    assert post.calls == 1 and sleeps == []


@pytest.mark.parametrize("name", PROVIDERS)
@pytest.mark.parametrize("exc,error_type", [
    (requests.exceptions.ReadTimeout("read timed out"), LLMTimeoutError),
    (_after_send(), LLMConnectionError),
    (requests.exceptions.SSLError("certificate verify failed"), LLMConnectionError),
    (requests.exceptions.ProxyError("proxy refused"), LLMConnectionError),
    (requests.exceptions.ChunkedEncodingError("incomplete"), LLMProviderError),
], ids=["read-timeout", "lost-after-send", "ssl", "proxy", "chunked"])
def test_errors_after_the_request_may_have_been_sent_are_not_retried(name, exc, error_type, sleeps):
    post = _Sequence(exc)
    with pytest.raises(error_type):
        _chat(name, post)
    assert post.calls == 1 and sleeps == []


@pytest.mark.parametrize("name", PROVIDERS)
@pytest.mark.parametrize("exc", [_refused(), requests.exceptions.ConnectTimeout(
    MaxRetryError(None, "/v1", reason=ConnectTimeoutError(None, "connect timed out")))], ids=["refused", "connect-timeout"])
def test_a_request_that_was_never_sent_is_retried(name, exc, sleeps):
    post = _Sequence(exc, _response(200, OK_BODY[name]))
    assert _chat(name, post) == "ok"
    assert post.calls == 2 and len(sleeps) == 1


@pytest.mark.parametrize("name", PROVIDERS)
def test_a_connection_refused_on_every_attempt_says_so(name, sleeps):
    post = _Sequence(_refused())
    with pytest.raises(LLMConnectionError) as info:
        _chat(name, post)
    assert post.calls == 4
    assert f"Cannot connect to {NAMES[name]} after 4 attempts" in str(info.value)
    assert "Connection refused" in str(info.value)


@pytest.mark.parametrize("name", PROVIDERS)
def test_retry_after_seconds_is_honoured(name, sleeps):
    post = _Sequence(_response(503, headers={"Retry-After": "7"}), _response(200, OK_BODY[name]))
    assert _chat(name, post) == "ok"
    assert sleeps == [7.0]


def test_retry_after_as_an_http_date_is_honoured(sleeps):
    when = email.utils.formatdate(time.time() + 12, usegmt=True)
    post = _Sequence(_response(429, headers={"Retry-After": when}), _response(200, OK_BODY["anthropic"]))
    assert _chat("anthropic", post) == "ok"
    assert 9 <= sleeps[0] <= 12


@pytest.mark.parametrize("name", PROVIDERS)
def test_a_wait_longer_than_the_cap_stops_and_says_so(name, sleeps):
    post = _Sequence(_response(429, headers={"Retry-After": "120"}))
    with pytest.raises(LLMResponseError) as info:
        _chat(name, post)
    assert post.calls == 1 and sleeps == []
    assert "asked to wait 120s, longer than Scrutics waits (30s)" in str(info.value)


def test_the_total_wait_cap_stops_before_passing_60_seconds(sleeps):
    post = _Sequence(_response(503, headers={"Retry-After": "25"}))
    with pytest.raises(LLMResponseError) as info:
        _chat("openai", post)
    assert sleeps == [25.0, 25.0] and post.calls == 3
    assert "waiting 25s more would pass Scrutics' 60s limit on retries" in str(info.value)


def test_gemini_retry_info_is_honoured(sleeps):
    body = {"error": {"status": "RESOURCE_EXHAUSTED", "details": [
        {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "3s"}]}}
    post = _Sequence(_response(429, body), _response(200, OK_BODY["gemini"]))
    assert _chat("gemini", post) == "ok"
    assert sleeps == [3.0]


@pytest.mark.parametrize("error", ["rate limited", None, ["x"]])
def test_gemini_429_whose_error_is_not_an_object_backs_off_without_crashing(error, sleeps):
    post = _Sequence(_response(429, {"error": error}), _response(200, OK_BODY["gemini"]))
    assert _chat("gemini", post) == "ok"
    assert len(sleeps) == 1 and 1.0 <= sleeps[0] <= 1.5


def test_gemini_429_with_a_string_error_on_every_attempt_ends_with_the_message(sleeps):
    with pytest.raises(LLMResponseError) as info:
        _chat("gemini", _Sequence(_response(429, {"error": "rate limited"})))
    assert "after 4 attempts" in str(info.value)


def test_a_streamed_openai_request_is_retried_before_reading_the_body(sleeps):
    first = _response(503)
    stream = mock.Mock(status_code=200, headers={})
    stream.iter_lines.return_value = iter(['data: {"choices": [{"delta": {"content": "ok"}}]}', "data: [DONE]"])
    post = _Sequence(first, stream)
    provider = OpenAIProvider(api_key="k")
    with mock.patch("requests.post", post):
        assert "".join(provider.chat([{"role": "user", "content": "hi"}], stream=True)) == "ok"
    assert post.calls == 2
    first.close.assert_called()


def test_ollama_keeps_its_behaviour_and_is_not_retried(sleeps):
    post = _Sequence(_response(503))
    with mock.patch("requests.post", post), pytest.raises(LLMProviderError):
        OllamaProvider().chat([{"role": "user", "content": "hi"}])
    assert post.calls == 1 and sleeps == []


def test_a_three_argument_callback_still_works(sleeps):
    calls = []
    post = _Sequence(_response(503), _response(200, OK_BODY["anthropic"]))
    assert _chat("anthropic", post, lambda attempt, total, delay: calls.append((attempt, total, delay))) == "ok"
    assert [c[:2] for c in calls] == [(2, 4), (2, 4)]


def test_the_cli_shows_the_retry_reason(tmp_path, monkeypatch, sleeps):
    from scrutics import cli

    stats = {k: 0 for k in ("asset_count", "ot_count", "it_count", "unknown_count",
                            "connection_count", "anomaly_count")}
    (tmp_path / "manifest.json").write_text(json.dumps({
        "format": "scrutics-evidence", "version": 1, "scrutics_version": "0.7",
        "created_at": "2026-10-16T00:00:00Z", "capture_started": "2026-10-16T00:00:00Z",
        "capture_ended": "2026-10-16T00:01:00Z", "sensor_id": "s", "scope": {}, "files": {}, "stats": stats}))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    cfg = {"enabled": True, "provider": "anthropic", "model": "claude-haiku-5-5", "api_key": "${ANTHROPIC_API_KEY}"}
    messages = []
    args = cli.build_parser().parse_args(["ai", "--session", str(tmp_path), "hi"])
    with mock.patch("scrutics.ai.config.load_ai_config", return_value=cfg), \
         mock.patch("requests.post", _Sequence(_response(529), _response(200, OK_BODY["anthropic"]))), \
         mock.patch.object(cli.Spinner, "set_message", lambda self, m: messages.append(m)), \
         redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        assert cli.run_ai(args) == 0
    assert any(m.startswith("Anthropic returned HTTP 529 (overloaded); waiting") for m in messages)
    assert any(m.startswith("Anthropic returned HTTP 529 (overloaded); retrying (attempt 2 of 4)") for m in messages)


# ── topology chat ─────────────────────────────────────────────────────────────

def _js_function(page, name):
    start = page.index(f"function {name}(")
    depth = 0
    for i in range(page.index("{", start), len(page)):
        depth += {"{": 1, "}": -1}.get(page[i], 0)
        if depth == 0:
            return page[start:i + 1]
    raise AssertionError(f"{name} not closed")


def _chat_js(tmp_path, function, outcomes, ok_body):
    """Run one provider call of the page in Node. outcomes: [status, headers] or "reject" per fetch."""
    node = require_node()
    from scrutics.topology import generate_topology_html

    page = generate_topology_html({"nodes": [], "edges": []})
    script = "\n".join([
        "var " + re.search(r"AI_MODELS = (\{.*?\});", page).group(0),
        "var " + re.search(r"AI_REQUEST_OPTIONS = (\{.*?\});", page).group(0),
        "var " + re.search(r"RETRY_POLICY = (\{.*?\});", page).group(0),
        re.search(r"var TOKEN_LIMIT_MESSAGE = .*?;\n", page, flags=re.S).group(0),
        f"var OUTCOMES = {json.dumps(outcomes)}; var OK_BODY = {json.dumps(ok_body)};",
        "var calls = 0, delays = [], progress = [];",
        "setTimeout = function (fn, ms) { delays.push(ms / 1000); fn(); };",
        "function fetch(url, init) {",
        "  var o = OUTCOMES[Math.min(calls, OUTCOMES.length - 1)]; calls += 1;",
        "  if (o === 'reject') return Promise.reject(new TypeError('Failed to fetch'));",
        "  var headers = o[1] || {};",
        "  return Promise.resolve({ok: o[0] === 200, status: o[0],",
        "    headers: {get: function (n) { return headers[n] || null; }},",
        "    json: function () { return Promise.resolve(o[0] === 200 ? OK_BODY : {error: {type: 'overloaded_error', message: 'busy'}}); }});",
        "}",
        *(_js_function(page, name) for name in ("errorDetail", "providerError", "retryAfterSeconds", "withRetry", function)),
        f"{function}('k', [{{role: 'user', content: 'hi'}}], function (m) {{ progress.push(m); }})",
        ".then(function (r) { done({reply: r}); }, function (e) { done({error: e.message}); });",
        "function done(x) { x.calls = calls; x.delays = delays; x.progress = progress; console.log(JSON.stringify(x)); }",
    ])
    path = tmp_path / "retry.js"
    path.write_text(script, encoding="utf-8")
    result = subprocess.run([node, str(path)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


_JS = [("callAnthropic", "Anthropic", OK_BODY["anthropic"]),
       ("callOpenAI", "OpenAI", OK_BODY["openai"]),
       ("callGemini", "Gemini", OK_BODY["gemini"])]


@pytest.mark.parametrize("function,name,ok", _JS, ids=[j[1] for j in _JS])
def test_topology_chat_retries_503_then_succeeds_and_shows_progress(tmp_path, function, name, ok):
    out = _chat_js(tmp_path, function, [[503], [200]], ok)
    assert out["reply"] == "ok" and out["calls"] == 2
    assert len(out["delays"]) == 1 and 1 <= out["delays"][0] <= 1.5
    assert out["progress"][0].startswith(f"{name} returned HTTP 503 (service unavailable); retrying in")
    assert "(attempt 2 of 4)" in out["progress"][0]


@pytest.mark.parametrize("function,name,ok", _JS, ids=[j[1] for j in _JS])
def test_topology_chat_stops_after_four_attempts(tmp_path, function, name, ok):
    out = _chat_js(tmp_path, function, [[503]], ok)
    assert out["calls"] == 4 and len(out["delays"]) == 3
    assert max(out["delays"]) <= 30 and sum(out["delays"]) <= 60
    assert out["error"].startswith(f"{name} still returned HTTP 503 (service unavailable) after 4 attempts over")
    assert "Details: overloaded_error: busy" in out["error"]


@pytest.mark.parametrize("status", [400, 401, 500, 504, 408])
def test_topology_chat_does_not_retry_other_statuses(tmp_path, status):
    out = _chat_js(tmp_path, "callAnthropic", [[status]], OK_BODY["anthropic"])
    assert out["calls"] == 1 and out["delays"] == [] and "error" in out


def test_topology_chat_honours_retry_after_and_stops_on_a_long_one(tmp_path):
    out = _chat_js(tmp_path, "callOpenAI", [[429, {"Retry-After": "4"}], [200]], OK_BODY["openai"])
    assert out["reply"] == "ok" and out["delays"] == [4]
    out = _chat_js(tmp_path, "callOpenAI", [[429, {"Retry-After": "120"}]], OK_BODY["openai"])
    assert out["calls"] == 1
    assert "asked to wait 120s, longer than Scrutics waits (30s)" in out["error"]


def test_topology_chat_total_wait_cap(tmp_path):
    out = _chat_js(tmp_path, "callGemini", [[503, {"Retry-After": "25"}]], OK_BODY["gemini"])
    assert out["delays"] == [25, 25] and out["calls"] == 3
    assert "would pass Scrutics' 60s limit on retries" in out["error"]


def test_topology_chat_does_not_retry_a_failed_fetch(tmp_path):
    out = _chat_js(tmp_path, "callAnthropic", ["reject"], OK_BODY["anthropic"])
    assert out["calls"] == 1 and out["delays"] == []
    assert out["error"].startswith("Anthropic could not be reached (Failed to fetch). Check your connection")


def test_the_page_carries_the_python_policy():
    from scrutics.topology import generate_topology_html

    page = generate_topology_html({"nodes": [], "edges": []})
    policy = json.loads(re.search(r"var RETRY_POLICY = (\{.*?\});", page).group(1))
    assert policy == retry.policy_for_browser()
