"""A provider API key never appears in anything Scrutics prints, logs, raises or puts in a URL.

Each AI path runs with a recognisable key while its HTTP calls are stubbed to fail in every way
requests can fail and to return error statuses whose bodies echo the request. The key must not
appear in output, log records, error messages, rendered tracebacks, exception chains or URLs.
"""

from __future__ import annotations

import http.client
import http.server
import io
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import traceback
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import pytest
import requests

from scrutics.ai import diagnostics, gemini_provider, model_discovery
from scrutics.ai.anthropic_provider import AnthropicProvider
from scrutics.ai.gemini_provider import GeminiProvider
from scrutics.ai.openai_provider import OpenAIProvider
from scrutics.ai.provider import LLMProviderError
from scrutics.ai.redact import redact

CANARY = "CANARY-sk-0123456789abcdefABCDEF"

_REQUEST_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.ConnectTimeout,
    requests.exceptions.ReadTimeout,
    requests.exceptions.SSLError,
    requests.exceptions.ProxyError,
    requests.exceptions.ChunkedEncodingError,
    requests.exceptions.RequestException,
)
_STATUSES = (400, 401, 429, 500, 503)


class _Recorder:
    """Stands in for requests.get / requests.post and keeps every URL and header it was given."""

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.calls = []
        self.bodies = []

    def __call__(self, url, *args, **kwargs):
        headers = kwargs.get("headers") or {}
        self.calls.append((url, dict(headers), kwargs.get("params")))
        self.bodies.append(kwargs.get("json"))
        return self.behaviour(url, headers)


def _raising(exc_type):
    # requests puts the request URL in its exception text; build it the same way
    def behaviour(url, headers):
        raise exc_type(f"Max retries exceeded with url: {url} (Caused by request to {url})")
    return behaviour


def _status(code):
    def behaviour(url, headers):
        resp = mock.Mock()
        resp.status_code = code
        body = {"error": {"message": f"failed for {url} with key {CANARY}", "status": "UNAVAILABLE"}}
        resp.json.return_value = body
        resp.text = json.dumps(body)
        resp.headers = {}
        return resp
    return behaviour


def _behaviours():
    for exc_type in _REQUEST_ERRORS:
        yield exc_type.__name__, _raising(exc_type)
    for code in _STATUSES:
        yield f"HTTP {code}", _status(code)


_BEHAVIOURS = list(_behaviours())


def _exception_texts(exc):
    """Every message in the exception chain plus the traceback Python would print for it."""
    texts = ["".join(traceback.format_exception(type(exc), exc, exc.__traceback__))]
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        texts.append(f"{type(exc).__name__}: {exc}")
        exc = exc.__cause__ or exc.__context__
    return texts


def _assert_clean(*texts):
    for text in texts:
        assert CANARY not in str(text)


def _assert_urls_clean(recorder):
    for url, _headers, params in recorder.calls:
        _assert_clean(url, params)


def _providers():
    return {
        "gemini": lambda: GeminiProvider(model="gemini-3.8-flash", api_key=CANARY),
        "anthropic": lambda: AnthropicProvider(model="claude-haiku-4-5", api_key=CANARY),
        "openai": lambda: OpenAIProvider(model="gpt-4o-mini", api_key=CANARY),
    }


@pytest.fixture(autouse=True)
def _no_sleep():
    with mock.patch("time.sleep"):
        yield


@pytest.fixture
def debug_logs():
    records = []

    class _Keep(logging.Handler):
        def emit(self, record):
            records.append(self.format(record))

    handler = _Keep(level=logging.DEBUG)
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)


@pytest.mark.parametrize("provider_name", ["gemini", "anthropic", "openai"])
@pytest.mark.parametrize("label,behaviour", _BEHAVIOURS, ids=[b[0] for b in _BEHAVIOURS])
def test_provider_errors_never_carry_the_key(provider_name, label, behaviour, debug_logs):
    provider = _providers()[provider_name]()
    recorder = _Recorder(behaviour)
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("requests.post", recorder), redirect_stdout(out), redirect_stderr(err):
        with pytest.raises(LLMProviderError) as info:
            provider.chat([{"role": "user", "content": "hi"}])
    _assert_clean(out.getvalue(), err.getvalue(), *debug_logs, *_exception_texts(info.value))
    _assert_urls_clean(recorder)


_NETWORK_REASON = "peer refused the connection (errno 111)"


def _network_failure(exc_type):
    def behaviour(url, headers):
        raise exc_type(f"{_NETWORK_REASON} for {url} key={CANARY} Authorization: Bearer {CANARY}")
    return behaviour


@pytest.mark.parametrize("provider_name", ["gemini", "anthropic", "openai"])
@pytest.mark.parametrize("exc_type", _REQUEST_ERRORS, ids=[e.__name__ for e in _REQUEST_ERRORS])
def test_provider_network_errors_keep_the_type_and_the_redacted_reason(provider_name, exc_type):
    provider = _providers()[provider_name]()
    with mock.patch("requests.post", _Recorder(_network_failure(exc_type))):
        with pytest.raises(LLMProviderError) as info:
            provider.chat([{"role": "user", "content": "hi"}])
    message = str(info.value)
    assert f"{exc_type.__name__}: {_NETWORK_REASON}" in message
    _assert_clean(message)


@pytest.mark.parametrize("provider_name", ["gemini", "anthropic", "openai"])
@pytest.mark.parametrize("exc_type", _REQUEST_ERRORS, ids=[e.__name__ for e in _REQUEST_ERRORS])
def test_diagnose_network_errors_keep_the_type_and_the_redacted_reason(provider_name, exc_type):
    # Gemini fails at its model check (GET); the other providers at the first generation (POST)
    failing = _network_failure(exc_type)
    get_behaviour = failing if provider_name == "gemini" else _status(200)
    rc, output, _getter, _poster = _run_diagnose(provider_name, get_behaviour, failing)
    assert rc == 1
    assert f"{exc_type.__name__}: {_NETWORK_REASON}" in output
    _assert_clean(output)


def test_gemini_key_travels_only_in_the_header():
    provider = _providers()["gemini"]()
    recorder = _Recorder(_status(503))
    with mock.patch("requests.post", recorder), pytest.raises(LLMProviderError):
        provider.chat([{"role": "user", "content": "hi"}])
    assert recorder.calls
    for url, headers, _params in recorder.calls:
        assert CANARY not in url
        assert headers.get("x-goog-api-key") == CANARY


@pytest.mark.parametrize("provider_name", ["gemini", "openai", "anthropic"])
@pytest.mark.parametrize("label,behaviour", _BEHAVIOURS, ids=[b[0] for b in _BEHAVIOURS])
def test_model_discovery_never_carries_the_key(provider_name, label, behaviour, debug_logs):
    recorder = _Recorder(behaviour)
    out = io.StringIO()
    with mock.patch("requests.get", recorder), redirect_stdout(out), redirect_stderr(out):
        models = model_discovery.fetch_models(provider_name, CANARY, "", timeout=1.0)
    _assert_clean(out.getvalue(), *debug_logs, *models)
    _assert_urls_clean(recorder)


def _run_diagnose(provider_name, get_behaviour, post_behaviour):
    buf = io.StringIO()
    getter, poster = _Recorder(get_behaviour), _Recorder(post_behaviour)
    cfg = {"provider": provider_name, "model": "m-1", "api_key": CANARY}
    with mock.patch.object(diagnostics.socket, "gethostbyname", return_value="0.0.0.0"), \
         mock.patch.object(diagnostics.socket, "create_connection"), \
         mock.patch.object(diagnostics.ssl, "create_default_context"), \
         mock.patch("requests.get", getter), mock.patch("requests.post", poster), \
         redirect_stderr(buf):
        rc = diagnostics.run_ai_diagnostics(cfg_override=cfg, stream=buf)
    return rc, buf.getvalue(), getter, poster


@pytest.mark.parametrize("label,behaviour", _BEHAVIOURS, ids=[b[0] for b in _BEHAVIOURS])
def test_gemini_diagnose_model_check_never_prints_the_key(label, behaviour, debug_logs):
    rc, output, getter, poster = _run_diagnose("gemini", behaviour, _status(200))
    assert rc == 1
    _assert_clean(output, *debug_logs)
    _assert_urls_clean(getter)
    for _url, headers, _params in getter.calls:
        assert headers.get("x-goog-api-key") == CANARY


@pytest.mark.parametrize("provider_name", ["gemini", "openai", "anthropic"])
@pytest.mark.parametrize("label,behaviour", _BEHAVIOURS, ids=[b[0] for b in _BEHAVIOURS])
def test_diagnose_generation_failures_never_print_the_key(provider_name, label, behaviour, debug_logs):
    model_ok = _status(200)
    rc, output, getter, poster = _run_diagnose(provider_name, model_ok, behaviour)
    assert rc == 1
    _assert_clean(output, *debug_logs)
    _assert_urls_clean(getter)
    _assert_urls_clean(poster)


@pytest.mark.parametrize("stage", ["dns", "tls", "build"])
def test_diagnose_early_stage_failures_are_redacted(stage):
    buf = io.StringIO()
    leak = f"https://host/v1?key={CANARY} Authorization: Bearer {CANARY}"
    patches = [mock.patch.object(diagnostics.socket, "gethostbyname", return_value="0.0.0.0"),
               mock.patch.object(diagnostics.socket, "create_connection"),
               mock.patch.object(diagnostics.ssl, "create_default_context")]
    if stage == "dns":
        patches[0] = mock.patch.object(diagnostics.socket, "gethostbyname",
                                       side_effect=diagnostics.socket.gaierror(leak))
    elif stage == "tls":
        patches[1] = mock.patch.object(diagnostics.socket, "create_connection", side_effect=OSError(leak))
    else:
        patches.append(mock.patch.object(diagnostics, "build_provider", side_effect=RuntimeError(leak)))
    for p in patches:
        p.start()
    try:
        rc = diagnostics.run_ai_diagnostics(
            cfg_override={"provider": "gemini", "model": "m-1", "api_key": CANARY}, stream=buf)
    finally:
        for p in patches:
            p.stop()
    assert rc == 1
    _assert_clean(buf.getvalue())


def test_cli_ai_question_failure_never_prints_the_key(tmp_path, monkeypatch):
    from scrutics import cli

    session = tmp_path / "session"
    session.mkdir()
    stats = {k: 0 for k in ("asset_count", "ot_count", "it_count", "unknown_count",
                            "connection_count", "anomaly_count")}
    (session / "manifest.json").write_text(json.dumps({
        "format": "scrutics-evidence", "version": 1, "scrutics_version": "0.7",
        "created_at": "2026-10-16T00:00:00Z", "capture_started": "2026-10-16T00:00:00Z",
        "capture_ended": "2026-10-16T00:01:00Z", "sensor_id": "s", "scope": {},
        "files": {}, "stats": stats,
    }))
    monkeypatch.setenv("GEMINI_API_KEY", CANARY)
    args = mock.Mock(question=["hi"], session=str(session), output="output", provider=None, model=None,
                     reconfigure=False, disable=False, reset=False, diagnose=False)
    cfg = {"enabled": True, "provider": "gemini", "model": "gemini-3.8-flash", "api_key": "${GEMINI_API_KEY}"}
    for _label, behaviour in _BEHAVIOURS:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("scrutics.ai.config.load_ai_config", return_value=cfg), \
             mock.patch("requests.post", _Recorder(behaviour)), redirect_stdout(out), redirect_stderr(err):
            cli.run_ai(args)
        _assert_clean(out.getvalue(), err.getvalue())


_KEY_VARS = {"gemini": "GEMINI_API_KEY", "openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
_OVERRIDES = [(configured, chosen) for configured in _KEY_VARS
              for chosen in ("gemini", "openai", "anthropic", "ollama") if chosen != configured]
_OTHER_KEY = "other-provider-key-0000"


def _echoing_status(code):
    # The provider can only repeat what it was sent, so the body echoes this request's URL and headers
    def behaviour(url, headers):
        resp = mock.Mock()
        resp.status_code = code
        body = {"error": {"message": f"failed for {url} with {json.dumps(headers)}", "status": "UNAVAILABLE"}}
        resp.json.return_value = body
        resp.text = json.dumps(body)
        resp.headers = {}
        return resp
    return behaviour


_OVERRIDE_BEHAVIOURS = ([(e.__name__, _raising(e)) for e in _REQUEST_ERRORS]
                        + [(f"HTTP {code}", _echoing_status(code)) for code in _STATUSES])


def _overriding_cfg(configured):
    return {"enabled": True, "provider": configured, "model": "configured-model",
            "api_key": f"${{{_KEY_VARS[configured]}}}", "base_url": "https://configured.example"}


def _assert_requests_clean(*recorders):
    for recorder in recorders:
        _assert_urls_clean(recorder)
        for (_url, headers, _params), body in zip(recorder.calls, recorder.bodies):
            _assert_clean(json.dumps(headers), json.dumps(body, default=str))


@pytest.mark.parametrize("configured,chosen", _OVERRIDES, ids=[f"{c}-to-{o}" for c, o in _OVERRIDES])
def test_cli_provider_override_never_sends_or_prints_the_configured_key(tmp_path, monkeypatch, configured, chosen):
    from scrutics import cli

    session = tmp_path / "session"
    session.mkdir()
    stats = {k: 0 for k in ("asset_count", "ot_count", "it_count", "unknown_count",
                            "connection_count", "anomaly_count")}
    (session / "manifest.json").write_text(json.dumps({
        "format": "scrutics-evidence", "version": 1, "scrutics_version": "0.7",
        "created_at": "2026-10-16T00:00:00Z", "capture_started": "2026-10-16T00:00:00Z",
        "capture_ended": "2026-10-16T00:01:00Z", "sensor_id": "s", "scope": {},
        "files": {}, "stats": stats,
    }))
    for var in _KEY_VARS.values():
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(_KEY_VARS[configured], CANARY)
    args = cli.build_parser().parse_args(["ai", "--session", str(session), "--provider", chosen, "hi"])
    if chosen in _KEY_VARS:
        # first without the chosen provider's key (refused), then with it
        cases = [(None, "no key", _echoing_status(401))] + [(_OTHER_KEY, label, b) for label, b in _OVERRIDE_BEHAVIOURS]
    else:
        cases = [(None, label, b) for label, b in _OVERRIDE_BEHAVIOURS]
    for chosen_key, _label, behaviour in cases:
        if chosen in _KEY_VARS:
            if chosen_key:
                monkeypatch.setenv(_KEY_VARS[chosen], chosen_key)
            else:
                monkeypatch.delenv(_KEY_VARS[chosen], raising=False)
        out, err = io.StringIO(), io.StringIO()
        poster, getter = _Recorder(behaviour), _Recorder(behaviour)
        with mock.patch("scrutics.ai.config.load_ai_config", return_value=_overriding_cfg(configured)), \
             mock.patch("requests.post", poster), mock.patch("requests.get", getter), \
             redirect_stdout(out), redirect_stderr(err):
            cli.run_ai(args)
        _assert_clean(out.getvalue(), err.getvalue())
        _assert_requests_clean(poster, getter)
        if chosen in _KEY_VARS and not chosen_key:
            assert poster.calls == [] and getter.calls == []


@pytest.mark.parametrize("configured,chosen", _OVERRIDES, ids=[f"{c}-to-{o}" for c, o in _OVERRIDES])
@pytest.mark.parametrize("label,behaviour", _OVERRIDE_BEHAVIOURS, ids=[b[0] for b in _OVERRIDE_BEHAVIOURS])
def test_diagnose_provider_override_never_sends_or_prints_the_configured_key(
        monkeypatch, configured, chosen, label, behaviour):
    for var in _KEY_VARS.values():
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(_KEY_VARS[configured], CANARY)
    if chosen in _KEY_VARS:
        monkeypatch.setenv(_KEY_VARS[chosen], _OTHER_KEY)
    buf = io.StringIO()
    getter, poster = _Recorder(behaviour), _Recorder(behaviour)
    with mock.patch("scrutics.ai.diagnostics.load_ai_config", return_value=_overriding_cfg(configured)), \
         mock.patch.object(diagnostics.socket, "gethostbyname", return_value="0.0.0.0"), \
         mock.patch.object(diagnostics.socket, "create_connection"), \
         mock.patch.object(diagnostics.ssl, "create_default_context"), \
         mock.patch("requests.get", getter), mock.patch("requests.post", poster), redirect_stderr(buf):
        rc = diagnostics.run_ai_diagnostics(provider_name=chosen, stream=buf)
    assert rc == 1
    _assert_clean(buf.getvalue())
    _assert_requests_clean(getter, poster)


def test_malformed_config_with_a_literal_key_is_redacted(tmp_path, monkeypatch):
    from scrutics.ai.config import load_ai_config

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    (tmp_path / ".scrutics").mkdir()
    # A literal key on the line the parser rejects must not reach the error text
    (tmp_path / ".scrutics" / "ai.yaml").write_text(f"provider: gemini\napi_key: {CANARY}: x\nmodel: m\n")
    with pytest.raises(LLMProviderError) as info:
        load_ai_config()
    _assert_clean(*_exception_texts(info.value))


class _ErrorServer(http.server.BaseHTTPRequestHandler):
    """Loopback stand-in for a provider; answers every request with 503."""

    def do_GET(self):
        self._reply()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._reply()

    def _reply(self):
        body = json.dumps({"error": {"message": "unavailable", "status": "UNAVAILABLE"}}).encode()
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def loopback_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ErrorServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("provider_name", ["gemini", "anthropic", "openai"])
def test_real_http_stack_at_debug_logging_shows_no_key(provider_name, loopback_server, debug_logs):
    from scrutics.ai import anthropic_provider

    with mock.patch.object(gemini_provider, "_GEMINI_BASE_URL", f"{loopback_server}/v1beta/models"), \
         mock.patch.object(anthropic_provider, "_ANTHROPIC_API_URL", f"{loopback_server}/v1/messages"):
        if provider_name == "openai":
            provider = OpenAIProvider(model="gpt-4o-mini", api_key=CANARY, base_url=loopback_server)
        else:
            provider = _providers()[provider_name]()
        with pytest.raises(LLMProviderError) as info:
            provider.chat([{"role": "user", "content": "hi"}])
    assert any("urllib3" in r or "127.0.0.1" in r for r in debug_logs), "urllib3 debug lines expected"
    _assert_clean(*debug_logs, *_exception_texts(info.value))
    assert http.client.HTTPConnection.debuglevel == 0


def test_redactor_strips_credential_shapes():
    text = (f"GET /m?key={CANARY}&alt=json x-goog-api-key: {CANARY} 'x-api-key': '{CANARY}' "
            f"Authorization: Bearer {CANARY}")
    assert CANARY not in redact(text)
    assert redact(f"prefix {CANARY} suffix", [CANARY]) == "prefix [REDACTED_API_KEY] suffix"


def _js_function(page, name):
    start = page.index(f"function {name}(")
    depth = 0
    for i in range(page.index("{", start), len(page)):
        depth += {"{": 1, "}": -1}.get(page[i], 0)
        if depth == 0:
            return page[start:i + 1]
    raise AssertionError(f"{name} not closed")


def test_topology_chat_sends_the_gemini_key_only_in_a_header(tmp_path):
    node = shutil.which("node")
    if node is None:
        if os.environ.get("CI"):
            pytest.fail("Node.js is required in CI to check the topology page scripts")
        pytest.skip("Node.js not installed")
    from scrutics.topology import generate_topology_html

    page = generate_topology_html({"nodes": [], "edges": []})
    models = re.search(r"var AI_MODELS = (\{.*?\});", page).group(1)
    script = "\n".join([
        f"var AI_MODELS = {models};",
        "var calls = [];",
        "function fetch(url, init) { calls.push({url: url, headers: init.headers});"
        " return Promise.resolve({ok: true, status: 200, json: function () {"
        " return Promise.resolve({candidates: [{content: {parts: [{text: 'ok'}]}}]}); }}); }",
        _js_function(page, "callGemini"),
        f"callGemini({json.dumps(CANARY)}, [{{role: 'user', content: 'hi'}}])"
        ".then(function () { console.log(JSON.stringify(calls)); });",
    ])
    path = tmp_path / "gemini_call.js"
    path.write_text(script, encoding="utf-8")
    result = subprocess.run([node, str(path)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    calls = json.loads(result.stdout.strip().splitlines()[-1])
    assert len(calls) == 1
    assert CANARY not in calls[0]["url"]
    assert calls[0]["headers"]["x-goog-api-key"] == CANARY
