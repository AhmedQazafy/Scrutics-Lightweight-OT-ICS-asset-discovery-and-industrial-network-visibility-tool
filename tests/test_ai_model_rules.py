"""Offered models, per-model request parameters and provider errors for Anthropic and OpenAI.

The provider stubs below refuse requests the way each provider's documentation says it does, so a
request Scrutics builds passes only if it follows those rules.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import pytest

from scrutics import cli
from scrutics.ai import model_discovery
from scrutics.ai.agent import run_agent_loop
from scrutics.ai.anthropic_provider import AnthropicProvider
from scrutics.ai.config import DEFAULT_ANTHROPIC_MODEL, DEFAULT_OPENAI_MODEL, build_provider
from scrutics.ai.model_rules import FALLBACK_CHECKED, FALLBACK_LABEL, fallback_models
from scrutics.ai.openai_provider import OpenAIProvider
from scrutics.ai.provider import LLMResponseError
from scrutics.ai.tools import SessionContext

ANTHROPIC_KEY = "sk-ant-test"
OPENAI_KEY = "sk-openai-test"


def _response(status, body):
    resp = mock.Mock(status_code=status, headers={}, text=json.dumps(body))
    resp.json.return_value = body
    return resp


# ── Anthropic stub ────────────────────────────────────────────────────────────

# Documented: temperature/top_p/top_k at non-default values return 400 on Claude 4.7 and later.
_CLAUDE_BEFORE_4_7 = {"claude-haiku-4-5", "claude-haiku-4-5-20251001", "claude-sonnet-4-6",
                      "claude-opus-4-6", "claude-opus-4-5-20251101", "claude-sonnet-4-5-20250929"}
_CLAUDE_4_7_AND_LATER = {"claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5", "claude-opus-5",
                         "claude-sonnet-5", "claude-opus-4-8", "claude-opus-4-7", "claude-fable-5",
                         "claude-fable-5-1"}
# Documented: thinking {"type": "disabled"} returns 400 on these
_THINKING_ALWAYS_ON = {"claude-opus-5-5", "claude-fable-5", "claude-fable-5-1", "claude-sonnet-5-5"}
# Adaptive thinking runs when no thinking field is sent
_THINKS_BY_DEFAULT = {"claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5", "claude-opus-5",
                      "claude-sonnet-5", "claude-fable-5", "claude-fable-5-1"}


class AnthropicStub:
    def __init__(self):
        self.requests = []
        self.issued = {}  # tool_use id -> exact content blocks of that assistant turn

    @staticmethod
    def _error(message):
        return _response(400, {"type": "error", "error": {"type": "invalid_request_error", "message": message},
                               "request_id": "req_1"})

    def __call__(self, url, json=None, headers=None, timeout=None):
        payload = json
        self.requests.append(payload)
        model = payload["model"]
        if model not in _CLAUDE_BEFORE_4_7 | _CLAUDE_4_7_AND_LATER:
            return _response(404, {"type": "error", "error": {"type": "not_found_error", "message": f"model: {model}"}})
        if model in _CLAUDE_4_7_AND_LATER:
            for name, default in (("temperature", 1), ("top_p", 0.99)):
                if name in payload and payload[name] != default:
                    return self._error(f"{name}: non-default values are not supported for this model")
            if "top_k" in payload:
                return self._error("top_k is not supported for this model")
        thinking = payload.get("thinking")
        if thinking == {"type": "disabled"} and model in _THINKING_ALWAYS_ON:
            return self._error('"thinking.type.disabled" is not supported for this model.')
        for i, msg in enumerate(payload["messages"]):
            if msg["role"] != "assistant" or not isinstance(msg["content"], list):
                continue
            ids = [b.get("id") for b in msg["content"] if b.get("type") == "tool_use"]
            for tool_id in ids:
                if tool_id in self.issued and msg["content"] != self.issued[tool_id]:
                    return self._error(f"messages.{i}.content.0: `thinking` or `redacted_thinking` blocks in "
                                       "the latest assistant message cannot be modified.")
        thinks = model in _THINKS_BY_DEFAULT and thinking != {"type": "disabled"}
        blocks = [{"type": "thinking", "thinking": "", "signature": f"sig-{len(self.requests)}"}] if thinks else []
        last = payload["messages"][-1]
        answered = isinstance(last["content"], list) and any(b.get("type") == "tool_result" for b in last["content"])
        if payload.get("tools") and not answered:
            tool_id = f"toolu_{len(self.requests)}"
            blocks.append({"type": "tool_use", "id": tool_id, "name": "get_statistics", "input": {}})
            self.issued[tool_id] = blocks
            return _response(200, {"content": blocks, "stop_reason": "tool_use"})
        blocks.append({"type": "text", "text": "There are 2 assets."})
        return _response(200, {"content": blocks, "stop_reason": "end_turn"})


# ── OpenAI stub ───────────────────────────────────────────────────────────────

_GPT6_TOOLS_WITH_NONE = {"gpt-6-luna", "gpt-6-sol"}
_GPT6_TOOLS_NEED_RESPONSES = {"gpt-6-astra", "gpt-6.1-sol"}
_GPT_LEGACY = {"gpt-4o-mini", "gpt-4o", "gpt-4.1", "gpt-4.1-mini"}


class OpenAIStub:
    def __init__(self):
        self.requests = []

    @staticmethod
    def _error(message, param=None):
        return _response(400, {"error": {"message": message, "type": "invalid_request_error", "param": param}})

    def __call__(self, url, json=None, headers=None, timeout=None, stream=False):
        payload = json
        self.requests.append(payload)
        model = payload["model"]
        gpt6 = model in _GPT6_TOOLS_WITH_NONE | _GPT6_TOOLS_NEED_RESPONSES
        if not gpt6 and model not in _GPT_LEGACY:
            return _response(404, {"error": {"message": f"The model {model} does not exist", "type": "invalid_request_error"}})
        # Documented: remove temperature when reasoning effort is not none. Its acceptance with
        # "none" is not documented, so the stub refuses it on GPT-6 altogether.
        if gpt6 and "temperature" in payload:
            return self._error("Unsupported parameter: 'temperature'", "temperature")
        if payload.get("tools"):
            if model in _GPT6_TOOLS_NEED_RESPONSES:
                return self._error("Function tools are not supported on Chat Completions for this model.", "tools")
            if model in _GPT6_TOOLS_WITH_NONE and payload.get("reasoning_effort") != "none":
                return self._error("Function calling requires reasoning_effort 'none' on Chat Completions.",
                                   "reasoning_effort")
        answered = any(m.get("role") == "tool" for m in payload["messages"])
        if payload.get("tools") and not answered:
            message = {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "get_statistics", "arguments": "{}"}}]}
        else:
            message = {"role": "assistant", "content": "There are 2 assets."}
        return _response(200, {"choices": [{"message": message}]})


# ── session fixture ───────────────────────────────────────────────────────────

@pytest.fixture
def session(tmp_path):
    stats = {"asset_count": 2, "ot_count": 2, "it_count": 0, "unknown_count": 0,
             "connection_count": 0, "anomaly_count": 0}
    (tmp_path / "manifest.json").write_text(json.dumps({
        "format": "scrutics-evidence", "version": 1, "scrutics_version": "0.7",
        "created_at": "2026-10-16T00:00:00Z", "capture_started": "2026-10-16T00:00:00Z",
        "capture_ended": "2026-10-16T00:01:00Z", "sensor_id": "s", "scope": {},
        "files": {"assets": "assets.csv"}, "stats": stats}))
    (tmp_path / "assets.csv").write_text("ip,mac,type\n10.0.0.1,00:0e:8c:00:00:01,OT\n10.0.0.2,00:0e:8c:00:00:02,OT\n")
    return SessionContext(str(tmp_path))


def _agent(provider, ctx, stub):
    with mock.patch("requests.post", stub), mock.patch("time.sleep"):
        return run_agent_loop(provider, ctx, "How many assets?", max_tool_iterations=3)


# ── Anthropic: parameters and thinking ────────────────────────────────────────

def test_the_default_anthropic_model_completes_an_agent_turn_with_tool_results(session):
    stub = AnthropicStub()
    provider = build_provider({"provider": "anthropic", "api_key": ANTHROPIC_KEY})
    assert provider.model == DEFAULT_ANTHROPIC_MODEL == "claude-haiku-5-5"
    assert _agent(provider, session, stub) == "There are 2 assets."
    assert len(stub.requests) == 2
    for payload in stub.requests:
        assert payload["thinking"] == {"type": "disabled"}
        assert not {"temperature", "top_p", "top_k"} & set(payload)


@pytest.mark.parametrize("model", ["claude-sonnet-5-5", "claude-opus-5-5", "claude-fable-5-1"])
def test_a_thinking_model_gets_its_thinking_blocks_back_unmodified(session, model):
    stub = AnthropicStub()
    provider = AnthropicProvider(model=model, api_key=ANTHROPIC_KEY, temperature=0.3)
    assert _agent(provider, session, stub) == "There are 2 assets."
    first, second = stub.requests
    assert "thinking" not in first and "temperature" not in first
    replayed = next(m for m in second["messages"] if m["role"] == "assistant")["content"]
    assert replayed[0]["type"] == "thinking" and replayed == next(iter(stub.issued.values()))


def test_the_stub_refuses_a_rebuilt_assistant_turn(session):
    # The same conversation with the thinking blocks dropped, as Scrutics sent it before
    stub = AnthropicStub()
    provider = AnthropicProvider(model="claude-sonnet-5-5", api_key=ANTHROPIC_KEY)
    with mock.patch("requests.post", stub):
        first = provider.chat([{"role": "user", "content": "q"}], tools=[{"type": "function", "function": {
            "name": "get_statistics", "parameters": {"type": "object", "properties": {}}}}])
    first.pop("_anthropic_content")
    messages = [{"role": "user", "content": "q"}, first,
                {"role": "tool", "tool_call_id": first["tool_calls"][0]["id"], "content": "{}"}]
    with mock.patch("requests.post", stub), pytest.raises(LLMResponseError) as info:
        provider.chat(messages, tools=[{"type": "function", "function": {"name": "get_statistics"}}])
    assert "cannot be modified" in str(info.value)


@pytest.mark.parametrize("model", ["claude-haiku-4-5", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"])
def test_models_before_4_7_still_get_the_configured_temperature(session, model):
    stub = AnthropicStub()
    provider = AnthropicProvider(model=model, api_key=ANTHROPIC_KEY, temperature=0.3)
    assert _agent(provider, session, stub) == "There are 2 assets."
    assert all(p["temperature"] == 0.3 and "thinking" not in p for p in stub.requests)


def test_an_unknown_anthropic_model_gets_no_optional_parameters():
    captured = []
    with mock.patch("requests.post", side_effect=lambda url, json=None, **kw: captured.append(json) or _response(
            200, {"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"})):
        AnthropicProvider(model="claude-new-9", api_key=ANTHROPIC_KEY, temperature=0.3).chat(
            [{"role": "user", "content": "hi"}])
    assert set(captured[0]) == {"model", "max_tokens", "messages"}


def test_an_anthropic_400_reports_the_providers_error_type_and_message():
    body = {"type": "error", "error": {"type": "invalid_request_error",
                                       "message": f"messages.0: bad request for key {ANTHROPIC_KEY}"}}
    with mock.patch("requests.post", return_value=_response(400, body)):
        with pytest.raises(LLMResponseError) as info:
            AnthropicProvider(api_key=ANTHROPIC_KEY).chat([{"role": "user", "content": "hi"}])
    message = str(info.value)
    assert "HTTP 400 (invalid_request_error: messages.0: bad request" in message
    assert ANTHROPIC_KEY not in message


def test_an_anthropic_auth_failure_keeps_its_wording_and_adds_the_type():
    body = {"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}}
    with mock.patch("requests.post", return_value=_response(401, body)):
        with pytest.raises(LLMResponseError) as info:
            AnthropicProvider(api_key=ANTHROPIC_KEY).chat([{"role": "user", "content": "hi"}])
    assert str(info.value).startswith("Authentication failed for Anthropic.")
    assert "authentication_error: invalid x-api-key" in str(info.value)


def test_an_anthropic_400_body_reaches_the_cli_user(tmp_path, monkeypatch, session):
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    body = {"type": "error", "error": {"type": "invalid_request_error", "message": "max_tokens: too large"}}
    args = cli.build_parser().parse_args(["ai", "--session", session.session_dir, "hi"])
    cfg = {"enabled": True, "provider": "anthropic", "model": "claude-haiku-5-5", "api_key": "${ANTHROPIC_API_KEY}"}
    err = io.StringIO()
    with mock.patch("scrutics.ai.config.load_ai_config", return_value=cfg), \
         mock.patch("requests.post", return_value=_response(400, body)), \
         redirect_stdout(io.StringIO()), redirect_stderr(err):
        cli.run_ai(args)
    assert "invalid_request_error: max_tokens: too large" in err.getvalue()


# ── OpenAI: parameters ────────────────────────────────────────────────────────

def test_the_default_openai_model_completes_an_agent_turn_with_tool_results(session):
    stub = OpenAIStub()
    provider = build_provider({"provider": "openai", "api_key": OPENAI_KEY})
    assert provider.model == DEFAULT_OPENAI_MODEL == "gpt-6-luna"
    assert _agent(provider, session, stub) == "There are 2 assets."
    assert len(stub.requests) == 2
    for payload in stub.requests:
        assert payload["reasoning_effort"] == "none" and "temperature" not in payload


def test_gpt_6_sol_follows_the_same_rule(session):
    stub = OpenAIStub()
    assert _agent(OpenAIProvider(model="gpt-6-sol", api_key=OPENAI_KEY), session, stub) == "There are 2 assets."


@pytest.mark.parametrize("model", ["gpt-4o-mini", "gpt-4.1", "gpt-4o-mini-2024-07-18"])
def test_deprecated_gpt_4_models_keep_the_configured_temperature(model):
    captured = []
    with mock.patch("requests.post", side_effect=lambda url, json=None, **kw: captured.append(json) or _response(
            200, {"choices": [{"message": {"role": "assistant", "content": "ok"}}]})):
        OpenAIProvider(model=model, api_key=OPENAI_KEY, temperature=0.3).chat([{"role": "user", "content": "hi"}])
    assert captured[0]["temperature"] == 0.3 and "reasoning_effort" not in captured[0]


def test_an_unknown_openai_model_gets_no_optional_parameters():
    captured = []
    with mock.patch("requests.post", side_effect=lambda url, json=None, **kw: captured.append(json) or _response(
            200, {"choices": [{"message": {"role": "assistant", "content": "ok"}}]})):
        OpenAIProvider(model="local-model", api_key=OPENAI_KEY, base_url="http://10.0.0.5:8000").chat(
            [{"role": "user", "content": "hi"}])
    assert set(captured[0]) == {"model", "messages", "stream"}


def test_an_openai_400_reports_the_providers_message():
    stub = OpenAIStub()
    with mock.patch("requests.post", stub), pytest.raises(LLMResponseError) as info:
        OpenAIProvider(model="gpt-6-astra", api_key=OPENAI_KEY).chat(
            [{"role": "user", "content": "hi"}], tools=[{"type": "function", "function": {"name": "t"}}])
    assert "HTTP 400: Function tools are not supported on Chat Completions" in str(info.value)


# ── model lists ───────────────────────────────────────────────────────────────

class _ListStub:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def __call__(self, url, headers=None, params=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "params": dict(params or {})})
        return _response(200, self.pages[len(self.calls) - 1])


_ANTHROPIC_PAGES = [
    {"data": [{"id": "claude-opus-5-5", "lifecycle": "active"}, {"id": "claude-haiku-5-5", "lifecycle": "active"},
              {"id": "claude-sonnet-4-5-20250929", "lifecycle": "deprecated"}],
     "has_more": True, "last_id": "claude-sonnet-4-5-20250929"},
    {"data": [{"id": "claude-sonnet-5-5", "lifecycle": "active"}, {"id": "claude-opus-4-8", "lifecycle": "active"},
              {"id": "claude-3-haiku-20240307", "lifecycle": "retired"}],
     "has_more": False, "last_id": "claude-3-haiku-20240307"},
]


def test_anthropic_models_come_from_the_models_endpoint():
    stub = _ListStub(_ANTHROPIC_PAGES)
    with mock.patch("requests.get", stub):
        models, source, reason = model_discovery.fetch_models_with_source("anthropic", ANTHROPIC_KEY)
    assert source == "live" and reason == ""
    assert models == ["claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5", "claude-opus-4-8"]
    assert stub.calls[0]["url"] == "https://api.anthropic.com/v1/models"
    assert stub.calls[0]["headers"] == {"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01"}
    assert stub.calls[1]["params"]["after_id"] == "claude-sonnet-4-5-20250929"


def test_openai_lists_only_models_that_work_with_scrutics_requests():
    page = {"data": [{"id": m} for m in ("o4-mini-deep-research", "gpt-6-astra", "gpt-6-sol", "gpt-4o-mini",
                                         "gpt-6.1-sol", "gpt-6-luna", "gpt-realtime-2", "text-embedding-3-large")]}
    with mock.patch("requests.get", _ListStub([page])):
        models, source, _ = model_discovery.fetch_models_with_source("openai", OPENAI_KEY)
    assert (models, source) == (["gpt-6-luna", "gpt-6-sol"], "live")


@pytest.mark.parametrize("provider,default", [("anthropic", "claude-haiku-5-5"), ("openai", "gpt-6-luna")])
def test_without_a_key_the_fallback_has_only_offered_models_default_first(provider, default):
    with mock.patch("requests.get", side_effect=AssertionError("no request without a key")):
        models, source, reason = model_discovery.fetch_models_with_source(provider, "")
    assert source == "fallback" and reason == "no API key"
    assert models == fallback_models(provider) and models[0] == default


def test_a_failing_endpoint_falls_back_and_says_why():
    with mock.patch("requests.get", return_value=_response(503, {})):
        models, source, reason = model_discovery.fetch_models_with_source("anthropic", ANTHROPIC_KEY)
    assert source == "fallback" and models[0] == "claude-haiku-5-5"
    assert "503" in reason and ANTHROPIC_KEY not in reason


def test_the_fallback_label_states_it_is_not_live_and_its_date():
    assert FALLBACK_CHECKED == "2026-10-16"
    assert "not from your account" in FALLBACK_LABEL and FALLBACK_CHECKED in FALLBACK_LABEL


def _onboard(tmp_path, monkeypatch, choice, get_behaviour, answers=("",)):
    monkeypatch.setenv("HOME", str(tmp_path))
    out = io.StringIO()
    replies = iter([choice, *answers])
    with mock.patch("builtins.input", lambda prompt="": next(replies)), \
         mock.patch("getpass.getpass", return_value="k-123"), \
         mock.patch("requests.get", get_behaviour), redirect_stdout(out):
        cfg = cli._run_ai_onboarding_cli()
    return cfg, out.getvalue()


def test_onboarding_with_the_endpoint_offers_live_models_and_defaults_to_haiku_5_5(tmp_path, monkeypatch):
    cfg, output = _onboard(tmp_path, monkeypatch, "3", _ListStub(_ANTHROPIC_PAGES))
    assert cfg["model"] == "claude-haiku-5-5"
    assert FALLBACK_LABEL not in output
    assert re.findall(r"^\s+\d+\. (\S+)$", output, flags=re.M)[0] == "claude-haiku-5-5"
    assert "model: claude-haiku-5-5" in (tmp_path / ".scrutics" / "ai.yaml").read_text()


@pytest.mark.parametrize("choice,default", [("3", "claude-haiku-5-5"), ("2", "gpt-6-luna")])
def test_onboarding_when_listing_fails_offers_the_labelled_fallback(tmp_path, monkeypatch, choice, default):
    cfg, output = _onboard(tmp_path, monkeypatch, choice, mock.Mock(return_value=_response(401, {})))
    assert cfg["model"] == default
    assert FALLBACK_LABEL in output
    listed = re.findall(r"^\s+\d+\. (\S+)$", output, flags=re.M)
    assert listed and set(listed) <= set(fallback_models("anthropic" if choice == "3" else "openai"))


def test_list_models_labels_the_fallback(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = io.StringIO()
    with redirect_stdout(out):
        rc = cli.run_list_models(cli.build_parser().parse_args(["list-models", "anthropic"]))
    assert rc == 1
    assert FALLBACK_LABEL in out.getvalue() and "claude-haiku-5-5" in out.getvalue()
    assert "claude-sonnet-4\n" not in out.getvalue() and "claude-3-" not in out.getvalue()


def test_the_tui_model_step_preselects_the_default_and_labels_a_fallback():
    import asyncio
    from scrutics.ui.tui import AIModelSelectionModal, ChoiceField, ScruticsApp

    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            step1 = {"default_model": "claude-haiku-5-5", "model_source": "fallback"}
            await app.push_screen(AIModelSelectionModal(step1, ["claude-sonnet-5-5", "claude-haiku-5-5"]))
            await pilot.pause()
            screen = app.screen
            assert screen.query_one("#model-choice", ChoiceField).value == "claude-haiku-5-5"
            assert str(screen.query_one("#fallback-model-hint").render()) == FALLBACK_LABEL
    asyncio.run(run())


# ── topology chat ─────────────────────────────────────────────────────────────

def _js_function(page, name):
    start = page.index(f"function {name}(")
    depth = 0
    for i in range(page.index("{", start), len(page)):
        depth += {"{": 1, "}": -1}.get(page[i], 0)
        if depth == 0:
            return page[start:i + 1]
    raise AssertionError(f"{name} not closed")


def _run_chat(tmp_path, function, status, body):
    node = shutil.which("node")
    if node is None:
        if os.environ.get("CI"):
            pytest.fail("Node.js is required in CI to check the topology page scripts")
        pytest.skip("Node.js not installed")
    from scrutics.topology import generate_topology_html

    page = generate_topology_html({"nodes": [], "edges": []})
    script = "\n".join([
        "var " + re.search(r"AI_MODELS = (\{.*?\});", page).group(0),
        "var " + re.search(r"AI_REQUEST_OPTIONS = (\{.*?\});", page).group(0),
        re.search(r"var TOKEN_LIMIT_MESSAGE = .*?;\n", page, flags=re.S).group(0),
        "var calls = [];",
        f"var STATUS = {status}; var BODY = {json.dumps(body)};",
        "function fetch(url, init) { calls.push({url: url, body: JSON.parse(init.body)});"
        " return Promise.resolve({ok: STATUS === 200, status: STATUS,"
        " json: function () { return Promise.resolve(BODY); }}); }",
        "var " + re.search(r"RETRY_POLICY = (\{.*?\});", page).group(0),
        *(_js_function(page, name) for name in ("errorDetail", "providerError", "retryAfterSeconds", "withRetry")),
        _js_function(page, function),
        f"{function}('k', [{{role: 'system', content: 's'}}, {{role: 'user', content: 'hi'}}])"
        ".then(function (r) { console.log(JSON.stringify({calls: calls, reply: r})); },"
        " function (e) { console.log(JSON.stringify({calls: calls, error: e.message})); });",
    ])
    path = tmp_path / "chat.js"
    path.write_text(script, encoding="utf-8")
    result = subprocess.run([node, str(path)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_topology_chat_anthropic_request_follows_the_rules(tmp_path):
    out = _run_chat(tmp_path, "callAnthropic", 200, {"content": [{"type": "text", "text": "ok"}]})
    body = out["calls"][0]["body"]
    assert body["model"] == "claude-haiku-5-5" and body["thinking"] == {"type": "disabled"}
    assert "temperature" not in body and body["max_tokens"] == 1024
    assert out["reply"] == "ok"


def test_topology_chat_openai_request_follows_the_rules(tmp_path):
    out = _run_chat(tmp_path, "callOpenAI", 200, {"choices": [{"message": {"content": "ok"}}]})
    body = out["calls"][0]["body"]
    assert body["model"] == "gpt-6-luna" and body["reasoning_effort"] == "none"
    assert "temperature" not in body and "max_tokens" not in body and body["max_completion_tokens"] == 1024


@pytest.mark.parametrize("function,status,body,expected", [
    ("callAnthropic", 400, {"error": {"type": "invalid_request_error", "message": "bad thinking"}},
     "Anthropic error HTTP 400 (invalid_request_error: bad thinking)."),
    ("callOpenAI", 400, {"error": {"type": "invalid_request_error", "message": "Unsupported parameter"}},
     "OpenAI error HTTP 400 (invalid_request_error: Unsupported parameter)."),
    ("callGemini", 400, {"error": {"status": "INVALID_ARGUMENT", "message": "bad field"}},
     "Gemini error HTTP 400 (INVALID_ARGUMENT: bad field)."),
    ("callAnthropic", 401, {"error": {"type": "authentication_error", "message": "invalid x-api-key"}},
     "Auth failed: check your Anthropic key (authentication_error: invalid x-api-key)."),
    ("callOpenAI", 500, None, "OpenAI error HTTP 500."),
])
def test_topology_chat_shows_the_providers_error(tmp_path, function, status, body, expected):
    assert _run_chat(tmp_path, function, status, body)["error"] == expected


# ── token limit reached before any answer ─────────────────────────────────────

def test_anthropic_stopping_at_max_tokens_with_no_text_says_so():
    body = {"content": [{"type": "thinking", "thinking": "", "signature": "s"}], "stop_reason": "max_tokens"}
    with mock.patch("requests.post", return_value=_response(200, body)):
        with pytest.raises(LLMResponseError) as info:
            AnthropicProvider(model="claude-sonnet-5-5", api_key=ANTHROPIC_KEY, max_tokens=1024).chat(
                [{"role": "user", "content": "hi"}])
    message = str(info.value)
    assert "token limit (max_tokens 1024)" in message and "reasoning" in message
    assert "Raise max_tokens" in message and "thinking off" in message


def test_anthropic_stopping_at_max_tokens_inside_a_tool_call_says_so():
    body = {"content": [{"type": "thinking", "thinking": "", "signature": "s"},
                        {"type": "tool_use", "id": "t1", "name": "get_statistics", "input": {}}],
            "stop_reason": "max_tokens"}
    with mock.patch("requests.post", return_value=_response(200, body)):
        with pytest.raises(LLMResponseError, match="token limit"):
            AnthropicProvider(model="claude-sonnet-5-5", api_key=ANTHROPIC_KEY).chat(
                [{"role": "user", "content": "hi"}], tools=[{"type": "function", "function": {"name": "t"}}])


def test_anthropic_text_cut_at_max_tokens_is_still_returned():
    body = {"content": [{"type": "text", "text": "Partial answer"}], "stop_reason": "max_tokens"}
    with mock.patch("requests.post", return_value=_response(200, body)):
        assert AnthropicProvider(api_key=ANTHROPIC_KEY).chat([{"role": "user", "content": "hi"}]) == "Partial answer"


def test_openai_stopping_at_the_length_limit_with_no_text_says_so():
    body = {"choices": [{"message": {"role": "assistant", "content": ""}, "finish_reason": "length"}]}
    with mock.patch("requests.post", return_value=_response(200, body)):
        with pytest.raises(LLMResponseError) as info:
            OpenAIProvider(model="gpt-6-sol", api_key=OPENAI_KEY).chat([{"role": "user", "content": "hi"}])
    message = str(info.value)
    assert "OpenAI stopped at the model's output token limit" in message and "reasoning off" in message


def test_openai_text_cut_at_the_length_limit_is_still_returned():
    body = {"choices": [{"message": {"role": "assistant", "content": "Partial"}, "finish_reason": "length"}]}
    with mock.patch("requests.post", return_value=_response(200, body)):
        assert OpenAIProvider(api_key=OPENAI_KEY).chat([{"role": "user", "content": "hi"}]) == "Partial"


def test_the_token_limit_message_reaches_the_cli_user(monkeypatch, session):
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    body = {"content": [{"type": "thinking", "thinking": "", "signature": "s"}], "stop_reason": "max_tokens"}
    args = cli.build_parser().parse_args(["ai", "--session", session.session_dir, "hi"])
    cfg = {"enabled": True, "provider": "anthropic", "model": "claude-opus-5-5", "api_key": "${ANTHROPIC_API_KEY}"}
    err = io.StringIO()
    with mock.patch("scrutics.ai.config.load_ai_config", return_value=cfg), \
         mock.patch("requests.post", return_value=_response(200, body)), \
         redirect_stdout(io.StringIO()), redirect_stderr(err):
        assert cli.run_ai(args) == 1
    assert "stopped at the token limit" in err.getvalue()


@pytest.mark.parametrize("function,body", [
    ("callAnthropic", {"content": [{"type": "thinking", "thinking": ""}], "stop_reason": "max_tokens"}),
    ("callOpenAI", {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}),
])
def test_topology_chat_reports_a_token_limit_stop(tmp_path, function, body):
    error = _run_chat(tmp_path, function, 200, body)["error"]
    assert error.startswith("The model used its token limit before answering")
