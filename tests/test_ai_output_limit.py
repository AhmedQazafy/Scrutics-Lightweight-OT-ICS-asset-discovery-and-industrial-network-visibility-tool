"""
Answers that stop at the output token limit: the default limits, the 1024 that setup used to write,
the flag every provider sets on a cut-off answer, the notice the CLI, the TUI and the topology chat
show, and the answer length the model is told.
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
from scrutics.ai.agent import run_agent_loop
from scrutics.ai.anthropic_provider import AnthropicProvider
from scrutics.ai.config import build_provider, override_provider
from scrutics.ai.gemini_provider import GeminiProvider
from scrutics.ai.model_rules import answer_char_budget, answer_length_instruction, gemini_options, max_tokens_for
from scrutics.ai.ollama_provider import OllamaProvider
from scrutics.ai.openai_provider import OpenAIProvider
from scrutics.ai.provider import ChatResult, LLMProvider, LLMResponseError, truncation_notice
from scrutics.ai.tools import SessionContext
from scrutics.topology import generate_topology_html

GEMINI_KEY = "gm-test"
ANTHROPIC_KEY = "sk-ant-test"
OPENAI_KEY = "sk-openai-test"


def _response(status, body):
    resp = mock.Mock(status_code=status, headers={}, text=json.dumps(body))
    resp.json.return_value = body
    return resp


def _gemini_body(text, finish):
    parts = [{"text": text}] if text else []
    return {"candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": finish}]}


@pytest.fixture
def session(tmp_path):
    stats = {"asset_count": 1, "ot_count": 1, "it_count": 0, "unknown_count": 0,
             "connection_count": 0, "anomaly_count": 0}
    (tmp_path / "manifest.json").write_text(json.dumps({
        "format": "scrutics-evidence", "version": 1, "scrutics_version": "0.7",
        "created_at": "2026-10-18T00:00:00Z", "capture_started": "2026-10-18T00:00:00Z",
        "capture_ended": "2026-10-18T00:01:00Z", "sensor_id": "s", "scope": {},
        "files": {"assets": "assets.csv"}, "stats": stats}))
    (tmp_path / "assets.csv").write_text("ip,mac,type\n10.0.0.1,00:0e:8c:00:00:01,OT\n")
    return SessionContext(str(tmp_path))


# ── limits ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("provider,configured,expected", [
    ("gemini", None, 8192), ("gemini", 1024, 8192), ("gemini", "1024", 8192), ("gemini", 3000, 3000),
    ("anthropic", None, 4096), ("anthropic", 1024, 4096), ("anthropic", 512, 512),
    ("openai", None, None), ("ollama", None, None),
])
def test_output_limit_defaults_and_the_old_setup_value(provider, configured, expected):
    assert max_tokens_for(provider, configured) == expected


@pytest.mark.parametrize("configured,expected", [(None, 8192), (1024, 8192), (2048, 2048)])
def test_gemini_provider_gets_the_default_unless_the_user_chose_a_value(monkeypatch, configured, expected):
    monkeypatch.setenv("GEMINI_API_KEY", GEMINI_KEY)
    cfg = {"enabled": True, "provider": "gemini", "api_key": "${GEMINI_API_KEY}"}
    if configured is not None:
        cfg["max_tokens"] = configured
    assert build_provider(cfg).max_tokens == expected


@pytest.mark.parametrize("configured,expected", [(None, 4096), (1024, 4096), (600, 600)])
def test_anthropic_provider_gets_the_default_unless_the_user_chose_a_value(monkeypatch, configured, expected):
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    cfg = {"enabled": True, "provider": "anthropic", "api_key": "${ANTHROPIC_API_KEY}"}
    if configured is not None:
        cfg["max_tokens"] = configured
    assert build_provider(cfg).max_tokens == expected


def test_the_old_setup_value_carried_to_another_provider_gives_that_providers_default(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    cfg = {"enabled": True, "provider": "gemini", "api_key": "${GEMINI_API_KEY}", "max_tokens": 1024}
    assert build_provider(override_provider(cfg, provider="anthropic")).max_tokens == 4096


def test_answer_length_follows_the_limit():
    assert [answer_char_budget(n) for n in (8192, 4096, 1024)] == [18400, 9200, 2300]
    assert answer_char_budget(None) is None and answer_length_instruction(None) == ""
    assert "8192 tokens" in answer_length_instruction(8192) and "18,400 characters" in answer_length_instruction(8192)


# ── Gemini request ────────────────────────────────────────────────────────────

def test_gemini_request_sends_the_limit_and_a_low_thinking_level():
    with mock.patch("requests.post", return_value=_response(200, _gemini_body("ok", "STOP"))) as post:
        GeminiProvider(model="gemini-3.8-flash", api_key=GEMINI_KEY).chat([{"role": "user", "content": "hi"}])
    config = post.call_args.kwargs["json"]["generationConfig"]
    assert config["maxOutputTokens"] == 8192
    assert config["thinkingConfig"] == {"thinkingLevel": "LOW"}


def test_a_gemini_model_without_a_documented_level_gets_no_thinking_setting():
    assert gemini_options("gemini-2.5-flash") == {}
    with mock.patch("requests.post", return_value=_response(200, _gemini_body("ok", "STOP"))) as post:
        GeminiProvider(model="gemini-9-unknown", api_key=GEMINI_KEY).chat([{"role": "user", "content": "hi"}])
    assert "thinkingConfig" not in post.call_args.kwargs["json"]["generationConfig"]


# ── the flag on each provider ─────────────────────────────────────────────────

def test_gemini_answer_stopped_at_max_tokens_is_flagged():
    with mock.patch("requests.post", return_value=_response(200, _gemini_body("### 1. Modbus Devices (7 Total", "MAX_TOKENS"))):
        answer = GeminiProvider(api_key=GEMINI_KEY).chat([{"role": "user", "content": "hi"}])
    assert answer == "### 1. Modbus Devices (7 Total"
    assert answer.truncated is True and answer.limit == 8192


def test_gemini_answer_that_finished_is_not_flagged():
    with mock.patch("requests.post", return_value=_response(200, _gemini_body("Done.", "STOP"))):
        answer = GeminiProvider(api_key=GEMINI_KEY).chat([{"role": "user", "content": "hi"}])
    assert answer.truncated is False and truncation_notice(answer) is None


def test_gemini_stopping_at_max_tokens_before_any_text_says_so():
    with mock.patch("requests.post", return_value=_response(200, _gemini_body("", "MAX_TOKENS"))):
        with pytest.raises(LLMResponseError, match=r"token limit \(maxOutputTokens 8192\)"):
            GeminiProvider(api_key=GEMINI_KEY).chat([{"role": "user", "content": "hi"}])


def test_anthropic_answer_stopped_at_max_tokens_is_flagged():
    body = {"content": [{"type": "text", "text": "Partial"}], "stop_reason": "max_tokens"}
    with mock.patch("requests.post", return_value=_response(200, body)) as post:
        answer = AnthropicProvider(api_key=ANTHROPIC_KEY).chat([{"role": "user", "content": "hi"}])
    assert post.call_args.kwargs["json"]["max_tokens"] == 4096
    assert answer == "Partial" and answer.truncated is True and answer.limit == 4096


def test_anthropic_answer_that_finished_is_not_flagged():
    body = {"content": [{"type": "text", "text": "Done"}], "stop_reason": "end_turn"}
    with mock.patch("requests.post", return_value=_response(200, body)):
        assert AnthropicProvider(api_key=ANTHROPIC_KEY).chat([{"role": "user", "content": "hi"}]).truncated is False


def test_openai_answer_stopped_at_length_is_flagged_without_a_limit():
    body = {"choices": [{"message": {"role": "assistant", "content": "Partial"}, "finish_reason": "length"}]}
    with mock.patch("requests.post", return_value=_response(200, body)):
        answer = OpenAIProvider(api_key=OPENAI_KEY).chat([{"role": "user", "content": "hi"}])
    assert answer == "Partial" and answer.truncated is True and answer.limit is None


def test_openai_tool_call_cut_at_length_says_so():
    body = {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "get_statistics", "arguments": "{\"x\": "}}]},
        "finish_reason": "length"}]}
    with mock.patch("requests.post", return_value=_response(200, body)):
        with pytest.raises(LLMResponseError, match="output token limit while calling a tool"):
            OpenAIProvider(api_key=OPENAI_KEY).chat([{"role": "user", "content": "hi"}],
                                                    tools=[{"type": "function", "function": {"name": "t"}}])


@pytest.mark.parametrize("body", [
    {"choices": [{"message": {"role": "assistant", "content": "Partial"}, "finish_reason": "length"}]},
    {"choices": [{"message": {"role": "assistant", "content": "Partial"}}], "done_reason": "length"},
])
def test_ollama_answer_stopped_at_the_limit_is_flagged(body):
    with mock.patch("requests.post", return_value=_response(200, body)):
        answer = OllamaProvider().chat([{"role": "user", "content": "hi"}])
    assert answer == "Partial" and answer.truncated is True


def test_ollama_tool_call_cut_at_the_limit_says_so():
    body = {"choices": [{"message": {"role": "assistant", "content": "", "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "get_statistics", "arguments": "{"}}]},
        "finish_reason": "length"}]}
    with mock.patch("requests.post", return_value=_response(200, body)):
        with pytest.raises(LLMResponseError, match="output token limit while calling a tool"):
            OllamaProvider().chat([{"role": "user", "content": "hi"}],
                                  tools=[{"type": "function", "function": {"name": "t"}}])


def test_the_notice_names_the_limit_when_one_was_sent():
    assert "max_tokens 8192" in truncation_notice(ChatResult("x", truncated=True, limit=8192))
    assert "~/.scrutics/ai.yaml" in truncation_notice(ChatResult("x", truncated=True, limit=8192))
    assert "max_tokens" not in truncation_notice(ChatResult("x", truncated=True))
    assert truncation_notice("plain text") is None


# ── the model is told its answer length ───────────────────────────────────────

class _Recorder(LLMProvider):
    def __init__(self, output_limit, reply):
        self.output_limit = output_limit
        self.reply = reply
        self.seen = []

    def chat(self, messages, tools=None, stream=False, timeout=180.0):
        self.seen.append(messages)
        return self.reply


def test_the_system_prompt_states_the_answer_length(session):
    provider = _Recorder(8192, ChatResult("Partial", truncated=True, limit=8192))
    answer = run_agent_loop(provider, session, "hi")
    system = provider.seen[0][0]["content"]
    assert "limited to 8192 tokens" in system and "18,400 characters" in system
    assert answer.truncated is True


def test_no_length_is_stated_when_no_limit_is_sent(session):
    provider = _Recorder(None, "ok")
    run_agent_loop(provider, session, "hi")
    assert "characters" not in provider.seen[0][0]["content"]


# ── the notice in the CLI and the TUI ─────────────────────────────────────────

def test_the_cli_shows_the_answer_and_a_cut_off_notice(monkeypatch, session):
    monkeypatch.setenv("GEMINI_API_KEY", GEMINI_KEY)
    args = cli.build_parser().parse_args(["ai", "--session", session.session_dir, "list the Modbus devices"])
    cfg = {"enabled": True, "provider": "gemini", "model": "gemini-3.8-flash",
           "api_key": "${GEMINI_API_KEY}", "max_tokens": 1024}
    out, err = io.StringIO(), io.StringIO()
    body = _gemini_body("### 1. Modbus Devices Observed on the Network (7 Total", "MAX_TOKENS")
    with mock.patch("scrutics.ai.config.load_ai_config", return_value=cfg), \
         mock.patch("requests.post", return_value=_response(200, body)) as post, \
         redirect_stdout(out), redirect_stderr(err):
        assert cli.run_ai(args) == 0
    printed = out.getvalue()
    assert "(7 Total" in printed
    assert "[Answer cut off: the model reached its output limit (max_tokens 8192)." in printed
    request = post.call_args.kwargs["json"]
    assert request["generationConfig"]["maxOutputTokens"] == 8192
    assert "18,400 characters" in request["systemInstruction"]["parts"][0]["text"]


def test_the_tui_shows_a_cut_off_notice(tmp_path):
    import asyncio
    from scrutics.ui.tui import AIAssistantModal, ScruticsApp

    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            modal = AIAssistantModal(session_dir=str(tmp_path))
            await app.push_screen(modal)
            await pilot.pause()
            modal._on_query_complete(ChatResult("Partial answer", truncated=True, limit=4096), None)
            await pilot.pause()
            return list(modal.query_one("#ai-history").lines)

    lines = asyncio.run(run())
    assert any("Partial answer" in line for line in lines)
    assert any("Answer cut off" in line and "max_tokens 4096" in line for line in lines)


# ── setup no longer writes max_tokens ─────────────────────────────────────────

def test_cli_setup_writes_no_max_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    replies = iter(["4", "", ""])
    with mock.patch("builtins.input", lambda prompt="": next(replies)), \
         mock.patch("requests.get", side_effect=OSError("offline")), redirect_stdout(io.StringIO()):
        cfg = cli._run_ai_onboarding_cli()
    assert cfg is not None and "max_tokens" not in cfg
    assert "max_tokens" not in (tmp_path / ".scrutics" / "ai.yaml").read_text()


def test_tui_setup_writes_no_max_tokens(tmp_path, monkeypatch):
    import asyncio
    from scrutics.ui.tui import AIModelSelectionModal, ScruticsApp

    monkeypatch.setenv("HOME", str(tmp_path))
    results = []

    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            step1 = {"provider_id": "ollama", "var_name": "", "api_key": "",
                     "default_model": "qwen3.5:4b", "model_source": "live"}
            screen = AIModelSelectionModal(step1, ["qwen3.5:4b"])
            await app.push_screen(screen, results.append)
            await pilot.pause()
            with mock.patch.object(screen, "notify", lambda *a, **kw: None):
                screen.confirm()
            await pilot.pause()

    asyncio.run(run())
    assert "max_tokens" not in (tmp_path / ".scrutics" / "ai.yaml").read_text()
    assert results and "max_tokens" not in results[0]


def test_setup_scripts_and_template_write_no_max_tokens():
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scrutics", "config")
    for name in ("scrutics_ai_setup.sh", "scrutics_ai_setup.bat", "ai.yaml"):
        with open(os.path.join(root, name), encoding="utf-8") as f:
            assert "max_tokens" not in f.read(), name


# ── topology chat ─────────────────────────────────────────────────────────────

def _js_function(page, name):
    start = page.index(f"function {name}(")
    depth = 0
    for i in range(page.index("{", start), len(page)):
        depth += {"{": 1, "}": -1}.get(page[i], 0)
        if depth == 0:
            return page[start:i + 1]
    raise AssertionError(f"{name} not closed")


def _chat(tmp_path, function, body):
    node = shutil.which("node")
    if node is None:
        if os.environ.get("CI"):
            pytest.fail("Node.js is required in CI to check the topology page scripts")
        pytest.skip("Node.js not installed")
    page = generate_topology_html({"nodes": [], "edges": []})
    script = "\n".join([
        "var " + re.search(r"AI_MODELS = (\{.*?\});", page).group(0),
        "var " + re.search(r"AI_REQUEST_OPTIONS = (\{.*?\});", page).group(0),
        re.search(r"var TOKEN_LIMIT_MESSAGE = .*?;\n", page, flags=re.S).group(0),
        "var calls = [];",
        f"var BODY = {json.dumps(body)};",
        "function fetch(url, init) { calls.push(JSON.parse(init.body));"
        " return Promise.resolve({ok: true, status: 200, json: function () { return Promise.resolve(BODY); }}); }",
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


CUT_OFF = "[Answer cut off: the model reached its output limit. Ask for a shorter answer.]"


@pytest.mark.parametrize("function,body", [
    ("callGemini", _gemini_body("Partial", "MAX_TOKENS")),
    ("callAnthropic", {"content": [{"type": "text", "text": "Partial"}], "stop_reason": "max_tokens"}),
    ("callOpenAI", {"choices": [{"message": {"content": "Partial"}, "finish_reason": "length"}]}),
])
def test_topology_chat_marks_an_answer_cut_off_at_the_limit(tmp_path, function, body):
    reply = _chat(tmp_path, function, body)["reply"]
    assert reply.startswith("Partial") and reply.endswith(CUT_OFF)


@pytest.mark.parametrize("function,body", [
    ("callGemini", _gemini_body("Whole", "STOP")),
    ("callAnthropic", {"content": [{"type": "text", "text": "Whole"}], "stop_reason": "end_turn"}),
    ("callOpenAI", {"choices": [{"message": {"content": "Whole"}, "finish_reason": "stop"}]}),
])
def test_topology_chat_leaves_a_finished_answer_alone(tmp_path, function, body):
    assert _chat(tmp_path, function, body)["reply"] == "Whole"


def test_topology_chat_gemini_request_and_empty_cut_off(tmp_path):
    out = _chat(tmp_path, "callGemini", _gemini_body("", "MAX_TOKENS"))
    assert out["calls"][0]["generationConfig"] == {
        "temperature": 0.3, "maxOutputTokens": 8192, "thinkingConfig": {"thinkingLevel": "LOW"}}
    assert out["error"].startswith("The model used its token limit before answering")


def test_topology_chat_tells_each_model_its_answer_length():
    page = generate_topology_html({"nodes": [], "edges": []})
    lengths = json.loads(re.search(r"var AI_ANSWER_LENGTH = (\{.*?\});", page).group(1))
    assert "2,300 characters" in lengths["openai"]
    assert "9,200 characters" in lengths["anthropic"]
    assert "18,400 characters" in lengths["gemini"]
    assert "AI_ANSWER_LENGTH[provider]" in page
