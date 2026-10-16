"""--provider never sends the configured provider's key, model or base URL to a different provider."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import pytest

from scrutics import cli
from scrutics.ai import diagnostics
from scrutics.ai.config import (
    DEFAULT_ANTHROPIC_MODEL,
    DEFAULT_GEMINI_MODEL,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OPENAI_MODEL,
    ProviderOverrideError,
    override_provider,
)

GEMINI_KEY = "gemini-key-configured-111"
OPENAI_KEY = "openai-key-from-env-222"
ANTHROPIC_KEY = "anthropic-key-from-env-333"

GEMINI_CFG = {
    "enabled": True, "provider": "gemini", "model": "gemini-3.8-flash",
    "api_key": "${GEMINI_API_KEY}", "base_url": "https://proxy.example/gemini",
    "temperature": 0.2, "max_tokens": 512, "timeout": 45,
}
HOSTS = {
    "openai": "https://api.openai.com/",
    "anthropic": "https://api.anthropic.com/",
    "gemini": "https://generativelanguage.googleapis.com/",
    "ollama": "http://localhost:11434/",
}
DEFAULTS = {
    "openai": DEFAULT_OPENAI_MODEL, "anthropic": DEFAULT_ANTHROPIC_MODEL,
    "gemini": DEFAULT_GEMINI_MODEL, "ollama": DEFAULT_OLLAMA_MODEL,
}


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    for var in ("GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", GEMINI_KEY)
    with mock.patch("time.sleep"):
        yield


class _Sent:
    """Records every request instead of sending it; answers 401."""

    def __init__(self):
        self.requests = []

    def __call__(self, url, *args, **kwargs):
        self.requests.append({"url": url, "headers": dict(kwargs.get("headers") or {}),
                              "body": kwargs.get("json")})
        resp = mock.Mock(status_code=401, headers={}, text="{}")
        resp.json.return_value = {}
        return resp


def _session(tmp_path):
    session = tmp_path / "session"
    session.mkdir(parents=True)
    stats = {k: 0 for k in ("asset_count", "ot_count", "it_count", "unknown_count",
                            "connection_count", "anomaly_count")}
    (session / "manifest.json").write_text(json.dumps({
        "format": "scrutics-evidence", "version": 1, "scrutics_version": "0.7",
        "created_at": "2026-10-16T00:00:00Z", "capture_started": "2026-10-16T00:00:00Z",
        "capture_ended": "2026-10-16T00:01:00Z", "sensor_id": "s", "scope": {},
        "files": {}, "stats": stats,
    }))
    return str(session)


def _run_ai(argv, cfg):
    sent = _Sent()
    out, err = io.StringIO(), io.StringIO()
    args = cli.build_parser().parse_args(argv)
    with mock.patch("scrutics.ai.config.load_ai_config", return_value=dict(cfg)), \
         mock.patch("requests.post", sent), mock.patch("requests.get", sent), \
         redirect_stdout(out), redirect_stderr(err):
        rc = cli.run_ai(args)
    return rc, out.getvalue() + err.getvalue(), sent.requests


# ── the override rule ─────────────────────────────────────────────────────────

def test_same_provider_keeps_the_configuration_and_takes_the_model():
    cfg = override_provider(GEMINI_CFG, "Gemini", "gemini-2.5-flash")
    assert cfg == {**GEMINI_CFG, "model": "gemini-2.5-flash"}


def test_model_alone_changes_only_the_model():
    assert override_provider(GEMINI_CFG, None, "m2") == {**GEMINI_CFG, "model": "m2"}
    assert override_provider(GEMINI_CFG) == GEMINI_CFG


@pytest.mark.parametrize("provider,var,key", [
    ("openai", "OPENAI_API_KEY", OPENAI_KEY),
    ("anthropic", "ANTHROPIC_API_KEY", ANTHROPIC_KEY),
])
def test_a_different_provider_takes_nothing_from_the_account(monkeypatch, provider, var, key):
    monkeypatch.setenv(var, key)
    cfg = override_provider(GEMINI_CFG, provider)
    assert cfg == {"enabled": True, "provider": provider, "model": DEFAULTS[provider],
                   "api_key": f"${{{var}}}", "max_tokens": 512}
    assert override_provider(GEMINI_CFG, provider, "chosen-model")["model"] == "chosen-model"


def test_ollama_needs_no_key_and_does_not_inherit_the_base_url():
    cfg = override_provider(GEMINI_CFG, "ollama")
    assert "api_key" not in cfg and "base_url" not in cfg
    assert cfg["model"] == DEFAULT_OLLAMA_MODEL


@pytest.mark.parametrize("provider", ["openai", "anthropic", "ollama"])
def test_only_max_tokens_carries_over_to_a_different_provider(monkeypatch, provider):
    monkeypatch.setenv("OPENAI_API_KEY", OPENAI_KEY)
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    cfg = override_provider(GEMINI_CFG, provider)
    assert cfg["max_tokens"] == 512
    assert "timeout" not in cfg and "temperature" not in cfg


def test_a_different_provider_uses_its_own_timeout(monkeypatch):
    from scrutics.ai.config import build_provider

    monkeypatch.setenv("OPENAI_API_KEY", OPENAI_KEY)
    assert build_provider(override_provider(GEMINI_CFG, "openai")).timeout == 60.0
    assert build_provider(override_provider(GEMINI_CFG, "ollama")).timeout == 180.0


def test_a_missing_key_is_refused_with_the_variable_to_set():
    with pytest.raises(ProviderOverrideError) as info:
        override_provider(GEMINI_CFG, "openai")
    message = str(info.value)
    assert "OPENAI_API_KEY" in message and "never sent to another provider" in message
    assert override_provider(GEMINI_CFG, "openai", require_key=False)["api_key"] == "${OPENAI_API_KEY}"


def test_the_given_configuration_is_not_modified(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", OPENAI_KEY)
    before = dict(GEMINI_CFG)
    override_provider(GEMINI_CFG, "openai", "m")
    assert GEMINI_CFG == before


def test_an_unknown_provider_is_refused():
    with pytest.raises(Exception, match="Unsupported LLM provider"):
        override_provider(GEMINI_CFG, "mistral")


# ── scrutics ai ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("provider,var", [("openai", "OPENAI_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY")])
def test_ai_without_the_providers_key_sends_nothing(tmp_path, provider, var):
    rc, output, requests_sent = _run_ai(
        ["ai", "--session", _session(tmp_path), "--provider", provider, "hi"], GEMINI_CFG)
    assert rc == 1
    assert var in output
    assert requests_sent == []


@pytest.mark.parametrize("provider,var,key", [
    ("openai", "OPENAI_API_KEY", OPENAI_KEY),
    ("anthropic", "ANTHROPIC_API_KEY", ANTHROPIC_KEY),
])
def test_ai_sends_only_that_providers_key_and_model(monkeypatch, tmp_path, provider, var, key):
    monkeypatch.setenv(var, key)
    _rc, _output, requests_sent = _run_ai(
        ["ai", "--session", _session(tmp_path), "--provider", provider, "hi"], GEMINI_CFG)
    assert requests_sent
    for req in requests_sent:
        assert req["url"].startswith(HOSTS[provider])
        assert key in json.dumps(req["headers"])
        assert GEMINI_KEY not in json.dumps(req)
        assert req["body"]["model"] == DEFAULTS[provider]


def test_ai_model_option_applies_to_the_chosen_provider(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", OPENAI_KEY)
    _rc, _output, requests_sent = _run_ai(
        ["ai", "--session", _session(tmp_path), "--provider", "openai", "--model", "gpt-6-sol", "hi"],
        GEMINI_CFG)
    assert [req["body"]["model"] for req in requests_sent] == ["gpt-6-sol"]


def test_ai_with_the_configured_provider_is_unchanged(tmp_path):
    _rc, _output, requests_sent = _run_ai(
        ["ai", "--session", _session(tmp_path), "--provider", "gemini", "hi"], GEMINI_CFG)
    assert requests_sent
    assert all(req["headers"].get("x-goog-api-key") == GEMINI_KEY for req in requests_sent)


def test_a_custom_base_url_stays_with_its_provider(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", OPENAI_KEY)
    ollama_cfg = {"enabled": True, "provider": "ollama", "model": "llama", "base_url": "http://10.20.30.40:11434"}
    _rc, _output, requests_sent = _run_ai(
        ["ai", "--session", _session(tmp_path), "--provider", "openai", "hi"], ollama_cfg)
    assert requests_sent and all(r["url"].startswith(HOSTS["openai"]) for r in requests_sent)

    openai_cfg = {"enabled": True, "provider": "openai", "model": "gpt-4o-mini",
                  "api_key": "${OPENAI_API_KEY}", "base_url": "http://10.20.30.40:8000"}
    _rc, _output, requests_sent = _run_ai(
        ["ai", "--session", _session(tmp_path / "b"), "--provider", "ollama", "hi"], openai_cfg)
    assert requests_sent and all(r["url"].startswith(HOSTS["ollama"]) for r in requests_sent)
    assert all(OPENAI_KEY not in json.dumps(r) for r in requests_sent)


# ── scrutics ai diagnose ──────────────────────────────────────────────────────

def _diagnose(provider, model=None):
    sent = _Sent()
    buf = io.StringIO()
    with mock.patch("scrutics.ai.diagnostics.load_ai_config", return_value=dict(GEMINI_CFG)), \
         mock.patch.object(diagnostics.socket, "gethostbyname", return_value="0.0.0.0"), \
         mock.patch.object(diagnostics.socket, "create_connection"), \
         mock.patch.object(diagnostics.ssl, "create_default_context"), \
         mock.patch("requests.post", sent), mock.patch("requests.get", sent):
        rc = diagnostics.run_ai_diagnostics(provider_name=provider, model_name=model, stream=buf)
    return rc, buf.getvalue(), sent.requests


@pytest.mark.parametrize("provider,var", [("openai", "OPENAI_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY")])
def test_diagnose_without_the_providers_key_stops_at_the_key_stage(provider, var):
    rc, output, requests_sent = _diagnose(provider)
    assert rc == 1
    assert f"provider={provider}, model={DEFAULTS[provider]}" in output
    assert "[02/14] API key presence" in output and var in output
    assert requests_sent == []


@pytest.mark.parametrize("provider,var,key", [
    ("openai", "OPENAI_API_KEY", OPENAI_KEY),
    ("anthropic", "ANTHROPIC_API_KEY", ANTHROPIC_KEY),
])
def test_diagnose_sends_only_that_providers_key(monkeypatch, provider, var, key):
    monkeypatch.setenv(var, key)
    _rc, output, requests_sent = _diagnose(provider, "chosen-model")
    assert f"provider={provider}, model=chosen-model" in output
    assert requests_sent
    for req in requests_sent:
        assert req["url"].startswith(HOSTS[provider])
        assert key in json.dumps(req["headers"])
        assert GEMINI_KEY not in json.dumps(req)


def test_diagnose_from_the_cli_passes_provider_and_model():
    args = cli.build_parser().parse_args(["ai", "--diagnose", "--provider", "openai", "--model", "m"])
    with mock.patch("scrutics.ai.diagnostics.run_ai_diagnostics", return_value=0) as run:
        assert cli.run_ai(args) == 0
    run.assert_called_once_with(provider_name="openai", model_name="m")


def test_diagnose_names_the_variable_of_the_configured_provider():
    buf = io.StringIO()
    diagnostics.run_ai_diagnostics(cfg_override={"provider": "anthropic", "model": "m", "api_key": ""}, stream=buf)
    assert "ANTHROPIC_API_KEY" in buf.getvalue()
