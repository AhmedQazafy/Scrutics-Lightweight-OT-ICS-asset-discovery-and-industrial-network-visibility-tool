"""Tests for the Ollama LLM provider and AI configuration loading.

Covers OllamaProvider chat completion (streaming and non-streaming),
error mapping, reasoning_effort validation, ai.yaml loading,
build_provider() dispatch, and defensive response parsing.
"""

import json
from unittest.mock import patch, MagicMock
import pytest
import requests

from scrutics.ai.provider import (
    LLMProvider,
    LLMProviderError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMResponseError,
)
from scrutics.ai.ollama_provider import OllamaProvider
from scrutics.ai.config import load_ai_config, build_provider


def test_ollama_chat_success_non_stream():
    """1. Successful chat completion (non-streaming) returns expected string."""
    provider = OllamaProvider(model="qwen3.5:4b", base_url="http://localhost:11434")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Hello, ICS engineer!",
                }
            }
        ]
    }

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = provider.chat([{"role": "user", "content": "hello"}], stream=False)
        assert result == "Hello, ICS engineer!"
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert kwargs["json"]["stream"] is False
        assert kwargs["json"]["model"] == "qwen3.5:4b"


def test_ollama_chat_success_stream():
    """2. Successful streaming chat completion yields expected string chunks."""
    provider = OllamaProvider(model="qwen3.5:4b", base_url="http://localhost:11434")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    # Simulate SSE lines
    sse_lines = [
        "",  # empty line should be ignored
        'data: {"choices": [{"delta": {"content": "Hello"}}]}',
        'data: {"choices": [{"delta": {"content": " "}}]}',
        'data: {"choices": [{"delta": {}}]}',  # empty delta ignored
        'data: {"choices": [{"delta": {"content": "World"}}]}',
        "data: [DONE]",
    ]
    mock_resp.iter_lines.return_value = iter(sse_lines)

    with patch("requests.post", return_value=mock_resp):
        chunks = list(provider.chat([{"role": "user", "content": "hi"}], stream=True))
        assert chunks == ["Hello", " ", "World"]
        mock_resp.close.assert_called_once()


def test_ollama_connection_refused():
    """3. Connection refused raises LLMConnectionError."""
    provider = OllamaProvider()
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        with pytest.raises(LLMConnectionError) as exc_info:
            provider.chat([{"role": "user", "content": "hi"}], stream=False)
        assert "Cannot connect to Ollama" in str(exc_info.value)
        assert "ollama serve" in str(exc_info.value)

    # Also test stream path connection refused
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        with pytest.raises(LLMConnectionError):
            provider.chat([{"role": "user", "content": "hi"}], stream=True)


def test_ollama_timeout():
    """4. Request timeout raises LLMTimeoutError."""
    provider = OllamaProvider()
    with patch("requests.post", side_effect=requests.exceptions.Timeout("Read timed out")):
        with pytest.raises(LLMTimeoutError) as exc_info:
            provider.chat([{"role": "user", "content": "hi"}], timeout=5.0)
        assert "timed out after 5.0s" in str(exc_info.value)

    # Mid-stream timeout
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    def stream_timeout_generator(*args, **kwargs):
        yield 'data: {"choices": [{"delta": {"content": "Start"}}]}'
        raise requests.exceptions.Timeout("Stream stalled")

    mock_resp.iter_lines = stream_timeout_generator
    with patch("requests.post", return_value=mock_resp):
        gen = provider.chat([{"role": "user", "content": "hi"}], stream=True)
        assert next(gen) == "Start"
        with pytest.raises(LLMTimeoutError):
            next(gen)


def test_ollama_non_200_response():
    """5. Non-200 response raises LLMResponseError."""
    provider = OllamaProvider()
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"
    mock_resp.json.side_effect = ValueError("No JSON")

    with patch("requests.post", return_value=mock_resp):
        with pytest.raises(LLMResponseError) as exc_info:
            provider.chat([{"role": "user", "content": "hi"}])
        assert "Ollama returned HTTP 500" in str(exc_info.value)


def test_ollama_malformed_response():
    """6. Malformed or missing-field response body raises LLMResponseError."""
    provider = OllamaProvider()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"unexpected": "payload"}

    with patch("requests.post", return_value=mock_resp):
        with pytest.raises(LLMResponseError) as exc_info:
            provider.chat([{"role": "user", "content": "hi"}])
        assert "Unexpected response structure" in str(exc_info.value)


def test_ollama_model_not_found_heuristic():
    """Ollama returns 404 with model not found -> raises with pull hint."""
    provider = OllamaProvider(model="qwen3.5:4b")
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.json.return_value = {"error": "model 'qwen3.5:4b' not found"}

    with patch("requests.post", return_value=mock_resp):
        with pytest.raises(LLMResponseError) as exc_info:
            provider.chat([{"role": "user", "content": "hi"}])
        assert "Model 'qwen3.5:4b' not found" in str(exc_info.value)
        assert "ollama pull qwen3.5:4b" in str(exc_info.value)


def test_ollama_non_matching_404_graceful_fallback():
    """Ollama 404 with unrecognised error text falls back gracefully to generic LLMResponseError."""
    provider = OllamaProvider(model="qwen3.5:4b")
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.json.return_value = {"error": "endpoint route not found"}

    with patch("requests.post", return_value=mock_resp):
        with pytest.raises(LLMResponseError) as exc_info:
            provider.chat([{"role": "user", "content": "hi"}])
        # Verifies it does NOT raise model hint, but does raise generic HTTP 404 error
        assert "Ollama returned HTTP 404" in str(exc_info.value)
        assert "endpoint route not found" in str(exc_info.value)


def test_load_ai_config_missing_returns_empty(monkeypatch, tmp_path):
    """7. load_ai_config() returns {} when no user override and no packaged default exist."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))

    # Also remove the packaged default fallback so load_ai_config() truly finds nothing
    import scrutics.ai.config as _cfg_mod
    monkeypatch.setattr(_cfg_mod, "_DEFAULT_PKG_AI_CONFIG", str(tmp_path / "nonexistent.yaml"))

    config = load_ai_config()
    assert config == {}


def test_load_ai_config_valid(monkeypatch, tmp_path):
    """8. load_ai_config() correctly parses a valid ~/.scrutics/ai.yaml override."""
    fake_home = tmp_path / "fake_home"
    scrutics_dir = fake_home / ".scrutics"
    scrutics_dir.mkdir(parents=True)
    ai_yaml = scrutics_dir / "ai.yaml"
    ai_yaml.write_text(
        "provider: ollama\nmodel: custom-model\nbase_url: http://10.0.0.5:11434\ntemperature: 0.7\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))

    config = load_ai_config()
    assert config["provider"] == "ollama"
    assert config["model"] == "custom-model"
    assert config["base_url"] == "http://10.0.0.5:11434"
    assert config["temperature"] == 0.7


def test_build_provider_default_ollama():
    """9. build_provider() returns an OllamaProvider instance when provider: ollama or config is empty."""
    # From empty config (default)
    provider1 = build_provider({})
    assert isinstance(provider1, OllamaProvider)
    assert provider1.model == "qwen3.5:4b"

    # From explicit ollama config
    provider2 = build_provider({"provider": "ollama", "model": "mistral:7b"})
    assert isinstance(provider2, OllamaProvider)
    assert provider2.model == "mistral:7b"


def test_build_provider_unrecognized_raises():
    """10. build_provider() raises LLMProviderError for an unrecognized provider."""
    with pytest.raises(LLMProviderError) as exc_info:
        build_provider({"provider": "nonexistent_provider_xyz"})
    assert "nonexistent_provider_xyz" in str(exc_info.value)


# ── Part A: Qwen3.5 reasoning_effort and defensive parsing tests ───────────────

def test_packaged_ai_yaml_includes_reasoning_effort():
    """Part A.1: Packaged ai.yaml template has correct defaults (enabled: false, reasoning_effort: low)."""
    import yaml
    from scrutics.ai.config import _DEFAULT_PKG_AI_CONFIG

    with open(_DEFAULT_PKG_AI_CONFIG, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    # The packaged template must ship with AI disabled so it can never be accidentally active
    assert data.get("enabled") is False
    # Ollama reasoning effort default must be 'low'
    assert data.get("reasoning_effort") == "low"


def test_build_provider_reasoning_effort_handling():
    """Part A.2 & A.3: build_provider reads reasoning_effort and defaults to 'low'."""
    # Defaults to 'low'
    provider_default = build_provider({})
    assert isinstance(provider_default, OllamaProvider)
    assert provider_default.reasoning_effort == "low"

    # Reads configured value
    provider_none = build_provider({"provider": "ollama", "reasoning_effort": "none"})
    assert provider_none.reasoning_effort == "none"

    provider_high = build_provider({"provider": "ollama", "reasoning_effort": "high"})
    assert provider_high.reasoning_effort == "high"


def test_build_provider_invalid_reasoning_effort_raises():
    """Part A.4: build_provider raises LLMProviderError for invalid reasoning_effort."""
    with pytest.raises(LLMProviderError) as exc_info:
        build_provider({"provider": "ollama", "reasoning_effort": "maximum"})
    assert "Invalid reasoning_effort 'maximum'" in str(exc_info.value)


def test_ollama_chat_payload_includes_reasoning_effort():
    """Part A.5: OllamaProvider.chat() sends reasoning_effort in post payload."""
    provider = OllamaProvider(model="qwen3.5:4b", reasoning_effort="medium")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"role": "assistant", "content": "Hi"}}]
    }

    with patch("requests.post", return_value=mock_resp) as mock_post:
        provider.chat([{"role": "user", "content": "hello"}])
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["reasoning_effort"] == "medium"


def test_ollama_chat_reasoning_only_raises_informative_error():
    """Part A.6: Model response with empty content and reasoning raises LLMResponseError."""
    provider = OllamaProvider(model="qwen3.5:4b")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "reasoning": "Thinking step 1... wait, is 'hello' right? Let's check...",
                }
            }
        ]
    }

    with patch("requests.post", return_value=mock_resp):
        with pytest.raises(LLMResponseError) as exc_info:
            provider.chat([{"role": "user", "content": "hello"}])
        assert "reasoning content without a final answer" in str(exc_info.value)
        assert "reasoning_effort" in str(exc_info.value)

