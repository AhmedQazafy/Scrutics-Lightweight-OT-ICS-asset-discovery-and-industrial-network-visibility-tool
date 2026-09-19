"""Tests for the OpenAI, Anthropic, and Gemini LLM provider implementations.

Covers request/response parsing, error mapping, tool-call normalization,
env-var API key resolution, and the guarantee that credentials never appear
in exception messages.
"""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from scrutics.ai.provider import (
    LLMConnectionError,
    LLMProviderError,
    LLMResponseError,
    LLMTimeoutError,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_response(status_code: int = 200, json_body: dict = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text or json.dumps(json_body or {})
    resp.json.return_value = json_body or {}
    return resp


def _openai_plain_response(content: str = "Hello there!") -> dict:
    return {
        "choices": [
            {
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ]
    }


def _openai_tool_call_response(fn_name: str = "get_assets", args: dict = None) -> dict:
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_test123",
                            "type": "function",
                            "function": {
                                "name": fn_name,
                                "arguments": json.dumps(args or {}),
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ]
    }


def _anthropic_plain_response(content: str = "Hello there!") -> dict:
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": content}],
    }


def _anthropic_tool_call_response(fn_name: str = "get_assets", input_: dict = None) -> dict:
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "stop_reason": "tool_use",
        "content": [
            {
                "type": "tool_use",
                "id": "toolu_test123",
                "name": fn_name,
                "input": input_ or {},
            }
        ],
    }


def _gemini_plain_response(content: str = "Hello there!") -> dict:
    return {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [{"text": content}],
                },
                "finishReason": "STOP",
            }
        ]
    }


def _gemini_tool_call_response(fn_name: str = "get_assets", args: dict = None) -> dict:
    return {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [
                        {
                            "functionCall": {
                                "id": "call_gemini_test",
                                "name": fn_name,
                                "args": args or {},
                            }
                        }
                    ],
                },
                "finishReason": "STOP",
            }
        ]
    }


# ── OpenAI chat/completions provider ─────────────────────────────────────────

class TestOpenAIProvider(unittest.TestCase):
    def _make_provider(self, model="gpt-4o-mini"):
        from scrutics.ai.openai_provider import OpenAIProvider
        return OpenAIProvider(model=model, api_key="sk-test-key")

    def test_plain_chat_returns_string(self):
        provider = self._make_provider()
        with patch("requests.post", return_value=_make_response(200, _openai_plain_response("Hi!"))):
            result = provider.chat([{"role": "user", "content": "Hello"}])
        self.assertEqual(result, "Hi!")

    def test_tool_call_response_normalized_to_dict(self):
        provider = self._make_provider()
        with patch("requests.post", return_value=_make_response(200, _openai_tool_call_response("get_assets"))):
            result = provider.chat(
                [{"role": "user", "content": "List assets"}],
                tools=[{"type": "function", "function": {"name": "get_assets", "parameters": {}}}],
            )
        self.assertIsInstance(result, dict)
        self.assertIn("tool_calls", result)
        self.assertEqual(result["tool_calls"][0]["function"]["name"], "get_assets")

    def test_connection_error_raises_llm_connection_error(self):
        import requests as req
        provider = self._make_provider()
        with patch("requests.post", side_effect=req.exceptions.ConnectionError("refused")):
            with self.assertRaises(LLMConnectionError):
                provider.chat([{"role": "user", "content": "hi"}])

    def test_timeout_raises_llm_timeout_error(self):
        import requests as req
        provider = self._make_provider()
        with patch("requests.post", side_effect=req.exceptions.Timeout("timed out")):
            with self.assertRaises(LLMTimeoutError):
                provider.chat([{"role": "user", "content": "hi"}])

    def test_401_raises_llm_response_error_without_key_in_message(self):
        provider = self._make_provider()
        with patch("requests.post", return_value=_make_response(401, {"error": "Unauthorized"})):
            with self.assertRaises(LLMResponseError) as ctx:
                provider.chat([{"role": "user", "content": "hi"}])
        self.assertNotIn("sk-test-key", str(ctx.exception))

    def test_missing_api_key_raises_at_construction(self):
        from scrutics.ai.openai_provider import OpenAIProvider
        with self.assertRaises(LLMProviderError):
            OpenAIProvider(model="gpt-4o-mini", api_key="")

    def test_build_provider_dispatches_to_openai(self):
        from scrutics.ai.config import build_provider
        with patch.dict(os.environ, {"MY_OPENAI_KEY": "sk-test"}):
            p = build_provider({"provider": "openai", "model": "gpt-4o-mini", "api_key": "${MY_OPENAI_KEY}"})
        from scrutics.ai.openai_provider import OpenAIProvider
        self.assertIsInstance(p, OpenAIProvider)

    def test_api_key_absent_from_error_message(self):
        """API key value must never appear in any exception string."""
        from scrutics.ai.openai_provider import OpenAIProvider
        provider = OpenAIProvider(model="gpt-4o-mini", api_key="super-secret-key-12345")
        with patch("requests.post", return_value=_make_response(403, {"error": "Forbidden"})):
            with self.assertRaises(LLMResponseError) as ctx:
                provider.chat([{"role": "user", "content": "hi"}])
        self.assertNotIn("super-secret-key-12345", str(ctx.exception))


# ── Anthropic Messages API provider ──────────────────────────────────────────

class TestAnthropicProvider(unittest.TestCase):
    def _make_provider(self, model="claude-haiku-4-5"):
        from scrutics.ai.anthropic_provider import AnthropicProvider
        return AnthropicProvider(model=model, api_key="sk-ant-test-key")

    def test_plain_chat_returns_string(self):
        provider = self._make_provider()
        with patch("requests.post", return_value=_make_response(200, _anthropic_plain_response("Hello!"))):
            result = provider.chat([{"role": "user", "content": "Hello"}])
        self.assertEqual(result, "Hello!")

    def test_tool_call_normalized_to_openai_shape(self):
        provider = self._make_provider()
        body = _anthropic_tool_call_response("get_assets", {"asset_type": "OT"})
        with patch("requests.post", return_value=_make_response(200, body)):
            result = provider.chat(
                [{"role": "user", "content": "List OT assets"}],
                tools=[{"type": "function", "function": {"name": "get_assets", "parameters": {}}}],
            )
        self.assertIsInstance(result, dict)
        self.assertIn("tool_calls", result)
        tc = result["tool_calls"][0]
        self.assertEqual(tc["function"]["name"], "get_assets")
        # arguments must be a JSON string (OpenAI contract)
        args = json.loads(tc["function"]["arguments"])
        self.assertEqual(args, {"asset_type": "OT"})

    def test_connection_error_raises_llm_connection_error(self):
        import requests as req
        provider = self._make_provider()
        with patch("requests.post", side_effect=req.exceptions.ConnectionError("refused")):
            with self.assertRaises(LLMConnectionError):
                provider.chat([{"role": "user", "content": "hi"}])

    def test_timeout_raises_llm_timeout_error(self):
        import requests as req
        provider = self._make_provider()
        with patch("requests.post", side_effect=req.exceptions.Timeout("timed out")):
            with self.assertRaises(LLMTimeoutError):
                provider.chat([{"role": "user", "content": "hi"}])

    def test_401_raises_llm_response_error_without_key_in_message(self):
        provider = self._make_provider()
        with patch("requests.post", return_value=_make_response(401, {})):
            with self.assertRaises(LLMResponseError) as ctx:
                provider.chat([{"role": "user", "content": "hi"}])
        self.assertNotIn("sk-ant-test-key", str(ctx.exception))

    def test_missing_api_key_raises_at_construction(self):
        from scrutics.ai.anthropic_provider import AnthropicProvider
        with self.assertRaises(LLMProviderError):
            AnthropicProvider(api_key="")

    def test_build_provider_dispatches_to_anthropic(self):
        from scrutics.ai.config import build_provider
        with patch.dict(os.environ, {"MY_ANTHROPIC_KEY": "sk-ant-test"}):
            p = build_provider({
                "provider": "anthropic",
                "model": "claude-haiku-4-5",
                "api_key": "${MY_ANTHROPIC_KEY}",
            })
        from scrutics.ai.anthropic_provider import AnthropicProvider
        self.assertIsInstance(p, AnthropicProvider)

    def test_api_key_absent_from_error_message(self):
        from scrutics.ai.anthropic_provider import AnthropicProvider
        provider = AnthropicProvider(model="claude-haiku-4-5", api_key="super-secret-anthropic-9999")
        with patch("requests.post", return_value=_make_response(403, {})):
            with self.assertRaises(LLMResponseError) as ctx:
                provider.chat([{"role": "user", "content": "hi"}])
        self.assertNotIn("super-secret-anthropic-9999", str(ctx.exception))

    def test_tool_schema_uses_input_schema_not_parameters(self):
        """Verifies the outgoing Anthropic request uses input_schema, not parameters."""
        from scrutics.ai.anthropic_provider import _openai_tools_to_anthropic
        openai_tools = [{
            "type": "function",
            "function": {
                "name": "get_assets",
                "description": "Get all assets",
                "parameters": {"type": "object", "properties": {"asset_type": {"type": "string"}}},
            }
        }]
        result = _openai_tools_to_anthropic(openai_tools)
        self.assertEqual(len(result), 1)
        self.assertIn("input_schema", result[0])
        self.assertNotIn("parameters", result[0])
        self.assertEqual(result[0]["name"], "get_assets")


# ── Google Gemini generateContent provider ───────────────────────────────────

class TestGeminiProvider(unittest.TestCase):
    def _make_provider(self, model="gemini-3.8-flash"):
        from scrutics.ai.gemini_provider import GeminiProvider
        return GeminiProvider(model=model, api_key="gemini-test-key")

    def test_plain_chat_returns_string(self):
        provider = self._make_provider()
        with patch("requests.post", return_value=_make_response(200, _gemini_plain_response("Hi there!"))):
            result = provider.chat([{"role": "user", "content": "Hello"}])
        self.assertEqual(result, "Hi there!")

    def test_tool_call_normalized_to_openai_shape(self):
        provider = self._make_provider()
        body = _gemini_tool_call_response("get_statistics", {})
        with patch("requests.post", return_value=_make_response(200, body)):
            result = provider.chat(
                [{"role": "user", "content": "How many devices?"}],
                tools=[{"type": "function", "function": {"name": "get_statistics", "parameters": {}}}],
            )
        self.assertIsInstance(result, dict)
        self.assertIn("tool_calls", result)
        tc = result["tool_calls"][0]
        self.assertEqual(tc["function"]["name"], "get_statistics")
        # arguments must be JSON string
        args = json.loads(tc["function"]["arguments"])
        self.assertEqual(args, {})

    def test_connection_error_raises_llm_connection_error(self):
        import requests as req
        provider = self._make_provider()
        with patch("requests.post", side_effect=req.exceptions.ConnectionError("refused")):
            with self.assertRaises(LLMConnectionError):
                provider.chat([{"role": "user", "content": "hi"}])

    def test_timeout_raises_llm_timeout_error(self):
        import requests as req
        provider = self._make_provider()
        with patch("requests.post", side_effect=req.exceptions.Timeout("timed out")):
            with self.assertRaises(LLMTimeoutError):
                provider.chat([{"role": "user", "content": "hi"}])

    def test_401_raises_llm_response_error_without_key_in_message(self):
        provider = self._make_provider()
        with patch("requests.post", return_value=_make_response(401, {})):
            with self.assertRaises(LLMResponseError) as ctx:
                provider.chat([{"role": "user", "content": "hi"}])
        self.assertNotIn("gemini-test-key", str(ctx.exception))

    def test_missing_api_key_raises_at_construction(self):
        from scrutics.ai.gemini_provider import GeminiProvider
        with self.assertRaises(LLMProviderError):
            GeminiProvider(api_key="")

    def test_build_provider_dispatches_to_gemini(self):
        from scrutics.ai.config import build_provider
        with patch.dict(os.environ, {"MY_GEMINI_KEY": "gemini-test"}):
            p = build_provider({
                "provider": "gemini",
                "model": "gemini-3.8-flash",
                "api_key": "${MY_GEMINI_KEY}",
            })
        from scrutics.ai.gemini_provider import GeminiProvider
        self.assertIsInstance(p, GeminiProvider)

    def test_api_key_absent_from_error_message(self):
        from scrutics.ai.gemini_provider import GeminiProvider
        provider = GeminiProvider(model="gemini-3.8-flash", api_key="super-secret-gemini-ABCDEF")
        with patch("requests.post", return_value=_make_response(403, {})):
            with self.assertRaises(LLMResponseError) as ctx:
                provider.chat([{"role": "user", "content": "hi"}])
        self.assertNotIn("super-secret-gemini-ABCDEF", str(ctx.exception))

    def test_tool_schema_uses_function_declarations(self):
        """Verifies Gemini request wraps tools in functionDeclarations."""
        from scrutics.ai.gemini_provider import _openai_tools_to_gemini
        openai_tools = [{
            "type": "function",
            "function": {
                "name": "get_assets",
                "description": "Get all assets",
                "parameters": {"type": "object", "properties": {}},
            }
        }]
        result = _openai_tools_to_gemini(openai_tools)
        self.assertEqual(len(result), 1)
        self.assertIn("functionDeclarations", result[0])
        self.assertEqual(result[0]["functionDeclarations"][0]["name"], "get_assets")

    def test_api_key_is_query_param_not_header(self):
        """Verify the API key appears in the URL, not in headers."""
        provider = self._make_provider()
        captured_calls = []

        def capture(*args, **kwargs):
            captured_calls.append((args, kwargs))
            return _make_response(200, _gemini_plain_response("ok"))

        with patch("requests.post", side_effect=capture):
            provider.chat([{"role": "user", "content": "hi"}])

        url = captured_calls[0][0][0] if captured_calls[0][0] else captured_calls[0][1].get("url", "")
        if not url and "url" in captured_calls[0][1]:
            url = captured_calls[0][1]["url"]
        self.assertIn("key=gemini-test-key", url)
        headers = captured_calls[0][1].get("headers", {})
        for v in headers.values():
            self.assertNotIn("gemini-test-key", str(v))


# ── env-var resolution tests ──────────────────────────────────────────────────

class TestEnvVarResolution(unittest.TestCase):
    def test_resolve_set_var(self):
        from scrutics.ai.config import _resolve_env_var
        with patch.dict(os.environ, {"TEST_KEY_XYZ": "my-actual-key"}):
            self.assertEqual(_resolve_env_var("${TEST_KEY_XYZ}"), "my-actual-key")

    def test_resolve_unset_var_raises(self):
        from scrutics.ai.config import _resolve_env_var
        env_without_var = {k: v for k, v in os.environ.items() if k != "SCRUTICS_MISSING_VAR_TEST"}
        with patch.dict(os.environ, env_without_var, clear=True):
            with self.assertRaises(LLMProviderError) as ctx:
                _resolve_env_var("${SCRUTICS_MISSING_VAR_TEST}")
        self.assertIn("SCRUTICS_MISSING_VAR_TEST", str(ctx.exception))

    def test_non_env_var_string_passes_through(self):
        from scrutics.ai.config import _resolve_env_var
        self.assertEqual(_resolve_env_var("literal-value"), "literal-value")

    def test_unrecognized_provider_still_raises(self):
        from scrutics.ai.config import build_provider
        with self.assertRaises(LLMProviderError) as ctx:
            build_provider({"provider": "cohere", "model": "command"})
        self.assertIn("cohere", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
