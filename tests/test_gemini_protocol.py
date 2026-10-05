"""Regression tests for Gemini protocol correctness, thought signatures, and retry behavior.

Covers:
  - Lazy optional dependency boundary (core-only imports without requests)
  - Model default consistency
  - FunctionCall ID preservation, thought signature on Part (functionCall & text),
    parallel function calls structure, functionResponse grouping.
  - Bounded exponential backoff, RetryInfo parsing, RPC status mapping, sanitized errors.
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

import requests

from scrutics.ai.provider import (
    ChatResult,
    ToolCall,
    LLMProvider,
    LLMProviderError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMResponseError,
)
from scrutics.ai.gemini_provider import (
    GeminiProvider,
    _translate_messages_to_gemini,
    _normalize_gemini_response,
    _extract_retry_delay,
    _format_gemini_error,
)


def _make_response(status_code: int, body: dict, headers: dict | None = None) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = json.dumps(body).encode("utf-8")
    resp.headers = headers or {"Content-Type": "application/json"}
    return resp


class TestGeminiProtocolCorrectness(unittest.TestCase):
    """Tests for FunctionCall IDs, thought signatures, and parallel calls."""

    def test_function_call_id_preserved_without_fallback_to_name(self):
        """C1: ID is preserved when present, and NOT replaced with function name when absent."""
        # Case 1: Genuine ID present
        resp_with_id = {
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{
                        "functionCall": {
                            "id": "call_abc_123",
                            "name": "get_assets",
                            "args": {"limit": 10},
                        }
                    }]
                }
            }]
        }
        res = _normalize_gemini_response(resp_with_id)
        self.assertIsInstance(res, dict)
        self.assertEqual(res["tool_calls"][0]["id"], "call_abc_123")
        self.assertEqual(res["tool_calls"][0]["function"]["name"], "get_assets")

        # Case 2: Missing ID: must remain empty string, never become 'get_assets'
        resp_without_id = {
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{
                        "functionCall": {
                            "name": "get_assets",
                            "args": {},
                        }
                    }]
                }
            }]
        }
        res_no_id = _normalize_gemini_response(resp_without_id)
        self.assertEqual(res_no_id["tool_calls"][0]["id"], "")
        self.assertNotEqual(res_no_id["tool_calls"][0]["id"], "get_assets")

    def test_function_response_id_round_trip(self):
        """C1: functionResponse receives the matching tool_call_id on replay."""
        messages = [
            {"role": "user", "content": "list devices"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_target_999",
                        "function": {"name": "get_statistics", "arguments": "{}"},
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "call_target_999",
                "name": "get_statistics",
                "content": json.dumps({"total_assets": 5}),
            },
        ]
        _, contents = _translate_messages_to_gemini(messages)
        # Find functionResponse part
        fr_part = None
        for c in contents:
            for p in c.get("parts", []):
                if "functionResponse" in p:
                    fr_part = p["functionResponse"]
        self.assertIsNotNone(fr_part)
        self.assertEqual(fr_part.get("id"), "call_target_999")
        self.assertEqual(fr_part.get("name"), "get_statistics")

    def test_thought_signature_on_function_call_part(self):
        """C3: thoughtSignature on Part is captured and replayed on outbound Part."""
        resp = {
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{
                        "functionCall": {
                            "id": "call_1",
                            "name": "get_asset",
                            "args": {"ip": "10.0.0.1"},
                        },
                        "thoughtSignature": "encrypted_sig_A1B2C3D4",
                    }]
                }
            }]
        }
        normalized = _normalize_gemini_response(resp)
        self.assertEqual(normalized["tool_calls"][0]["thought_signature"], "encrypted_sig_A1B2C3D4")

        # Now verify outbound replay attaches it to Part.thoughtSignature (NOT inside functionCall)
        messages = [
            {"role": "user", "content": "inspect asset"},
            normalized,
            {"role": "tool", "tool_call_id": "call_1", "name": "get_asset", "content": '{"status": "ok"}'},
        ]
        _, contents = _translate_messages_to_gemini(messages)
        model_content = next(c for c in contents if c.get("role") == "model")
        part = model_content["parts"][0]
        # Must be on part
        self.assertEqual(part.get("thoughtSignature"), "encrypted_sig_A1B2C3D4")
        # Must NOT be inside functionCall
        self.assertNotIn("thought_signature", part["functionCall"])
        self.assertNotIn("thoughtSignature", part["functionCall"])

    def test_text_only_thought_signature_preserved_via_chat_result(self):
        """C2: text-part thoughtSignature is returned on ChatResult and survives replay."""
        # Case 1: Model with text-part signature (Gemini 3)
        resp_with_sig = {
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{
                        "text": "The network has 12 PLCs observed.",
                        "thoughtSignature": "sig_text_xyz789",
                    }]
                }
            }]
        }
        result = _normalize_gemini_response(resp_with_sig)
        self.assertIsInstance(result, str)
        self.assertIsInstance(result, ChatResult)
        self.assertEqual(result, "The network has 12 PLCs observed.")
        self.assertEqual(result.thought_signature, "sig_text_xyz789")

        # Replay text turn in history
        messages = [
            {"role": "user", "content": "How many PLCs?"},
            {"role": "assistant", "content": str(result), "thought_signature": result.thought_signature},
            {"role": "user", "content": "What vendors?"},
        ]
        _, contents = _translate_messages_to_gemini(messages)
        model_content = contents[1]
        self.assertEqual(model_content["role"], "model")
        self.assertEqual(model_content["parts"][0]["text"], "The network has 12 PLCs observed.")
        self.assertEqual(model_content["parts"][0]["thoughtSignature"], "sig_text_xyz789")

        # Case 2: Model without text-part signature (Gemini 2.x / standard)
        resp_no_sig = {
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"text": "Hello, engineer!"}]
                }
            }]
        }
        result_no_sig = _normalize_gemini_response(resp_no_sig)
        self.assertIsInstance(result_no_sig, str)
        self.assertIsNone(result_no_sig.thought_signature)

    def test_trace_full_path_gemini_to_agent_loop_to_outbound_replay(self):
        """Trace exact path: Gemini response -> normalization -> agent messages.append -> _translate -> outbound payload."""
        expected_sig = "E4_MOCK_GEMINI_SIGNATURE_ABCD"
        gemini_raw_resp = {
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{
                        "thoughtSignature": expected_sig,
                        "functionCall": {
                            "id": "call_trace_001",
                            "name": "get_statistics",
                            "args": {},
                        }
                    }]
                }
            }]
        }

        # Hop 1: Normalization
        norm = _normalize_gemini_response(gemini_raw_resp)
        self.assertIsInstance(norm, dict)
        self.assertEqual(norm["role"], "assistant")
        self.assertEqual(norm.get("thought_signature"), expected_sig)
        self.assertEqual(norm["tool_calls"][0]["thought_signature"], expected_sig)

        # Hop 2: Agent loop appends to messages (agent.py line 108: messages.append(response))
        messages = [
            {"role": "user", "content": "Network status?"},
        ]
        # Agent loop appends the structured response verbatim
        messages.append(norm)

        # Hop 3: Agent loop appends tool result (agent.py line 141)
        messages.append({
            "role": "tool",
            "tool_call_id": "call_trace_001",
            "name": "get_statistics",
            "content": json.dumps({"asset_count": 5}),
        })

        # Hop 4: Replay into _translate_messages_to_gemini
        sys_instr, outbound_contents = _translate_messages_to_gemini(messages)

        # Hop 5: Outbound wire representation validation
        model_part = outbound_contents[1]["parts"][0]
        self.assertIn("functionCall", model_part)
        self.assertEqual(model_part["functionCall"]["id"], "call_trace_001")
        self.assertEqual(model_part["thoughtSignature"], expected_sig)

        # Confirm ChatResult object directly placed in {"role": "assistant", "content": chat_result}
        # also has its signature extracted during translation even without a top-level dict key
        text_sig = "SIG_CHAT_RESULT_TEXT_002"
        text_cr = ChatResult("All systems normal.", thought_signature=text_sig)
        chat_messages = [
            {"role": "user", "content": "Report status"},
            {"role": "assistant", "content": text_cr},
            {"role": "user", "content": "Next step?"},
        ]
        _, chat_outbound = _translate_messages_to_gemini(chat_messages)
        text_model_part = chat_outbound[1]["parts"][0]
        self.assertEqual(text_model_part["text"], "All systems normal.")
        self.assertEqual(text_model_part["thoughtSignature"], text_sig)

    def test_parallel_function_calls_structure_and_signature(self):
        """C4 & C5: Parallel calls remain in single Content block, signature only on first call."""
        # Incoming response with parallel calls
        resp = {
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {
                            "functionCall": {"id": "fc_1", "name": "get_assets", "args": {}},
                            "thoughtSignature": "first_call_signature_only",
                        },
                        {
                            "functionCall": {"id": "fc_2", "name": "get_connections", "args": {}},
                        },
                    ]
                }
            }]
        }
        normalized = _normalize_gemini_response(resp)
        tool_calls = normalized["tool_calls"]
        self.assertEqual(len(tool_calls), 2)
        self.assertEqual(tool_calls[0]["thought_signature"], "first_call_signature_only")
        self.assertNotIn("thought_signature", tool_calls[1])

        # Replay outbound: must stay in ONE model Content block
        messages = [
            {"role": "user", "content": "fetch all data"},
            normalized,
            {"role": "tool", "tool_call_id": "fc_1", "name": "get_assets", "content": '{"assets": []}'},
            {"role": "tool", "tool_call_id": "fc_2", "name": "get_connections", "content": '{"connections": []}'},
        ]
        _, contents = _translate_messages_to_gemini(messages)

        # 1. Verify single model Content block
        model_blocks = [c for c in contents if c.get("role") == "model"]
        self.assertEqual(len(model_blocks), 1)
        self.assertEqual(len(model_blocks[0]["parts"]), 2)

        # 2. First call has signature, second call does NOT have fabricated signature
        part_0 = model_blocks[0]["parts"][0]
        part_1 = model_blocks[0]["parts"][1]
        self.assertEqual(part_0.get("thoughtSignature"), "first_call_signature_only")
        self.assertNotIn("thoughtSignature", part_1)
        self.assertEqual(part_0["functionCall"]["id"], "fc_1")
        self.assertEqual(part_1["functionCall"]["id"], "fc_2")

        # 3. Both function responses are grouped in a single user Content block
        user_fr_blocks = [c for c in contents if c.get("role") == "user" and any("functionResponse" in p for p in c.get("parts", []))]
        self.assertEqual(len(user_fr_blocks), 1)
        self.assertEqual(len(user_fr_blocks[0]["parts"]), 2)
        self.assertEqual(user_fr_blocks[0]["parts"][0]["functionResponse"]["id"], "fc_1")
        self.assertEqual(user_fr_blocks[0]["parts"][1]["functionResponse"]["id"], "fc_2")


class TestGeminiRetryAndErrorHandling(unittest.TestCase):
    """Tests for bounded exponential backoff, RetryInfo, and RPC status taxonomy."""

    def setUp(self):
        self.provider = GeminiProvider(model="gemini-3.8-flash", api_key="test-api-key")

    def test_extract_retry_delay_formats(self):
        """Extracts protobuf string ("39s", "1.5s") and struct (seconds/nanos) formats."""
        # Case A: string duration "39s"
        resp_a = _make_response(429, {
            "error": {
                "details": [
                    {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "39s"}
                ]
            }
        })
        self.assertEqual(_extract_retry_delay(resp_a), 39.0)

        # Case B: string duration "1.5s"
        resp_b = _make_response(429, {
            "error": {
                "details": [
                    {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "1.5s"}
                ]
            }
        })
        self.assertEqual(_extract_retry_delay(resp_b), 1.5)

        # Case C: struct representation
        resp_c = _make_response(429, {
            "error": {
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.RetryInfo",
                        "retryDelay": {"seconds": 2, "nanos": 500000000},
                    }
                ]
            }
        })
        self.assertEqual(_extract_retry_delay(resp_c), 2.5)

        # Case D: absent RetryInfo
        resp_d = _make_response(503, {"error": {"message": "Service Unavailable"}})
        self.assertIsNone(_extract_retry_delay(resp_d))

    @patch("time.sleep")
    @patch("requests.post")
    def test_bounded_retry_on_429_with_retry_info(self, mock_post, mock_sleep):
        """429 retries using server retryDelay, succeeds on attempt 2."""
        err_body = {
            "error": {
                "status": "RESOURCE_EXHAUSTED",
                "details": [
                    {"@type": "google.rpc.RetryInfo", "retryDelay": "2.5s"}
                ]
            }
        }
        ok_body = {
            "candidates": [{"content": {"role": "model", "parts": [{"text": "Recovered!"}]}}]
        }
        mock_post.side_effect = [
            _make_response(429, err_body),
            _make_response(200, ok_body),
        ]

        result = self.provider.chat([{"role": "user", "content": "hi"}])
        self.assertEqual(result, "Recovered!")
        self.assertEqual(mock_post.call_count, 2)
        mock_sleep.assert_called_once_with(2.5)

    @patch("time.sleep")
    @patch("requests.post")
    def test_retryable_status_codes_max_4_attempts(self, mock_post, mock_sleep):
        """Status 503 retries up to 4 total attempts before raising."""
        mock_post.return_value = _make_response(503, {"error": {"status": "UNAVAILABLE"}})

        with self.assertRaises(LLMResponseError) as ctx:
            self.provider.chat([{"role": "user", "content": "hi"}])

        self.assertEqual(mock_post.call_count, 4)
        self.assertEqual(mock_sleep.call_count, 3)
        self.assertIn("UNAVAILABLE", str(ctx.exception))

    @patch("requests.post")
    def test_non_retryable_client_errors_fail_immediately(self, mock_post):
        """400, 401, 403, 404 do NOT retry (fail on attempt 1)."""
        for code in (400, 401, 403, 404):
            mock_post.reset_mock()
            mock_post.return_value = _make_response(code, {"error": {"message": "Client Error"}})

            with self.assertRaises(LLMResponseError):
                self.provider.chat([{"role": "user", "content": "hi"}])

            self.assertEqual(mock_post.call_count, 1, f"HTTP {code} should fail immediately on attempt 1")

    def test_sanitized_error_does_not_leak_keys_or_prompts(self):
        """Error messages are sanitized and do not contain secret keys."""
        resp = _make_response(400, {
            "error": {
                "status": "INVALID_ARGUMENT",
                "message": "Invalid request at https://generativelanguage.googleapis.com?key=SECRET_XYZ_9999",
            }
        })
        msg = _format_gemini_error(resp, "gemini-3.8-flash")
        self.assertNotIn("SECRET_XYZ_9999", msg)
        self.assertIn("[REDACTED]", msg)


class TestLazyDependencyBoundary(unittest.TestCase):
    """Tests for the lazy optional dependency boundary."""

    def test_core_provider_importable_without_requests(self):
        """A2: ChatResult and ToolCall can be imported in a core-only environment."""
        with patch.dict(sys.modules, {"requests": None}):
            from scrutics.ai.provider import ChatResult, ToolCall, LLMProvider
            c = ChatResult("sample text", thought_signature="sig_abc")
            self.assertEqual(c, "sample text")
            self.assertEqual(c.thought_signature, "sig_abc")
            t = ToolCall(id="call_1", name="tool_fn", arguments="{}")
            self.assertEqual(t.to_dict()["id"], "call_1")

    def test_ai_package_importable_without_requests(self):
        """A2: Importing scrutics.ai does not eagerly require requests."""
        with patch.dict(sys.modules, {"requests": None}):
            import scrutics.ai
            self.assertTrue(hasattr(scrutics.ai, "ChatResult"))
            self.assertTrue(hasattr(scrutics.ai, "ToolCall"))


class TestRetryProgressIndication(unittest.TestCase):
    """Tests for v0.6.1a Part 1: Retry Progress Indication in CLI and TUI."""

    def setUp(self):
        self.provider = GeminiProvider(api_key="test-secret-key")

    @patch("time.sleep")
    @patch("requests.post")
    def test_retry_callback_invoked_before_sleep_with_resolved_delay(self, mock_post, mock_sleep):
        """Callback is invoked before sleep with actual server delay and then in-flight indicator."""
        calls = []

        def record_cb(attempt, total, delay):
            # Record order relative to sleep
            calls.append((attempt, total, delay, mock_sleep.call_count))

        self.provider.set_retry_callback(record_cb)

        err_body = {
            "error": {
                "code": 429,
                "message": "Resource exhausted",
                "status": "RESOURCE_EXHAUSTED",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.RetryInfo",
                        "retryDelay": "2s",
                    }
                ],
            }
        }
        ok_body = {
            "candidates": [{"content": {"role": "model", "parts": [{"text": "Success!"}]}}]
        }
        mock_post.side_effect = [
            _make_response(429, err_body),
            _make_response(200, ok_body),
        ]

        res = self.provider.chat([{"role": "user", "content": "ping"}])
        self.assertEqual(res, "Success!")
        self.assertEqual(len(calls), 2)
        # First call: before sleep, delay=2.0s, mock_sleep had not been called yet (count 0)
        self.assertEqual(calls[0], (2, 4, 2.0, 0))
        # Sleep happened with 2.0s
        mock_sleep.assert_called_once_with(2.0)
        # Second call: attempt 2 in flight (delay=0.0) after sleep (count 1)
        self.assertEqual(calls[1], (2, 4, 0.0, 1))

    def test_cli_spinner_updates_labels_and_preserves_non_tty(self):
        """CLI Spinner updates message accurately and remains silent on non-TTY."""
        from scrutics.cli import Spinner

        spinner = Spinner("Thinking...")
        self.assertEqual(spinner.message, "Thinking...")

        # Wire retry handler as done in cli.py
        def retry_cb(attempt: int, total: int, delay: float):
            if delay > 0:
                spinner.set_message(f"Waiting {int(round(delay))}s before retry (attempt {attempt} of {total})...")
            else:
                spinner.set_message(f"Retrying (attempt {attempt} of {total})...")

        # Backoff wait
        retry_cb(2, 4, 5.2)
        self.assertEqual(spinner.message, "Waiting 5s before retry (attempt 2 of 4)...")

        # In-flight attempt
        retry_cb(2, 4, 0.0)
        self.assertEqual(spinner.message, "Retrying (attempt 2 of 4)...")

        # Non-TTY check
        with patch("sys.stdout.isatty", return_value=False):
            with patch("sys.stdout.write") as mock_write:
                spinner.clear()
                mock_write.assert_not_called()


if __name__ == "__main__":
    unittest.main()

