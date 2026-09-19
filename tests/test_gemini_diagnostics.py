"""
Tests for Scrutics v0.6.1 AI Progressive Diagnostics suite.
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import pytest

from scrutics.ai.diagnostics import _sanitize_string, run_ai_diagnostics
from scrutics.ai.provider import LLMProvider, ChatResult


class TestDiagnosticsSanitization:
    """Test sanitization of diagnostic output logs."""

    def test_sanitize_api_key(self):
        raw = "Error occurred with api_key AIzaSySecretKey123 while calling"
        sanitized = _sanitize_string(raw, "AIzaSySecretKey123")
        assert "AIzaSySecretKey123" not in sanitized
        assert "[REDACTED_API_KEY]" in sanitized

    def test_sanitize_url_key(self):
        raw = "GET https://generativelanguage.googleapis.com/v1beta/models?key=AIzaSyXYZ999&alt=json"
        sanitized = _sanitize_string(raw)
        assert "AIzaSyXYZ999" not in sanitized
        assert "key=[REDACTED]" in sanitized

    def test_sanitize_ip_and_mac(self):
        raw = "Asset at 192.168.1.100 with MAC 00:80:f4:12:34:56 had issue"
        sanitized = _sanitize_string(raw)
        assert "192.168.1.100" not in sanitized
        assert "[IP_REDACTED]" in sanitized
        assert "00:80:f4:12:34:56" not in sanitized
        assert "[MAC_REDACTED]" in sanitized


class TestDiagnosticsProgression:
    """Test execution and progression of diagnostic stages."""

    def test_stage_1_failure_empty_config(self):
        out = io.StringIO()
        res = run_ai_diagnostics(cfg_override={}, stream=out)
        assert res == 1
        output = out.getvalue()
        assert "[01/14] Configuration loading" in output
        assert "FAIL" in output

    def test_stage_2_failure_missing_key(self):
        out = io.StringIO()
        cfg = {"provider": "gemini", "model": "gemini-3.8-flash", "api_key": ""}
        res = run_ai_diagnostics(cfg_override=cfg, stream=out)
        assert res == 1
        output = out.getvalue()
        assert "[01/14] Configuration loading" in output
        assert "PASS" in output
        assert "[02/14] API key presence & resolution" in output
        assert "FAIL" in output
        assert "Missing API key" in output

    @patch("socket.gethostbyname")
    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    @patch("requests.get")
    def test_full_diagnostics_mocked_success(
        self,
        mock_requests_get,
        mock_ssl_ctx,
        mock_socket_conn,
        mock_dns,
    ):
        """Simulate all 14 stages passing end-to-end."""
        # 1. DNS
        mock_dns.return_value = "142.250.190.42"

        # 2. TLS handshake
        fake_sock = MagicMock()
        mock_socket_conn.return_value.__enter__.return_value = fake_sock
        fake_ssock = MagicMock()
        fake_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_ctx.return_value.wrap_socket.return_value.__enter__.return_value = fake_ssock

        # 3. Model availability check
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_requests_get.return_value = mock_resp

        # 4. Mock provider chat returns
        secret_key = "AIzaSyTestSecretDiagnosticKey"
        cfg = {
            "provider": "gemini",
            "model": "gemini-3.8-flash",
            "api_key": secret_key,
        }

        # Mock LLMProvider inside build_provider
        class MockGeminiDiagProvider(LLMProvider):
            def __init__(self, **kwargs):
                self.turn = 0

            def chat(self, messages, tools=None, response_schema=None, **kwargs):
                self.turn += 1
                # Turn 1: Plain text generation (Stage 7)
                if self.turn == 1:
                    return ChatResult("OK", thought_signature="sig_text_1")
                # Turn 2: Tool call probe (Stage 9)
                elif self.turn == 2:
                    return {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_mock_probe_1",
                                "type": "function",
                                "function": {
                                    "name": "get_network_summary",
                                    "arguments": "{}",
                                },
                                "thought_signature": "sig_fc_probe_1",
                            }
                        ]
                    }
                # Turn 3: Multi-step reply (Stage 12)
                elif self.turn == 3:
                    return "The network has 1 asset."
                # Subsequent: Agent loop (Stage 13)
                else:
                    return "There is 1 PLC asset present."

        with patch("scrutics.ai.diagnostics.build_provider", return_value=MockGeminiDiagProvider()):
            out = io.StringIO()
            res = run_ai_diagnostics(cfg_override=cfg, stream=out)
            output = out.getvalue()

            assert res == 0, f"Diagnostics failed with output:\n{output}"
            assert "[14/14] Parallel function call structure & replay" in output
            assert "All 14 Diagnostic Stages Passed Successfully (100% OK)" in output
            # Ensure API key is never leaked
            assert secret_key not in output
