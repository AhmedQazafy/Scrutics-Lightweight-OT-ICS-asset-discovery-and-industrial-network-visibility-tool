"""Tests for `scrutics ai` UX and reliability.

Covers KeyboardInterrupt handling, timeout defaults, fast-fail on
connection refusal, workflow-guidance messages in error output,
banner rendering behavior, and spinner cleanup.
"""

import io
import os
import sys
import time
import pytest
from unittest.mock import patch, MagicMock

from scrutics.cli import build_parser, run_ask, run_ai, Spinner, SCRUTICS_BANNER_LINES
from scrutics.ai.provider import LLMConnectionError
from scrutics.ai.ollama_provider import OllamaProvider
from scrutics.ai.config import build_provider
from scrutics.ai.agent import run_agent_loop
from scrutics.topology import write_manifest
from tests.test_ai_agent import FakeLLMProvider


def _create_fake_session(session_dir):
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / "assets.csv").write_text(
        "ip,mac,vendor,protocol,role,confidence_pct,type\n"
        "192.168.1.10,00:80:f4:11:22:33,Schneider Electric,Modbus TCP,PLC,85,OT\n",
        encoding="utf-8",
    )
    (session_dir / "evidence.json").write_text("{}", encoding="utf-8")
    (session_dir / "connections.csv").write_text("source,destination,protocol,count\n", encoding="utf-8")
    (session_dir / "anomalies.csv").write_text("timestamp,ip,severity,type,detail\n", encoding="utf-8")
    write_manifest(str(session_dir))
    return session_dir


# ── 1. KeyboardInterrupt Handled Cleanly ──────────────────────────────────────

def test_ask_keyboard_interrupt_handled_cleanly(tmp_path, capsys):
    session_dir = _create_fake_session(tmp_path / "scrutics_20260905_120000")
    parser = build_parser()
    args = parser.parse_args(["ask", "What devices exist?", "--session", str(session_dir)])

    with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
         patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
         patch("scrutics.ai.agent.run_agent_loop", side_effect=KeyboardInterrupt):
        rc = run_ask(args)

    assert rc == 130
    captured = capsys.readouterr()
    assert "Cancelled." in captured.err
    assert "Traceback" not in captured.err


# ── 2. Default Timeout is 180s ────────────────────────────────────────────────

def test_default_timeout_is_180():
    provider = OllamaProvider()
    assert provider.timeout == 180.0

    built = build_provider({"provider": "ollama"})
    assert built.timeout == 180.0


# ── 3. Connection Refused Fails Fast ──────────────────────────────────────────

def test_connection_refused_fails_fast():
    import urllib.request
    import urllib.error

    provider = OllamaProvider(base_url="http://127.0.0.1:59999")
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        with pytest.raises(LLMConnectionError) as exc_info:
            provider.chat(messages=[{"role": "user", "content": "hello"}])
        assert "Cannot connect to Ollama" in str(exc_info.value)


# ── 4. No Session Error Includes Workflow Guidance ────────────────────────────

def test_no_session_error_includes_workflow_guidance(tmp_path, capsys):
    empty_output = tmp_path / "output"
    empty_output.mkdir()

    parser = build_parser()
    args = parser.parse_args(["ask", "What devices exist?", "--output", str(empty_output)])

    rc = run_ask(args)
    assert rc != 0
    captured = capsys.readouterr()
    # Error message references 'scrutics ai'
    assert "'scrutics ai' answers questions about a completed capture session." in captured.err
    assert "sudo scrutics --live <interface> --duration 60 --headless" in captured.err
    assert "scrutics ai" in captured.err


# ── 5. Invalid Session Error Includes Workflow Guidance ───────────────────────

def test_invalid_session_error_includes_workflow_guidance(tmp_path, capsys):
    non_existent = tmp_path / "non_existent_session"

    parser = build_parser()
    args = parser.parse_args(["ask", "What devices exist?", "--session", str(non_existent)])

    rc = run_ask(args)
    assert rc != 0
    captured = capsys.readouterr()
    assert "'scrutics ai' answers questions about a completed capture session." in captured.err
    assert "sudo scrutics --live <interface> --duration 60 --headless" in captured.err


# ── 6. Banner Not Printed On Error / Before Valid Query ───────────────────────

def test_banner_not_printed_on_no_session(tmp_path, capsys):
    """Banner must NOT appear when there is no session to analyze."""
    empty_output = tmp_path / "output"
    empty_output.mkdir()

    parser = build_parser()
    args = parser.parse_args(["ai", "What devices exist?", "--output", str(empty_output)])

    rc = run_ai(args)
    assert rc != 0
    captured = capsys.readouterr()
    # Banner should NOT have printed before the error
    assert "OT/ICS Passive AI Assistant" not in captured.out


# ── 7. Banner Printed on Valid Run ────────────────────────────────────────────

def test_banner_printed_on_valid_run(tmp_path, capsys):
    session_dir = _create_fake_session(tmp_path / "scrutics_20260905_120000")
    parser = build_parser()
    # When run non-interactively (isatty=False), REPL exits after the first answer
    args = parser.parse_args(["ask", "What devices exist?", "--session", str(session_dir)])

    with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
         patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
         patch("scrutics.ai.agent.run_agent_loop", return_value="All clear."):
        # isatty=False → one-shot mode, no stdin read
        with patch("sys.stdout.isatty", return_value=False), patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NO_COLOR", None)
            rc = run_ask(args)

    assert rc == 0
    captured = capsys.readouterr()
    assert "OT/ICS Passive AI Assistant" in captured.out
    # No ANSI color when isatty is False
    assert "\033[38;2;" not in captured.out

    # Now test with isatty=True but stdin EOF so the REPL exits cleanly
    with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
         patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
         patch("scrutics.ai.agent.run_agent_loop", return_value="All clear."):
        with patch("sys.stdout.isatty", return_value=True), \
             patch("sys.stdin.readline", return_value=""), \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NO_COLOR", None)
            rc = run_ask(args)

    assert rc == 0
    captured_tty = capsys.readouterr()
    assert "OT/ICS Passive AI Assistant" in captured_tty.out
    # Truecolor ANSI escape should be present when isatty is True
    assert "\033[38;2;224;123;57m" in captured_tty.out
    assert "\033[38;2;74;144;217m" in captured_tty.out

    # Test with NO_COLOR set
    with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
         patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
         patch("scrutics.ai.agent.run_agent_loop", return_value="All clear."):
        with patch("sys.stdout.isatty", return_value=True), \
             patch("sys.stdin.readline", return_value=""), \
             patch.dict(os.environ, {"NO_COLOR": "1"}):
            rc = run_ask(args)

    assert rc == 0
    captured_no_color = capsys.readouterr()
    assert "OT/ICS Passive AI Assistant" in captured_no_color.out
    assert "\033[38;2;" not in captured_no_color.out


# ── 8. Spinner Clears Terminal Line ───────────────────────────────────────────

def test_spinner_clears_terminal_line():
    mock_stdout = MagicMock()
    with patch("sys.stdout.isatty", return_value=True), patch("sys.stdout.write", mock_stdout.write), patch("sys.stdout.flush", mock_stdout.flush):
        spinner = Spinner("Thinking...")
        spinner.start()
        time.sleep(0.1)
        spinner.set_message("Running get_assets...")
        time.sleep(0.1)
        spinner.stop()

    # Verify that \r\033[2K was written to clear lines
    written = "".join(call.args[0] for call in mock_stdout.write.call_args_list)
    assert "\r\033[2K" in written


# ── 9. Backward Compatibility: run_agent_loop without status_callback ─────────

def test_run_agent_loop_without_status_callback_regression(tmp_path):
    from scrutics.ai.tools import SessionContext
    session_dir = _create_fake_session(tmp_path / "scrutics_20260905_120000")
    ctx = SessionContext(str(session_dir))
    provider = FakeLLMProvider(["Response without callback."])

    # Must run completely without raising AttributeError or error when status_callback is None
    answer = run_agent_loop(provider=provider, ctx=ctx, user_message="Test query")
    assert answer == "Response without callback."


# ── 10. Interactive REPL: follow-up questions ─────────────────────────────────

def test_ai_repl_multi_turn(tmp_path, capsys):
    """REPL must preserve conversation history across multiple questions."""
    session_dir = _create_fake_session(tmp_path / "scrutics_20260905_120000")
    parser = build_parser()
    args = parser.parse_args(["ai", "--session", str(session_dir)])

    call_log = []

    def fake_loop(provider, ctx, user_message, **kw):
        call_log.append(user_message)
        if "Previous conversation" in user_message:
            return "Follow-up answer."
        return "First answer."

    # Simulate two questions then EOF
    stdin_lines = iter(["What is on the network?\n", "Tell me more.\n", ""])
    with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
         patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
         patch("scrutics.ai.agent.run_agent_loop", side_effect=fake_loop), \
         patch("sys.stdout.isatty", return_value=True), \
         patch("sys.stdin.readline", side_effect=lambda: next(stdin_lines)):
        rc = run_ai(args)

    assert rc == 0
    captured = capsys.readouterr()
    assert "First answer." in captured.out
    assert "Follow-up answer." in captured.out
    # Second call should have injected prior conversation history
    assert len(call_log) == 2
    assert "[Previous conversation]" in call_log[1]
    assert "First answer." in call_log[1]


# ── 11. Session Context Shown After Banner ────────────────────────────────────

def test_session_context_displayed(tmp_path, capsys):
    """Session timestamp and asset counts appear right after the banner."""
    session_dir = _create_fake_session(tmp_path / "scrutics_20260905_120000")
    parser = build_parser()
    args = parser.parse_args(["ai", "What devices exist?", "--session", str(session_dir)])

    with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
         patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
         patch("scrutics.ai.agent.run_agent_loop", return_value="One device."), \
         patch("sys.stdout.isatty", return_value=False):
        rc = run_ai(args)

    assert rc == 0
    captured = capsys.readouterr()
    # Session name parts should appear in the context line
    assert "2026-09-05" in captured.out
    assert "12:00:00" in captured.out
