"""Tests for the `scrutics ai` CLI command.

Covers session-directory resolution (auto-detect vs explicit path),
AI-disabled early exit, error handling for LLMProviderError subclasses,
provider/model CLI overrides, and non-zero exit on failure.
"""

import os
import time
import pytest
from unittest.mock import patch

from scrutics.cli import build_parser, run_ask, resolve_session_dir
from scrutics.ai.provider import LLMConnectionError, LLMProviderError
from scrutics.topology import write_manifest
from tests.test_ai_agent import FakeLLMProvider


def _create_fake_session(session_dir):
    """Helper to populate a valid Scrutics session directory with manifest and evidence files."""
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


# ── 1. Resolve Most Recent Session ─────────────────────────────────────────────

def test_ask_resolves_most_recent_session(tmp_path, monkeypatch, capsys):
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    session_old = output_dir / "scrutics_20260905_100000"
    _create_fake_session(session_old)

    session_new = output_dir / "scrutics_20260905_120000"
    _create_fake_session(session_new)

    # Ensure mtime reflects older and newer explicitly
    now = time.time()
    os.utime(str(session_old), (now - 3600, now - 3600))
    os.utime(str(session_new), (now, now))

    parser = build_parser()
    args = parser.parse_args(["ask", "What devices exist?", "--output", str(output_dir)])

    # Mock provider and agent loop
    fake_provider = FakeLLMProvider(["There is 1 OT device."])
    with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
         patch("scrutics.ai.config.build_provider", return_value=fake_provider), \
         patch("scrutics.ai.agent.run_agent_loop", wraps=None) as mock_agent:
        mock_agent.return_value = "There is 1 OT device."
        rc = run_ask(args)

    assert rc == 0
    # Verify the newest session was passed to SessionContext in run_agent_loop
    called_ctx = mock_agent.call_args[1]["ctx"]
    assert os.path.abspath(called_ctx.session_dir) == os.path.abspath(str(session_new))
    captured = capsys.readouterr()
    assert "There is 1 OT device." in captured.out


# ── 2. Explicit Session Path ───────────────────────────────────────────────────

def test_ask_uses_explicit_session_path(tmp_path, capsys):
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    session_a = output_dir / "scrutics_20260905_100000"
    _create_fake_session(session_a)

    session_b = output_dir / "scrutics_20260905_120000"
    _create_fake_session(session_b)

    parser = build_parser()
    args = parser.parse_args([
        "ask", "Tell me about session A",
        "--session", str(session_a),
        "--output", str(output_dir),
    ])

    fake_provider = FakeLLMProvider(["Session A parsed."])
    with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
         patch("scrutics.ai.config.build_provider", return_value=fake_provider), \
         patch("scrutics.ai.agent.run_agent_loop") as mock_agent:
        mock_agent.return_value = "Session A parsed."
        rc = run_ask(args)

    assert rc == 0
    called_ctx = mock_agent.call_args[1]["ctx"]
    assert os.path.abspath(called_ctx.session_dir) == os.path.abspath(str(session_a))


# ── 3. Invalid Session Path Exits Non-Zero ─────────────────────────────────────

def test_ask_invalid_session_path_exits_nonzero(tmp_path, capsys):
    non_existent = tmp_path / "non_existent_session"

    parser = build_parser()
    args = parser.parse_args(["ask", "What devices exist?", "--session", str(non_existent)])

    rc = run_ask(args)
    assert rc != 0
    captured = capsys.readouterr()
    assert "Error:" in captured.err
    assert "does not exist" in captured.err

    # Test directory without manifest
    empty_dir = tmp_path / "empty_session"
    empty_dir.mkdir()
    args_empty = parser.parse_args(["ask", "What devices exist?", "--session", str(empty_dir)])
    rc_empty = run_ask(args_empty)
    assert rc_empty != 0
    captured_empty = capsys.readouterr()
    assert "Error: Invalid session directory" in captured_empty.err


# ── 4. AI Disabled Exits Non-Zero ──────────────────────────────────────────────

def test_ask_ai_disabled_exits_nonzero(tmp_path, capsys):
    session_dir = _create_fake_session(tmp_path / "scrutics_20260905_120000")

    parser = build_parser()
    args = parser.parse_args(["ask", "What devices exist?", "--session", str(session_dir)])

    # Config returns empty dict (AI disabled) and user skips onboarding → exit non-zero
    with patch("scrutics.ai.config.load_ai_config", return_value={}):
        with patch("scrutics.cli._run_ai_onboarding_cli", return_value=None) as mock_onboard:
            rc = run_ask(args)
            assert mock_onboard.called

    assert rc != 0


# ── 5. Successful Run ──────────────────────────────────────────────────────────

def test_ask_successful_run(tmp_path, capsys):
    session_dir = _create_fake_session(tmp_path / "scrutics_20260905_120000")

    parser = build_parser()
    args = parser.parse_args(["ask", "What", "is", "192.168.1.10?", "--session", str(session_dir)])

    with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
         patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
         patch("scrutics.ai.agent.run_agent_loop", return_value="192.168.1.10 is a Schneider Electric PLC.") as mock_agent:
        rc = run_ask(args)

    assert rc == 0
    # Confirm question words were joined
    assert mock_agent.call_args[1]["user_message"] == "What is 192.168.1.10?"
    captured = capsys.readouterr()
    assert "192.168.1.10 is a Schneider Electric PLC." in captured.out


# ── 6. LLMConnectionError Handled Cleanly ─────────────────────────────────────

def test_ask_llm_connection_error_handled_cleanly(tmp_path, capsys):
    session_dir = _create_fake_session(tmp_path / "scrutics_20260905_120000")

    parser = build_parser()
    args = parser.parse_args(["ask", "What is running?", "--session", str(session_dir)])

    with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
         patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
         patch("scrutics.ai.agent.run_agent_loop", side_effect=LLMConnectionError("Connection refused to http://localhost:11434")):
        rc = run_ask(args)

    assert rc != 0
    captured = capsys.readouterr()
    assert "Could not reach LLM provider" in captured.err
    assert "ollama serve" in captured.err
    # Ensure no raw traceback leaked
    assert "Traceback" not in captured.err


# ── 7. Provider and Model CLI Overrides ─────────────────────────────────────────

def test_ask_provider_model_cli_overrides(tmp_path, capsys):
    session_dir = _create_fake_session(tmp_path / "scrutics_20260905_120000")

    parser = build_parser()
    args = parser.parse_args([
        "ask", "Question",
        "--session", str(session_dir),
        "--provider", "ollama",
        "--model", "custom-model:latest",
    ])

    captured_config = {}

    def mock_build(cfg):
        captured_config.update(cfg)
        return FakeLLMProvider([])

    # Even with config disabled, explicit --provider overrides it
    with patch("scrutics.ai.config.load_ai_config", return_value={}), \
         patch("scrutics.ai.config.build_provider", side_effect=mock_build), \
         patch("scrutics.ai.agent.run_agent_loop", return_value="Result"):
        rc = run_ask(args)

    assert rc == 0
    assert captured_config.get("provider") == "ollama"
    assert captured_config.get("model") == "custom-model:latest"


# ── 8. Unrecognized Provider Exits Non-Zero ────────────────────────────────────

def test_ask_unrecognized_provider_exits_nonzero(tmp_path, capsys):
    session_dir = _create_fake_session(tmp_path / "scrutics_20260905_120000")

    parser = build_parser()
    args = parser.parse_args([
        "ask", "Question",
        "--session", str(session_dir),
        "--provider", "unsupported_cloud_provider",
    ])

    rc = run_ask(args)
    assert rc != 0
    captured = capsys.readouterr()
    assert "Error: Unsupported LLM provider: 'unsupported_cloud_provider'" in captured.err
    assert "Traceback" not in captured.err
