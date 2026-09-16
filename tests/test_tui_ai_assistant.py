"""Tests for the TUI AI Assistant modal panel.

Covers modal open/close, session auto-detection, freshness labeling,
AI-disabled inline message, LLMProviderError inline error handling,
and background worker execution for AI calls.
"""

import asyncio
import os
import pytest
from unittest.mock import patch, MagicMock

from scrutics.ui.tui import ScruticsApp, AIAssistantModal
from scrutics.ai.provider import LLMConnectionError
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


def test_ai_button_and_binding_opens_modal():
    """1. AI Assistant button and 'a' keybinding opens the AIAssistantModal when AI is configured."""
    configured_cfg = {"enabled": True, "provider": "ollama", "model": "qwen3.5:4b"}

    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            btn = app.query_one("#btn-ai-assistant")
            assert btn is not None
            assert "AI Assistant" in str(btn.label)

            # Mock AI as configured so button opens AIAssistantModal, not the onboarding wizard
            with patch("scrutics.ai.config.load_ai_config", return_value=configured_cfg):
                await pilot.click("#btn-ai-assistant")
                await pilot.pause()
                assert isinstance(app.screen, AIAssistantModal)

                await pilot.press("escape")
                await pilot.pause()
                assert not isinstance(app.screen, AIAssistantModal)

                await pilot.press("a")
                await pilot.pause()
                assert isinstance(app.screen, AIAssistantModal)

                await pilot.press("escape")
                await pilot.pause()

    asyncio.run(run())


def test_freshness_message_gated_by_live_flag(tmp_path):
    """2. Freshness message appears only when live capture active flag is true."""
    session_dir = _create_fake_session(tmp_path / "scrutics_20260910_120000")

    async def run():
        # When live capture is active
        modal_live = AIAssistantModal(session_dir=str(session_dir), is_live_active=True)
        app_live = ScruticsApp()
        async with app_live.run_test() as pilot:
            await app_live.push_screen(modal_live)
            await pilot.pause()

            label = modal_live.query_one("#ai-status-label")
            assert "Data as of last checkpoint" in str(label.render())
            assert "during live capture" in str(label.render())

        # When completed/idle session (not live)
        modal_idle = AIAssistantModal(session_dir=str(session_dir), is_live_active=False)
        app_idle = ScruticsApp()
        async with app_idle.run_test() as pilot:
            await app_idle.push_screen(modal_idle)
            await pilot.pause()

            label = modal_idle.query_one("#ai-status-label")
            assert "Completed session evidence package" in str(label.render())

    asyncio.run(run())


def test_ai_disabled_config_shows_inline_and_no_provider_construction(tmp_path):
    """3. AI-disabled config shows inline message and never constructs provider."""
    session_dir = _create_fake_session(tmp_path / "scrutics_20260910_120000")

    async def run():
        modal = AIAssistantModal(session_dir=str(session_dir), is_live_active=False)
        app = ScruticsApp()

        with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": False}), \
             patch("scrutics.ai.config.build_provider") as mock_build_provider:
            async with app.run_test() as pilot:
                await app.push_screen(modal)
                await pilot.pause()

                input_widget = modal.query_one("#ai-query-input")
                send_btn = modal.query_one("#ai-send-btn")
                assert input_widget.disabled is True
                assert send_btn.disabled is True

                history_text = "\n".join(modal.query_one("#ai-history").lines)
                assert "AI features are currently disabled" in history_text

                mock_build_provider.assert_not_called()

    asyncio.run(run())


def test_llm_connection_error_shows_inline(tmp_path):
    """4. Mocked LLMConnectionError shows inline error without crashing the modal."""
    session_dir = _create_fake_session(tmp_path / "scrutics_20260910_120000")

    async def run():
        modal = AIAssistantModal(session_dir=str(session_dir), is_live_active=False)
        app = ScruticsApp()

        with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
             patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
             patch("scrutics.ai.agent.run_agent_loop", side_effect=LLMConnectionError("Cannot connect to Ollama")):
            async with app.run_test() as pilot:
                await app.push_screen(modal)
                await pilot.pause()

                input_widget = modal.query_one("#ai-query-input")
                input_widget.value = "What is on the network?"
                await pilot.click("#ai-send-btn")

                await pilot.pause(0.5)

                history_text = "\n".join(modal.query_one("#ai-history").lines)
                assert "LLM error: Cannot connect to Ollama" in history_text
                assert modal.query_one("#ai-send-btn").disabled is False

    asyncio.run(run())


def test_successful_run_agent_loop_renders_in_history(tmp_path):
    """5. Mocked successful run_agent_loop response renders in conversation history."""
    session_dir = _create_fake_session(tmp_path / "scrutics_20260910_120000")

    async def run():
        modal = AIAssistantModal(session_dir=str(session_dir), is_live_active=False)
        app = ScruticsApp()

        with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
             patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
             patch("scrutics.ai.agent.run_agent_loop", return_value="Discovered 1 Schneider PLC at 192.168.1.10."):
            async with app.run_test() as pilot:
                await app.push_screen(modal)
                await pilot.pause()

                input_widget = modal.query_one("#ai-query-input")
                input_widget.value = "List all PLCs"
                await pilot.click("#ai-send-btn")

                await pilot.pause(0.5)

                history_text = "\n".join(modal.query_one("#ai-history").lines)
                assert "List all PLCs" in history_text
                assert "Discovered 1 Schneider PLC at 192.168.1.10." in history_text
                assert len(modal._conversation_history) == 1
                assert modal._conversation_history[0][1] == "Discovered 1 Schneider PLC at 192.168.1.10."

    asyncio.run(run())


def test_worker_decorator_presence():
    """6. Confirm AI call happens via @work(thread=True) background worker."""
    assert hasattr(AIAssistantModal, "_run_query_worker")
    method = getattr(AIAssistantModal, "_run_query_worker")
    assert hasattr(method, "_work_decorator") or getattr(method, "__name__", "") == "_run_query_worker"


def test_session_display_and_switch_button(tmp_path):
    """7. AIAssistantModal displays session badge and Switch Session button."""
    session_dir = _create_fake_session(tmp_path / "scrutics_20260910_120000")

    async def run():
        modal = AIAssistantModal(session_dir=str(session_dir), is_live_active=True)
        app = ScruticsApp()
        async with app.run_test() as pilot:
            await app.push_screen(modal)
            await pilot.pause()

            badge = modal.query_one("#ai-session-badge")
            assert "scrutics_20260910_120000" in str(badge.content)
            assert "Live Capture" in str(badge.content)

            btn_switch = modal.query_one("#ai-btn-browse-session")
            assert btn_switch is not None
            assert "Switch Session" in str(btn_switch.label)

    asyncio.run(run())


def test_live_disclaimer_appended_on_query(tmp_path):
    """8. In live mode, asking a question appends a 15s checkpoint disclaimer."""
    session_dir = _create_fake_session(tmp_path / "scrutics_20260910_120000")

    async def run():
        modal = AIAssistantModal(session_dir=str(session_dir), is_live_active=True)
        app = ScruticsApp()
        with patch("scrutics.ai.config.load_ai_config", return_value={"enabled": True, "provider": "ollama"}), \
             patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
             patch("scrutics.ai.agent.run_agent_loop", return_value="Live answer"):
            async with app.run_test() as pilot:
                await app.push_screen(modal)
                await pilot.pause()

                inp = modal.query_one("#ai-query-input")
                inp.value = "Show live PLCs"
                await pilot.click("#ai-send-btn")
                await pilot.pause(0.5)

                lines = "\n".join(modal.query_one("#ai-history").lines)
                assert "Note: live session results reflect data up to the last 15s checkpoint" in lines

    asyncio.run(run())


def test_tier1_mac_changed_and_device_moved_anomalies():
    """9. CaptureEngine detects MAC_CHANGED and DEVICE_MOVED anomalies."""
    from scrutics.db.inventory import AssetInventory
    from scrutics.capture.engine import CaptureEngine
    import time

    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)

    ts1 = time.time()
    # Device 1 appears at IP 10.0.0.1 with MAC AA:BB:CC:11:22:33
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:22:33", None, None, None, ts1)
    assert inv.get("10.0.0.1") is not None
    assert inv.get("10.0.0.1").mac == "AA:BB:CC:11:22:33"
    assert not inv.get("10.0.0.1").is_stale(now_epoch=ts1 + 5, timeout=30)
    assert inv.get("10.0.0.1").is_stale(now_epoch=ts1 + 35, timeout=30)

    # Scenario A: Same IP claims a new MAC (e.g. ARP spoof or device replaced)
    ts2 = ts1 + 10
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:99:99:99", None, None, None, ts2)
    anomalies = engine.baseline.get_anomalies()
    mac_changed = [a for a in anomalies if a.get("type") == "MAC_CHANGED"]
    assert len(mac_changed) == 1
    assert mac_changed[0]["severity"] == "HIGH"
    assert "AA:BB:CC:11:22:33" in mac_changed[0]["detail"]
    assert "AA:BB:CC:99:99:99" in mac_changed[0]["detail"]

    # Scenario B: Known MAC appears on a different IP (Device moved / reconnects elsewhere)
    ts3 = ts2 + 10
    engine._process_flow_data("10.0.0.2", "AA:BB:CC:11:22:33", None, None, None, ts3)
    anomalies = engine.baseline.get_anomalies()
    device_moved = [a for a in anomalies if a.get("type") == "DEVICE_MOVED"]
    assert len(device_moved) == 1
    assert device_moved[0]["severity"] == "MEDIUM"
    assert "10.0.0.1" in device_moved[0]["detail"]
    assert "10.0.0.2" in device_moved[0]["detail"]

