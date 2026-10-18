"""The TUI assistant's transcript: text shown literally, wrapped to the panel, a taller answer area,
and the conversation kept across closing and reopening until the session changes."""

import asyncio
from unittest.mock import patch

from rich.errors import MarkupError
from rich.text import Text

from scrutics.ai.provider import ChatResult
from scrutics.ui.tui import AIAssistantModal, ScruticsApp
from tests.test_ai_agent import FakeLLMProvider
from tests.test_tui_ai_assistant import _create_fake_session

CONFIGURED = {"enabled": True, "provider": "ollama"}


def _shown(entry: str) -> str:
    """The text a transcript line displays: its markup rendered, or the raw line if that fails."""
    try:
        return Text.from_markup(entry).plain
    except MarkupError:
        return entry


def _shown_lines(modal) -> list[str]:
    return [_shown(entry) for entry in modal.query_one("#ai-history").lines]


async def _ask(pilot, modal, question):
    modal.query_one("#ai-query-input").value = question
    await pilot.click("#ai-send-btn")
    await pilot.pause(0.5)


async def _visible_answer_rows(size):
    app = ScruticsApp()
    async with app.run_test(size=size) as pilot:
        modal = AIAssistantModal(session_dir=None)
        await app.push_screen(modal)
        await pilot.pause()
        return modal.query_one("#ai-history").scrollable_content_region.height


# ── text shown literally ─────────────────────────────────────────────────────

def test_a_question_with_markup_like_text_is_shown_literally(tmp_path):
    session_dir = _create_fake_session(tmp_path / "scrutics_20261018_100000")
    question = "Why is [red] in the log and what closes [/bold] here?"

    async def run():
        app = ScruticsApp()
        with patch("scrutics.ai.config.load_ai_config", return_value=CONFIGURED), \
             patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
             patch("scrutics.ai.agent.run_agent_loop", return_value="ok"):
            async with app.run_test() as pilot:
                modal = AIAssistantModal(session_dir=str(session_dir))
                await app.push_screen(modal)
                await pilot.pause()
                await _ask(pilot, modal, question)
                return _shown_lines(modal)

    assert f"You: {question}" in asyncio.run(run())


def test_an_answer_with_markup_like_text_is_shown_literally(tmp_path):
    answer = "The [bold]PLC[/bold] at 10.0.0.5 logged [/red] and [link=x]."

    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            modal = AIAssistantModal(session_dir=str(tmp_path))
            await app.push_screen(modal)
            await pilot.pause()
            modal._on_query_complete(ChatResult(answer), None)
            await pilot.pause()
            return _shown_lines(modal)

    shown = asyncio.run(run())
    assert any(line.startswith(f"Assistant: {answer}") for line in shown)


# ── wrapping and the answer area ─────────────────────────────────────────────

def test_a_long_answer_wraps_to_the_panel_width(tmp_path):
    answer = " ".join(f"device-{n}" for n in range(80))

    async def run():
        app = ScruticsApp()
        async with app.run_test(size=(80, 24)) as pilot:
            modal = AIAssistantModal(session_dir=str(tmp_path))
            await app.push_screen(modal)
            await pilot.pause()
            modal._on_query_complete(ChatResult(answer), None)
            await pilot.pause()
            view = modal.query_one("#ai-history")
            return view.virtual_size.width, view.scrollable_content_region.width, view.max_scroll_x

    content_width, panel_width, max_scroll_x = asyncio.run(run())
    assert content_width <= panel_width
    assert max_scroll_x == 0


def test_the_answer_area_shows_at_least_13_lines_at_80x24_and_19_at_120x30():
    assert asyncio.run(_visible_answer_rows((80, 24))) >= 13
    assert asyncio.run(_visible_answer_rows((120, 30))) >= 19


# ── conversation across close and reopen, cleared on session switch ──────────

def test_the_conversation_is_kept_across_close_and_reopen(tmp_path):
    session_dir = _create_fake_session(tmp_path / "scrutics_20261018_100000")

    async def run():
        app = ScruticsApp()
        with patch("scrutics.ai.config.load_ai_config", return_value=CONFIGURED), \
             patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
             patch("scrutics.ai.agent.run_agent_loop", side_effect=["PLC list: 10.0.0.5", "second"]) as loop:
            async with app.run_test() as pilot:
                first = AIAssistantModal(session_dir=str(session_dir))
                await app.push_screen(first)
                await pilot.pause()
                await _ask(pilot, first, "List the PLCs")
                await pilot.press("escape")
                await pilot.pause()

                second = AIAssistantModal(session_dir=str(session_dir))
                await app.push_screen(second)
                await pilot.pause()
                shown = _shown_lines(second)
                await _ask(pilot, second, "And the first one?")
                return shown, loop.call_args.kwargs["user_message"], list(second._conversation_history)

    shown, sent, history = asyncio.run(run())
    assert "You: List the PLCs" in shown
    assert any(line.startswith("Assistant: PLC list: 10.0.0.5") for line in shown)
    assert "User: List the PLCs\nAssistant: PLC list: 10.0.0.5" in sent
    assert sent.endswith("[New question]\nAnd the first one?")
    assert [q for q, _ in history] == ["List the PLCs", "And the first one?"]


def test_reopening_on_another_session_starts_a_new_conversation(tmp_path):
    session_a = _create_fake_session(tmp_path / "scrutics_20261018_100000")
    session_b = _create_fake_session(tmp_path / "scrutics_20261018_110000")

    async def run():
        app = ScruticsApp()
        with patch("scrutics.ai.config.load_ai_config", return_value=CONFIGURED), \
             patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
             patch("scrutics.ai.agent.run_agent_loop", return_value="answer about A"):
            async with app.run_test() as pilot:
                first = AIAssistantModal(session_dir=str(session_a))
                await app.push_screen(first)
                await pilot.pause()
                await _ask(pilot, first, "About A")
                await pilot.press("escape")
                await pilot.pause()

                other = AIAssistantModal(session_dir=str(session_b))
                await app.push_screen(other)
                await pilot.pause()
                return _shown_lines(other), list(other._conversation_history)

    shown, history = asyncio.run(run())
    assert history == []
    assert not any("About A" in line for line in shown)


async def _switch_session(pilot, app, modal, path):
    """Switch Session, then 'Enter custom path...' with path, as a user would."""
    modal.action_browse_session()
    await pilot.pause()
    app.screen.dismiss("   Enter custom path...")
    await pilot.pause()
    app.screen.dismiss(str(path))
    await pilot.pause()


def test_switching_session_clears_the_conversation(tmp_path):
    session_a = _create_fake_session(tmp_path / "scrutics_20261018_100000")
    session_b = _create_fake_session(tmp_path / "scrutics_20261018_110000")

    async def run():
        app = ScruticsApp()
        with patch("scrutics.ai.config.load_ai_config", return_value=CONFIGURED), \
             patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
             patch("scrutics.ai.agent.run_agent_loop", side_effect=["answer about A", "answer about B"]) as loop:
            async with app.run_test() as pilot:
                modal = AIAssistantModal(session_dir=str(session_a))
                await app.push_screen(modal)
                await pilot.pause()
                await _ask(pilot, modal, "About A")
                await _switch_session(pilot, app, modal, session_b)
                shown = _shown_lines(modal)
                await _ask(pilot, modal, "About B")
                sent = loop.call_args.kwargs["user_message"]
                await pilot.press("escape")
                await pilot.pause()

                reopened = AIAssistantModal(session_dir=str(session_a))
                await app.push_screen(reopened)
                await pilot.pause()
                return shown, sent, _shown_lines(reopened)

    shown, sent, reopened_on_a = asyncio.run(run())
    assert not any("About A" in line for line in shown)
    assert any("conversation cleared" in line for line in shown)
    assert sent == "About B"
    assert not any("About A" in line for line in reopened_on_a)


def test_choosing_the_same_session_keeps_the_conversation(tmp_path):
    session_a = _create_fake_session(tmp_path / "scrutics_20261018_100000")

    async def run():
        app = ScruticsApp()
        with patch("scrutics.ai.config.load_ai_config", return_value=CONFIGURED), \
             patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
             patch("scrutics.ai.agent.run_agent_loop", return_value="answer about A"):
            async with app.run_test() as pilot:
                modal = AIAssistantModal(session_dir=str(session_a))
                await app.push_screen(modal)
                await pilot.pause()
                await _ask(pilot, modal, "About A")
                await _switch_session(pilot, app, modal, session_a)
                return _shown_lines(modal), list(modal._conversation_history)

    shown, history = asyncio.run(run())
    assert "You: About A" in shown
    assert [q for q, _ in history] == ["About A"]


def test_an_answer_arriving_after_close_is_kept_for_the_next_opening(tmp_path):
    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            modal = AIAssistantModal(session_dir=str(tmp_path))
            await app.push_screen(modal)
            await pilot.pause()
            conv = modal._conversation
            await pilot.press("escape")
            await pilot.pause()
            modal._on_query_complete(ChatResult("late answer"), None, conv, "slow question")

            reopened = AIAssistantModal(session_dir=str(tmp_path))
            await app.push_screen(reopened)
            await pilot.pause()
            return _shown_lines(reopened), list(reopened._conversation_history)

    shown, history = asyncio.run(run())
    assert any(line.startswith("Assistant: late answer") for line in shown)
    assert history == [("slow question", "late answer")]


# ── the TUI sends the capped history ─────────────────────────────────────────

def test_the_tui_sends_at_most_five_earlier_exchanges_and_keeps_an_over_cap_answer_start(tmp_path):
    session_dir = _create_fake_session(tmp_path / "scrutics_20261018_100000")
    first_item = "1. 10.0.0.5 Siemens S7-1200"
    long_answer = first_item + "\n" + "x" * 20000 + "\nEnd of list."
    answers = [f"answer {n}" for n in range(1, 8)] + [long_answer, "last"]

    async def run():
        app = ScruticsApp()
        with patch("scrutics.ai.config.load_ai_config", return_value=CONFIGURED), \
             patch("scrutics.ai.config.build_provider", return_value=FakeLLMProvider([])), \
             patch("scrutics.ai.agent.run_agent_loop", side_effect=answers) as loop:
            async with app.run_test() as pilot:
                modal = AIAssistantModal(session_dir=str(session_dir))
                await app.push_screen(modal)
                await pilot.pause()
                for n in range(1, 8):
                    await _ask(pilot, modal, f"question {n}")
                with_six_earlier = loop.call_args.kwargs["user_message"]
                await _ask(pilot, modal, "List the devices")
                await _ask(pilot, modal, "And the first one?")
                return with_six_earlier, loop.call_args.kwargs["user_message"]

    with_six_earlier, follow_up = asyncio.run(run())
    assert "User: question 1\n" not in with_six_earlier
    for n in range(2, 7):
        assert f"User: question {n}\nAssistant: answer {n}" in with_six_earlier
    assert first_item in follow_up
    assert "End of list." in follow_up
    assert "[middle of this answer omitted]" in follow_up
    assert "User: question 7" not in follow_up  # older exchanges no longer fit, dropped whole
