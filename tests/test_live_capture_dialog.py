"""
Duration and baseline in the Live Capture dialog.

Both fields take whole seconds: duration 0 or more (0 = run until stopped), baseline 1 or more.
Any other text shows a message in the dialog, keeps it open and starts nothing; it never raises.
The default duration is 60 s, the same as the CLI.
"""

import asyncio

import pytest
from textual.widgets import Label

from scrutics.capture.engine import CaptureEngine
from scrutics.ui.tui import (
    BASELINE_ERROR, DURATION_ERROR, FormInput, LiveCaptureModal, ScruticsApp, parse_whole_seconds,
)

INVALID_DURATIONS = ["1.5", "  ", "", "60s", "-5", "+5", "1e3", "٦٠"]   # last: Arabic-Indic digits
INVALID_BASELINES = ["0", "-1", "1.5", "", "  ", "60s"]


def _submit(duration=None, baseline=None):
    """Open the dialog, set the fields, press Start. Returns (dismissed results, open, error text)."""
    results = []

    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            modal = LiveCaptureModal()
            await app.push_screen(modal, results.append)
            await pilot.pause()
            defaults = (modal.query_one("#duration-input", FormInput).value,
                        modal.query_one("#baseline-input", FormInput).value)
            if duration is not None:
                modal.query_one("#duration-input", FormInput).value = duration
            if baseline is not None:
                modal.query_one("#baseline-input", FormInput).value = baseline
            await pilot.click("#start-btn")
            await pilot.pause()
            if app.screen is not modal:
                return defaults, False, ""
            error = modal.query_one("#setup-error", Label)
            message = str(error.render()) if error.display else ""
            return defaults, True, message

    defaults, still_open, message = asyncio.run(run())
    return results, still_open, message, defaults


def test_dialog_opens_with_the_cli_default_duration():
    *_, defaults = _submit()
    assert defaults == ("60", "60")


@pytest.mark.parametrize("value", INVALID_DURATIONS)
def test_invalid_duration_shows_a_message_and_keeps_the_dialog_open(value):
    results, still_open, message, _ = _submit(duration=value)
    assert results == [] and still_open
    assert message == DURATION_ERROR


@pytest.mark.parametrize("value", INVALID_BASELINES)
def test_invalid_baseline_shows_a_message_and_keeps_the_dialog_open(value):
    results, still_open, message, _ = _submit(baseline=value)
    assert results == [] and still_open
    assert message == BASELINE_ERROR


@pytest.mark.parametrize("duration, baseline, expected", [
    ("0", "60", (0, 60)), ("60", "60", (60, 60)), (" 120 ", "1", (120, 1)),
])
def test_valid_values_are_accepted(duration, baseline, expected):
    results, still_open, message, _ = _submit(duration=duration, baseline=baseline)
    assert not still_open and message == ""
    [config] = results
    assert (config["duration"], config["baseline"]) == expected


@pytest.mark.parametrize("text, minimum, expected", [
    ("0", 0, 0), ("60", 0, 60), (" 7 ", 1, 7), ("0", 1, None), ("-5", 0, None), ("1.5", 0, None),
    ("", 0, None), (None, 0, None), ("60s", 0, None), ("٦", 0, None),
])
def test_parse_whole_seconds(text, minimum, expected):
    assert parse_whole_seconds(text, minimum) == expected


def test_invalid_input_starts_no_capture_and_zero_runs_until_stopped(tmp_path, monkeypatch):
    monkeypatch.setenv("SCRUTICS_AUTO_OUTPUT", str(tmp_path))
    started, statuses = [], []
    monkeypatch.setattr(CaptureEngine, "start_live",
                        lambda self, interface, timeout=60, packet_count=0: started.append(timeout))
    original_status = ScruticsApp._set_status

    def record_status(self, value, *args, **kwargs):
        statuses.append(value)
        return original_status(self, value, *args, **kwargs)

    monkeypatch.setattr(ScruticsApp, "_set_status", record_status)

    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            modal = LiveCaptureModal()
            await app.push_screen(modal, app._on_capture_config)
            await pilot.pause()
            duration_input = modal.query_one("#duration-input", FormInput)
            for value in INVALID_DURATIONS:
                duration_input.value = value
                modal.query_one("#start-btn").focus()
                await pilot.click("#start-btn")
                # Buttons ignore a press during their 0.2 s active effect
                await pilot.pause(0.3)
                assert app.screen is modal
                assert app.focused is duration_input      # the press was handled: error shown
            assert started == []
            duration_input.value = "0"
            await pilot.click("#start-btn")
            for _ in range(20):
                await pilot.pause(0.05)
                if started:
                    break
    asyncio.run(run())
    assert started == [0]
    assert any("duration: infinite (stop with Q)" in s for s in statuses)


def test_the_message_fits_inside_the_dialog():
    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            modal = LiveCaptureModal()
            await app.push_screen(modal)
            await pilot.pause()
            modal.query_one("#duration-input", FormInput).value = "60s"
            await pilot.click("#start-btn")
            await pilot.pause()
            error = modal.query_one("#setup-error", Label)
            content = modal.query_one("#setup-dialog").content_region
            assert error.display and error.region.width <= content.width
            assert error.region.height >= 2          # the long message wraps instead of clipping
    asyncio.run(run())
