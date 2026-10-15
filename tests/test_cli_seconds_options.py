"""
--duration and --baseline take whole seconds, by the same rule as the TUI Live Capture dialog:
ASCII digits only, duration 0 or more (0 = run until Ctrl+C), baseline 1 or more. Anything else
exits with a usage error naming the option, before any capture starts.
"""

import pytest

from scrutics.cli import build_parser
from scrutics.seconds_input import parse_whole_seconds

INVALID_DURATIONS = ["-5", "1.5", "60s", "", "  ", "+5", "1e3", "٦٠"]
INVALID_BASELINES = ["0", "-1", "1.5", "60s", "", "  "]


def _usage_error(capsys, argv):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(argv)
    assert exc.value.code == 2
    return capsys.readouterr().err


@pytest.mark.parametrize("value", INVALID_DURATIONS)
def test_invalid_duration_is_a_usage_error(capsys, value):
    err = _usage_error(capsys, ["--live", "eth0", "--duration", value])
    assert "argument --duration: must be a whole number of seconds, 0 or more" in err
    assert repr(value) in err


@pytest.mark.parametrize("value", INVALID_BASELINES)
def test_invalid_baseline_is_a_usage_error(capsys, value):
    err = _usage_error(capsys, ["--file", "capture.pcap", "--baseline", value])
    assert "argument --baseline: must be a whole number of seconds, 1 or more" in err


@pytest.mark.parametrize("value, expected", [("0", 0), ("60", 60), ("3600", 3600)])
def test_valid_durations_are_accepted(value, expected):
    assert build_parser().parse_args(["--live", "eth0", "--duration", value]).duration == expected


@pytest.mark.parametrize("value, expected", [("1", 1), ("60", 60)])
def test_valid_baselines_are_accepted(value, expected):
    assert build_parser().parse_args(["--live", "eth0", "--baseline", value]).baseline == expected


def test_defaults_are_unchanged():
    args = build_parser().parse_args(["--live", "eth0"])
    assert (args.duration, args.baseline) == (60, 60)


def test_cli_and_dialog_share_one_rule():
    from scrutics.ui import tui
    assert tui.parse_whole_seconds is parse_whole_seconds
