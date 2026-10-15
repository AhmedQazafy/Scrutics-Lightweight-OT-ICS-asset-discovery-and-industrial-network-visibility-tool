"""
Whole-second values typed by a person: the capture duration and the baseline window.

The CLI options and the TUI Live Capture dialog use the same rule: ASCII digits only, surrounding
whitespace ignored, no sign, decimal point or unit suffix. A duration is 0 or more (0 = run until
stopped); a baseline window is 1 or more.
"""

import argparse

MIN_DURATION = 0
MIN_BASELINE = 1


def parse_whole_seconds(text, minimum: int):
    """
    Whole seconds typed into a field or option, or None when the text is not one.

    Only ASCII digits are accepted, with surrounding whitespace ignored: no sign, decimal point,
    unit suffix or empty value. A value below `minimum` is also None.
    """
    value = str(text or "").strip()
    if not (value.isascii() and value.isdigit()):
        return None
    seconds = int(value)
    return seconds if seconds >= minimum else None


def _option_type(minimum: int, rule: str):
    def parse(text):
        seconds = parse_whole_seconds(text, minimum)
        if seconds is None:
            raise argparse.ArgumentTypeError(f"must be a whole number of seconds, {rule}; got {text!r}")
        return seconds
    return parse


# argparse `type=` callables; an invalid value exits with a usage error naming the option
duration_option = _option_type(MIN_DURATION, "0 or more (0 = run until Ctrl+C)")
baseline_option = _option_type(MIN_BASELINE, "1 or more")
