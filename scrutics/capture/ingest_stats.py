"""
Accounting for input that could not be used during a run.

Two counts are kept and reported separately:
- rejected: validation dropped a packet, record or log line (expected for malformed input);
- contained: processing one item raised an unexpected exception, which was caught so the
  run could continue. Contained errors are aggregated per (exception type, code site); only
  the first occurrence's detail is kept.

Every text that can carry input content (exception messages) is stored as plain text with
control characters shown as escapes, so it cannot drive a terminal. Callers must still show it
without markup parsing (the TUI passes markup=False to notifications).
"""

import os
import traceback
from dataclasses import dataclass

# Distinct contained-error kinds kept with detail; further new kinds share one overflow count
CONTAINED_KEY_LIMIT = 64
MESSAGE_LIMIT = 200

_PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Captured frames that can produce an asset, and why such a frame may still be left out
SUPPORTED_FRAMES = "Ethernet with an IPv4 or ARP source address"
FILTERED_SCOPE = "source address outside the inventory scope"
FILTERED_MAC = "broadcast or zero source MAC"

# Paths that number their items as packets; the others number lines
_PACKET_PATHS = ("live", "pcap")


def plain_text(value, limit: int = MESSAGE_LIMIT) -> str:
    """Printable text only: control and other non-printable characters become escapes."""
    out = []
    for ch in str(value):
        if ch.isprintable():
            out.append(ch)
        elif ord(ch) < 0x100:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    text = "".join(out)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _item_label(path: str, item: int) -> str:
    return f"{path} {'packet' if path in _PACKET_PATHS else 'line'} {item}"


def _code_site(exc: BaseException) -> str:
    """Innermost frame inside the scrutics package, else the innermost frame overall."""
    frames = traceback.extract_tb(exc.__traceback__)
    if not frames:
        return "unknown"
    own = [f for f in frames if os.path.abspath(f.filename).startswith(_PACKAGE_DIR + os.sep)]
    frame = own[-1] if own else frames[-1]
    if own:
        name = os.path.relpath(os.path.abspath(frame.filename), _PACKAGE_DIR).replace(os.sep, "/")
    else:
        name = os.path.basename(frame.filename)
    return f"{name}:{frame.lineno} ({frame.name})"


@dataclass
class ContainedError:
    exception_type: str
    site: str
    count: int
    first_item: str      # e.g. "pcap packet 3" or "suricata line 12"
    first_message: str   # plain text


class IngestStats:
    def __init__(self, log=None):
        self._log = log                    # callable(str) for one event log entry
        self.rejected_total = 0
        self.rejected_by_reason: dict = {}
        self.contained: dict = {}          # (exception type, site) -> ContainedError
        self.contained_overflow = 0        # occurrences of kinds beyond CONTAINED_KEY_LIMIT
        self.warned_total = 0
        self.warned_by_reason: dict = {}   # items processed, with a field that was not used
        self.capture_file_problem = None   # CaptureFileProblem when a capture file ended early
        # Captured frames (pcap and live only): how many were read, how many carried a source
        # MAC and an IPv4/ARP source address, and why the others could not produce an asset
        self.frame_source = None           # "pcap" or "live" once a capture runs
        self.frames_read = 0
        self.frames_supported = 0
        self.unsupported_by_kind: dict = {}    # keys from scrutics.capture.frame_kinds.KINDS
        self.filtered_by_reason: dict = {}     # keys FILTERED_SCOPE, FILTERED_MAC

    @property
    def contained_total(self) -> int:
        return sum(e.count for e in self.contained.values()) + self.contained_overflow

    def reject(self, reason: str, path: str, item: int, label: str | None = None) -> None:
        """
        Record an item dropped by validation. One event log entry per new reason. `label` names
        the location when "<path> packet/line <item>" would not be exact.
        """
        self.rejected_total += 1
        first = reason not in self.rejected_by_reason
        self.rejected_by_reason[reason] = self.rejected_by_reason.get(reason, 0) + 1
        if first:
            self._emit(f"Rejected input at {label or _item_label(path, item)}: {reason}; "
                       "further rejections of this kind are counted")

    def capture_file_ended_early(self, problem) -> None:
        """Record that a capture file was not read to its end (see scrutics.capture.capture_file)."""
        self.capture_file_problem = problem
        self.reject(problem.reason, "pcap", problem.packets_read + 1, label=problem.location)

    def unsupported_frame(self, kind: str) -> None:
        self.unsupported_by_kind[kind] = self.unsupported_by_kind.get(kind, 0) + 1

    def filtered_frame(self, reason: str) -> None:
        self.filtered_by_reason[reason] = self.filtered_by_reason.get(reason, 0) + 1

    @property
    def unsupported_total(self) -> int:
        return sum(self.unsupported_by_kind.values())

    def _kind_counts(self) -> str:
        from scrutics.capture.frame_kinds import KINDS
        return ", ".join(f"{kind}: {self.unsupported_by_kind[kind]}"
                         for kind in KINDS if self.unsupported_by_kind.get(kind))

    def frame_lines(self, asset_count: int) -> list:
        """
        Summary lines about the captured frames, as (severity, text): "warning" for a capture
        that produced no assets, "information" for the kind counts. Empty for log input, and for
        a capture file that stopped early (its own line explains the result). The lines state
        observed counts only.
        """
        if self.frame_source is None:
            return []
        lines = []
        kinds = self._kind_counts()
        if asset_count == 0 and self.capture_file_problem is None:
            if self.frames_read == 0:
                return [("warning", "No assets: the capture contains no frames.")]
            if self.frames_supported == 0:
                return [("warning", f"No assets: {self.frames_read} frames read, none of a kind Scrutics "
                                    f"builds assets from ({SUPPORTED_FRAMES}). Frames seen: {kinds}.")]
            filtered = ", ".join(f"{r}: {n}" for r, n in sorted(self.filtered_by_reason.items()))
            lines.append(("warning", f"No assets: {self.frames_read} frames read, "
                                     f"{self.frames_supported} of a supported kind ({SUPPORTED_FRAMES}); "
                                     f"none produced an asset"
                                     + (f" ({filtered})." if filtered else ".")))
        if kinds:
            lines.append(("information", f"Frames of kinds Scrutics does not build assets from: "
                                         f"{self.unsupported_total} ({kinds})."))
        return lines

    def capture_file_line(self) -> str:
        """The run summary line for a capture file not read to its end, or "" when it was."""
        return self.capture_file_problem.summary() if self.capture_file_problem else ""

    def warn(self, reason: str, path: str, item: int) -> None:
        """Record an item that was processed but whose `reason` field or evidence was not used.
        One event log entry per new reason."""
        self.warned_total += 1
        first = reason not in self.warned_by_reason
        self.warned_by_reason[reason] = self.warned_by_reason.get(reason, 0) + 1
        if first:
            self._emit(f"Field warning at {_item_label(path, item)}: {reason}; "
                       "further warnings of this kind are counted")

    def contain(self, exc: Exception, path: str, item: int) -> None:
        """Record a caught unexpected exception. One event log entry per new kind."""
        key = (type(exc).__name__, _code_site(exc))
        entry = self.contained.get(key)
        if entry is not None:
            entry.count += 1
            return
        if len(self.contained) >= CONTAINED_KEY_LIMIT:
            self.contained_overflow += 1
            if self.contained_overflow == 1:
                self._emit(f"More than {CONTAINED_KEY_LIMIT} kinds of contained errors; "
                           "further new kinds are counted without detail")
            return
        entry = ContainedError(key[0], key[1], 1, _item_label(path, item), plain_text(exc))
        self.contained[key] = entry
        self._emit(f"Contained error at {entry.first_item}: {entry.exception_type} at "
                   f"{entry.site}: {entry.first_message}; the item was skipped and further "
                   "occurrences are counted")

    def has_issues(self) -> bool:
        return bool(self.rejected_total or self.contained_total or self.warned_total)

    def summary_line(self, max_kinds: int = 3) -> str:
        """One plain-text line with both counts, for the CLI and TUI run summaries."""
        parts = [f"Input: {self.rejected_total} rejected"]
        if self.rejected_by_reason:
            reasons = ", ".join(f"{r}: {n}" for r, n in sorted(self.rejected_by_reason.items()))
            parts[0] += f" ({reasons})"
        contained = f"{self.contained_total} contained errors"
        if self.contained:
            kinds = sorted(self.contained.values(), key=lambda e: -e.count)
            shown = "; ".join(f"{e.exception_type} at {e.site} x{e.count}, first at "
                              f"{e.first_item}: {e.first_message}" for e in kinds[:max_kinds])
            more = len(self.contained) - max_kinds
            contained += f" ({shown}{f'; {more} more kinds' if more > 0 else ''})"
        parts.append(contained)
        if self.warned_by_reason:
            reasons = ", ".join(f"{r}: {n}" for r, n in sorted(self.warned_by_reason.items()))
            parts.append(f"{self.warned_total} field warnings ({reasons})")
        return " | ".join(parts)

    def _emit(self, message: str) -> None:
        if self._log is not None:
            self._log(message)
