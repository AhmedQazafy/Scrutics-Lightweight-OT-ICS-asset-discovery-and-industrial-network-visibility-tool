"""
Reading a pcap or pcapng file to its real end, and saying so when it does not get there.

Scapy's readers stop without an error at a damaged record. A classic pcap record whose length
field claims more bytes than remain is returned as one packet holding the rest of the file, and
iteration then ends as if the file were complete; a pcapng block with a bad length ends iteration
or raises. CaptureFile wraps the reader's file object to see every read (bytes asked for and
bytes returned), so the end of the file can be checked from the reader's own reads.

Resynchronising past a damaged record is not attempted: classic pcap record headers carry no
marker, and finding the next pcapng block after a corrupted length means scanning for something
that looks like one. Reading stops at the first damaged record, which is never processed.

Two outcomes are reported, besides a clean end:
- "incomplete": the file ends inside the last record or block, as when a capture is stopped
  abruptly. A classic pcap record is incomplete when its header is within the format's limits
  (captured length not above the snapshot length when one is set, nor above the original length)
  but fewer bytes remain than it claims. A pcapng Enhanced Packet Block is incomplete when its own
  captured-length field fits the block and the file ends inside the packet data.
- "damaged": anything else, such as a record header outside those limits or a pcapng block whose
  length fields disagree; the rest of the file is not read.
Records are numbered only in classic pcap, where the count is exact. In pcapng the position is
given as the number of packets read and the byte offset where reading stopped; blocks that are not
packets are not counted.

Known limit: a pcapng file with exactly four stray bytes after its last complete block ends like
a clean file, so it is not reported.
"""

import gzip
import os
import struct
from collections import deque
from dataclasses import dataclass

INCOMPLETE = "incomplete"
DAMAGED = "damaged"

# Rejection reasons (one count each in IngestStats)
REASON_INCOMPLETE = "incomplete last record (capture stopped abruptly)"
REASON_DAMAGED = "damaged capture file (the rest was not read)"

_CLASSIC_HEADER = 16          # pcap record header: ts_sec, ts_usec, incl_len, orig_len
_PCAPNG_PACKET_BLOCKS = 6     # Enhanced Packet Block type
_EPB_FIXED = 20               # interface id, timestamp (2), captured length, original length


@dataclass
class CaptureFileProblem:
    kind: str           # INCOMPLETE or DAMAGED
    pcapng: bool
    packets_read: int   # packets read before the problem
    offset: int         # byte offset where the unusable data starts (decompressed for gzip input)

    @property
    def reason(self) -> str:
        return REASON_INCOMPLETE if self.kind == INCOMPLETE else REASON_DAMAGED

    @property
    def location(self) -> str:
        if self.pcapng:
            return f"pcapng file after {self.packets_read} packets, at byte offset {self.offset}"
        return f"pcap record {self.packets_read + 1}"

    def summary(self) -> str:
        if self.pcapng:
            where = f"after {self.packets_read} packets, at byte offset {self.offset}"
            if self.kind == INCOMPLETE:
                return (f"The last pcapng block ({where}) is incomplete, typical of a capture "
                        "stopped abruptly; it was skipped.")
            return (f"Analysis stopped {where} of a damaged pcapng file; "
                    "the rest of the file was not read.")
        record = self.packets_read + 1
        if self.kind == INCOMPLETE:
            return (f"The last record (pcap record {record}) is incomplete, typical of a capture "
                    "stopped abruptly; it was skipped.")
        return (f"Analysis stopped at pcap record {record} (byte offset {self.offset}) of a "
                "damaged file; the rest of the file was not read.")


class _ReadTracker:
    """
    File object wrapper that records the reader's reads, per read_packet() call: bytes asked for,
    bytes returned, a short prefix and the start position. Decisions use the call's own reads (its
    first read is the record header), so they do not depend on how a Scapy version splits the
    record data into reads.

    A read never asks the file for more than it holds: a corrupted length field can ask for up
    to 4 GiB, so reads are capped at the bytes left in a plain file and done in bounded chunks
    for a compressed one. The data returned is the same as an unbounded read.
    """

    _CHUNK = 1 << 20

    def __init__(self, inner):
        self.inner = inner
        # The file header was read before wrapping: positions count from the start of the file
        try:
            self.pos = inner.tell()
        except (OSError, ValueError, AttributeError):
            self.pos = 0
        try:
            self._size = None if isinstance(inner, gzip.GzipFile) else os.fstat(inner.fileno()).st_size
        except (OSError, ValueError, AttributeError):
            self._size = None
        self.partial = False                 # a read returned some but not all bytes asked for
        self.recent = deque(maxlen=3)        # (asked, returned, first bytes, start position)
        self.begin_call()

    def begin_call(self):
        self.call_first = None               # first read of the current read_packet() call
        self.call_short = False              # a read of the current call came back short

    def _bounded_read(self, size):
        if size is None or size < 0:
            return self.inner.read()
        if self._size is not None:
            return self.inner.read(max(0, min(size, self._size - self.pos)))
        if size <= self._CHUNK:
            return self.inner.read(size)
        parts, left = [], size
        while left > 0:
            part = self.inner.read(min(left, self._CHUNK))
            if not part:
                break
            parts.append(part)
            left -= len(part)
        return b"".join(parts)

    def read(self, size=-1):
        start = self.pos
        data = self._bounded_read(size)
        self.pos += len(data)
        short = size is not None and size >= 0 and len(data) < size
        if short and data:
            self.partial = True
        self.call_short = self.call_short or short
        entry = (size, len(data), data[:_EPB_FIXED], start)
        if self.call_first is None:
            self.call_first = entry
        self.recent.append(entry)
        return data

    def last(self, back: int = 1):
        return self.recent[-back] if len(self.recent) >= back else None

    def __getattr__(self, name):
        return getattr(self.inner, name)


class CaptureFile:
    """
    Iterate the packets of a pcap or pcapng file. After a full iteration, `problem` is None for a
    file read to its end, else a CaptureFileProblem. A damaged or incomplete record is not yielded.
    """

    def __init__(self, filepath: str):
        from scapy.utils import PcapNgReader, PcapReader
        self.reader = PcapReader(filepath)
        self.pcapng = isinstance(self.reader, PcapNgReader)
        self._tracker = _ReadTracker(self.reader.f)
        self.reader.f = self._tracker
        self.problem = None
        self.packets_read = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        # Put the real file object back first: the reader's close checks its type (gzip)
        self.reader.f = self._tracker.inner
        self.reader.close()

    def __iter__(self):
        from scapy.error import Scapy_Exception
        tracker = self._tracker
        while True:
            start = tracker.pos
            tracker.begin_call()
            try:
                pkt = self.reader.read_packet()
            except (EOFError, Scapy_Exception):
                # Only the reader is guarded. Depending on the Scapy version, a pcapng block
                # shorter than its length field ends with EOFError or Scapy_Exception
                self.problem = self._end_problem(start)
                return
            if not self.pcapng and tracker.call_short:
                self.problem = self._classic_short_record(start)
                return
            self.packets_read += 1
            yield pkt

    # ── classic pcap ──────────────────────────────────────────────────────
    def _classic_header_within_limits(self, header) -> bool:
        _, _, caplen, wirelen = struct.unpack(self.reader.endian + "IIII", header[:_CLASSIC_HEADER])
        snaplen = getattr(self.reader, "snaplen", 0)
        return caplen <= wirelen and (not snaplen or caplen <= snaplen)

    def _classic_short_record(self, start: int) -> CaptureFileProblem:
        """A record whose data ran past the end of the file; its header is the call's first read."""
        header = self._tracker.call_first
        kind = DAMAGED
        if header is not None and header[1] == _CLASSIC_HEADER and self._classic_header_within_limits(header[2]):
            kind = INCOMPLETE
        return CaptureFileProblem(kind, False, self.packets_read, start)

    # ── end of iteration ──────────────────────────────────────────────────
    def _end_problem(self, start: int):
        tracker = self._tracker
        if self.pcapng:
            short_block = self._pcapng_short_block(start)
            if short_block is not None:
                return short_block
            last = tracker.last()
            if last is None or (last[1] == 0 and not tracker.partial):
                return None
            asked, got, _, _ = last
            # A block header cut short by the end of the file is the last block, incomplete;
            # a complete read followed by the reader giving up means the block is inconsistent
            kind = INCOMPLETE if 0 < got < (asked or 0) else DAMAGED
            return CaptureFileProblem(kind, True, self.packets_read, start)
        # Classic pcap: the end is clean only when the call's header read returns nothing
        first = tracker.call_first
        if first is None or (first[1] == 0 and first[0] == _CLASSIC_HEADER):
            return None
        asked, got, _, _ = first
        kind = INCOMPLETE if asked == _CLASSIC_HEADER and 0 < got < _CLASSIC_HEADER else DAMAGED
        return CaptureFileProblem(kind, False, self.packets_read, start)

    # ── pcapng block shorter than its length field ────────────────────────
    def _pcapng_short_block(self, start: int):
        """
        A block whose body came back shorter than its length field says: the last three reads are
        its type (4 bytes), its length (4 bytes) and the short body. None for any other end.
        """
        body, length, block_type = (self._tracker.last(i) for i in (1, 2, 3))
        if not (body and length and block_type and length[1] == 4 and block_type[1] == 4
                and length[0] == 4 and block_type[0] == 4 and body[0] is not None and body[1] < body[0]):
            return None
        endian = self.reader.endian
        btype = struct.unpack(endian + "I", block_type[2][:4])[0]
        blocklen = struct.unpack(endian + "I", length[2][:4])[0]
        if body[0] != blocklen - 12:
            return None
        got = body[1]
        kind = DAMAGED
        if btype == _PCAPNG_PACKET_BLOCKS:
            if got < _EPB_FIXED:
                kind = INCOMPLETE
            else:
                caplen = struct.unpack(endian + "I", body[2][12:16])[0]
                if _EPB_FIXED + 12 + caplen <= blocklen and got < _EPB_FIXED + caplen:
                    kind = INCOMPLETE
        return CaptureFileProblem(kind, True, self.packets_read, start)
