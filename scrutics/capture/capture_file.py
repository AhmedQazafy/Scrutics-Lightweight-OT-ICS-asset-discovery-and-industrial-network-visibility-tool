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
    """File object wrapper that records each read: bytes asked for, returned, and a short prefix."""

    def __init__(self, inner):
        self.inner = inner
        # The file header was read before wrapping: positions count from the start of the file
        try:
            self.pos = inner.tell()
        except (OSError, ValueError, AttributeError):
            self.pos = 0
        self.reads = 0
        self.partial = False                 # a read returned some but not all bytes asked for
        self.recent = deque(maxlen=3)        # (asked, returned, first bytes, start position)

    def read(self, size=-1):
        start = self.pos
        data = self.inner.read(size)
        self.pos += len(data)
        self.reads += 1
        if size is not None and 0 < len(data) < size:
            self.partial = True
        self.recent.append((size, len(data), data[:_EPB_FIXED], start))
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
            start, reads_before = tracker.pos, tracker.reads
            try:
                pkt = self.reader.read_packet()
            except EOFError:
                self.problem = self._end_problem(start)
                return
            except Scapy_Exception:
                # Only the reader is guarded: a pcapng block shorter than its length field says
                self.problem = self._pcapng_short_block(start)
                return
            if not self.pcapng and self._classic_short_read(reads_before):
                self.problem = self._classic_short_record(start)
                return
            self.packets_read += 1
            yield pkt

    # ── classic pcap ──────────────────────────────────────────────────────
    def _classic_short_read(self, reads_before: int) -> bool:
        count = self._tracker.reads - reads_before
        if count <= 0:
            return False
        record_reads = list(self._tracker.recent)[-count:]
        return any(asked is not None and got < asked for asked, got, _, _ in record_reads)

    def _classic_short_record(self, start: int) -> CaptureFileProblem:
        header = self._tracker.last(2)
        kind = DAMAGED
        if header is not None and header[1] == _CLASSIC_HEADER:
            _, _, caplen, wirelen = struct.unpack(self.reader.endian + "IIII", header[2][:_CLASSIC_HEADER])
            snaplen = getattr(self.reader, "snaplen", 0)
            if caplen <= wirelen and (not snaplen or caplen <= snaplen):
                kind = INCOMPLETE
        return CaptureFileProblem(kind, False, self.packets_read, start)

    # ── end of iteration ──────────────────────────────────────────────────
    def _end_problem(self, start: int):
        last = self._tracker.last()
        if last is None:
            return None
        asked, got, _, _ = last
        if self.pcapng:
            if got == 0 and not self._tracker.partial:
                return None
            # A block header cut short by the end of the file is the last block, incomplete;
            # a complete read followed by the reader giving up means the block is inconsistent
            kind = INCOMPLETE if 0 < got < (asked or 0) else DAMAGED
            return CaptureFileProblem(kind, True, self.packets_read, start)
        # Classic pcap reads alternate header (16 bytes) and record data; the end is clean only
        # when a header read returns nothing
        if got == 0 and asked == _CLASSIC_HEADER:
            return None
        kind = INCOMPLETE if 0 < got < _CLASSIC_HEADER and asked == _CLASSIC_HEADER else DAMAGED
        return CaptureFileProblem(kind, False, self.packets_read, start)

    # ── pcapng block shorter than its length field ────────────────────────
    def _pcapng_short_block(self, start: int) -> CaptureFileProblem:
        body, length, block_type = (self._tracker.last(i) for i in (1, 2, 3))
        kind = DAMAGED
        if body and length and block_type and length[1] == 4 and block_type[1] == 4:
            endian = self.reader.endian
            btype = struct.unpack(endian + "I", block_type[2][:4])[0]
            blocklen = struct.unpack(endian + "I", length[2][:4])[0]
            got = body[1]
            if btype == _PCAPNG_PACKET_BLOCKS:
                if got < _EPB_FIXED:
                    kind = INCOMPLETE
                else:
                    caplen = struct.unpack(endian + "I", body[2][12:16])[0]
                    if _EPB_FIXED + 12 + caplen <= blocklen and got < _EPB_FIXED + caplen:
                        kind = INCOMPLETE
        return CaptureFileProblem(kind, True, self.packets_read, start)
