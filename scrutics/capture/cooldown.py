"""
Anomaly cooldowns whose keys age out.

A cooldown key (for example "PEER_10.0.0.5") suppresses further alerts of its kind while the packet
time is less than `cooldown` seconds after the time stored for it. Keeping every key forever lets
the table grow with each distinct peer, port or MAC/IP pair ever alerted on; here each key is
deleted once it can no longer change a decision for packets near the newest packet time.

The watermark is the latest packet time this table has been asked about. A packet more than one
cooldown behind the watermark is late (out of order, as in merged captures or logs):
- A key is deleted once the watermark is two cooldowns past its stored time. Any packet at most
  one cooldown behind the watermark is then at least one cooldown after the stored time, so it
  would be allowed with or without the key: decisions for such packets are unchanged.
- A late packet whose key was deleted is allowed, where keeping the key could have suppressed it.
  An allowed late packet stores watermark - cooldown instead of its own time, so the stored times
  of one key's successive alerts rise by at least one cooldown and never exceed the watermark. A
  key therefore alerts at most floor((W1 - W0) / cooldown) + 2 times while the watermark moves
  from W0 to W1, however many late packets arrive.

Deletion is amortized O(1) per call: every stored time is queued once, in the order it was
stored, and removed once. A queued entry whose key was stored again since is dropped without
deleting the key. Entries of the table that were not stored through allow() are never deleted.
"""

from collections import deque


class Cooldowns:
    """Cooldown decisions over `times` (key -> stored time), deleting keys that have aged out."""

    def __init__(self, times: dict):
        self.times = times
        self.watermark = None
        self._queue = deque()            # (deletion time, key, stored time), in storing order

    def allow(self, key, timestamp: float, cooldown: float) -> bool:
        """Whether an alert for key may fire at timestamp; if so, it is recorded."""
        if self.watermark is None or timestamp > self.watermark:
            self.watermark = timestamp
        self._expire()
        last = self.times.get(key)
        if last is not None and (timestamp - last) < cooldown:
            return False
        stored = max(timestamp, self.watermark - cooldown)
        self.times[key] = stored
        self._queue.append((stored + 2 * cooldown, key, stored))
        return True

    def _expire(self) -> None:
        queue, times, watermark = self._queue, self.times, self.watermark
        while queue and queue[0][0] <= watermark:
            _, key, stored = queue.popleft()
            if key in times and times[key] == stored:
                del times[key]
