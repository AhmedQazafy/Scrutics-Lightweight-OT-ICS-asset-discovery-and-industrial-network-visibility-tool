"""
Behavioral Baseline Engine for Scrutics.
Builds per-device behavioral baseline, detects anomalies.
"""

import time
import statistics
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DeviceBaseline:
    ip: str
    observation_window: int = 60
    _intervals: deque = field(default_factory=lambda: deque(maxlen=200))
    _last_packet_time: Optional[float] = None
    _peers_observed: set = field(default_factory=set)
    _initiate_count: int = 0
    _respond_count: int = 0
    _observation_start: Optional[float] = None
    locked: bool = False
    mean_interval: Optional[float] = None
    interval_stddev: Optional[float] = None
    known_peers: set = field(default_factory=set)
    typically_initiates: bool = False
    _last_anomaly_ts: dict = field(default_factory=dict)

    def observe(self, timestamp: float, initiates: bool, peers: set) -> Optional[dict]:
        if self._observation_start is None:
            self._observation_start = timestamp
        if self._last_packet_time is not None:
            interval = timestamp - self._last_packet_time
            if interval > 0:
                self._intervals.append(interval)
        self._last_packet_time = timestamp
        self._peers_observed.update(peers)
        if initiates:
            self._initiate_count += 1
        else:
            self._respond_count += 1
        if not self.locked and (timestamp - self._observation_start) >= self.observation_window:
            self._lock()
        if self.locked:
            return self._check_anomaly(timestamp, initiates, peers)
        return None

    def _lock(self):
        self.locked = True
        self.known_peers = set(self._peers_observed)
        self.typically_initiates = self._initiate_count > self._respond_count
        if len(self._intervals) >= 5:
            self.mean_interval = statistics.mean(self._intervals)
            self.interval_stddev = max(statistics.stdev(self._intervals), 0.05)

    def _check_anomaly(self, timestamp: float, initiates: bool, peers: set) -> Optional[dict]:
        new_peers = peers - self.known_peers
        if new_peers:
            self.known_peers.update(new_peers)
            return {"type": "NEW_PEER", "detail": f"New peer(s): {', '.join(new_peers)}", "severity": "MEDIUM"}
        if not self.typically_initiates and initiates:
            if self._anomaly_allowed("DIRECTIONALITY_CHANGE", timestamp, cooldown=300):
                return {"type": "DIRECTIONALITY_CHANGE", "detail": "Device now initiating connections", "severity": "HIGH"}
        if self.mean_interval and self._intervals and self.interval_stddev:
            last = self._intervals[-1]
            if abs(last - self.mean_interval) > (self.interval_stddev * 4):
                if not self._anomaly_allowed("INTERVAL_ANOMALY", timestamp, cooldown=60):
                    return None
                return {
                    "type": "INTERVAL_ANOMALY",
                    "detail": f"Polling interval {last:.2f}s deviates from baseline {self.mean_interval:.2f}s ±{self.interval_stddev:.2f}s",
                    "severity": "LOW",
                }
        return None

    def _anomaly_allowed(self, anomaly_type: str, timestamp: float, cooldown: float) -> bool:
        last = self._last_anomaly_ts.get(anomaly_type)
        if last is not None and timestamp >= last and (timestamp - last) < cooldown:
            return False
        self._last_anomaly_ts[anomaly_type] = timestamp
        return True

    def behavioral_score(self) -> int:
        total = self._initiate_count + self._respond_count
        if total == 0: return 0
        if not self.locked:
            if self.observation_window <= 0 or self._observation_start is None or self._last_packet_time is None:
                progress = 1.0
            else:
                progress = min((self._last_packet_time - self._observation_start) / self.observation_window, 1.0)
            return max(1, int(progress * 10))
        return 20

    def directionality_score(self) -> int:
        total = self._initiate_count + self._respond_count
        if total == 0: return 0
        dominant = max(self._initiate_count, self._respond_count)
        ratio = dominant / total
        if ratio >= 0.9: return 10
        elif ratio >= 0.7: return 7
        elif ratio >= 0.5: return 4
        return 2

    @property
    def status(self) -> str:
        total = self._initiate_count + self._respond_count
        if total == 0: return "no_data"
        if not self.locked:
            if self.observation_window <= 0 or self._observation_start is None or self._last_packet_time is None:
                pct = 99
            else:
                elapsed = self._last_packet_time - self._observation_start
                pct = int(min(elapsed / self.observation_window * 100, 99))
            return f"building ({pct}%)"
        return "active"


class BaselineEngine:
    def __init__(self, observation_window: int = 60):
        self.observation_window = observation_window
        self._devices: dict = {}
        self.anomaly_log: deque = deque(maxlen=100)

    def observe(self, ip: str, timestamp: float, initiates: bool, peers: set) -> Optional[dict]:
        if ip not in self._devices:
            self._devices[ip] = DeviceBaseline(ip=ip, observation_window=self.observation_window)
        anomaly = self._devices[ip].observe(timestamp, initiates, peers)
        if anomaly:
            anomaly["ip"] = ip
            anomaly["timestamp"] = timestamp
            self.anomaly_log.append(anomaly)
            return anomaly
        return None

    def get_behavioral_score(self, ip: str) -> int:
        return self._devices[ip].behavioral_score() if ip in self._devices else 0

    def get_directionality_score(self, ip: str) -> int:
        return self._devices[ip].directionality_score() if ip in self._devices else 0

    def get_status(self, ip: str) -> str:
        return self._devices[ip].status if ip in self._devices else "no_data"

    def get_anomalies(self) -> list:
        return list(self.anomaly_log)
