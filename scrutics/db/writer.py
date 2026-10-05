"""
Rolling append-mode CSV writer for events and anomalies.
Replaces the end-of-session _event_buffer flush so data is always
on disk, crash-safe for infinite / long-running sessions.
"""

import csv
import datetime
import os
import threading


class RollingWriter:
    """
    Thread-safe, append-mode CSV writer.
    Creates events.csv and anomalies.csv with headers on instantiation.
    Files are closed after every write for crash durability.
    """

    _ANOMALY_FIELDS = ["timestamp", "ip", "type", "severity", "detail"]

    def __init__(self, session_dir: str):
        self._events_path    = os.path.join(session_dir, "events.csv")
        self._anomalies_path = os.path.join(session_dir, "anomalies.csv")
        self._lock = threading.Lock()
        self._init_headers()

    def _init_headers(self):
        with open(self._events_path, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp", "message"])
        with open(self._anomalies_path, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=self._ANOMALY_FIELDS).writeheader()

    def write_event(self, ts: str, message: str):
        with self._lock:
            with open(self._events_path, "a", newline="") as f:
                csv.writer(f).writerow([ts, message])

    def write_anomaly(self, anomaly: dict):
        ts = datetime.datetime.fromtimestamp(
            anomaly.get("timestamp", 0)
        ).strftime("%Y-%m-%d %H:%M:%S")
        row = {
            "timestamp": ts,
            "ip":        anomaly.get("ip", ""),
            "type":      anomaly.get("type", ""),
            "severity":  anomaly.get("severity", ""),
            "detail":    anomaly.get("detail", ""),
        }
        with self._lock:
            with open(self._anomalies_path, "a", newline="") as f:
                csv.DictWriter(f, fieldnames=self._ANOMALY_FIELDS).writerow(row)
