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

    It is the only writer of both files. A failed append (disk full, file removed) never raises
    into capture: it is counted per kind with the first error, and the session export reports
    the record as not written.
    """

    _ANOMALY_FIELDS = ["timestamp", "ip", "type", "severity", "detail"]

    def __init__(self, session_dir: str):
        self._events_path    = os.path.join(session_dir, "events.csv")
        self._anomalies_path = os.path.join(session_dir, "anomalies.csv")
        self._lock = threading.Lock()
        self.written = {"events": 0, "anomalies": 0}
        self.failed = {"events": 0, "anomalies": 0}
        self.first_error = {"events": "", "anomalies": ""}
        self._init_headers()

    def _init_headers(self):
        with open(self._events_path, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp", "message"])
        with open(self._anomalies_path, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=self._ANOMALY_FIELDS).writeheader()

    def _append(self, kind: str, write) -> bool:
        try:
            write()
        except (OSError, ValueError, csv.Error) as exc:
            self.failed[kind] += 1
            if not self.first_error[kind]:
                from scrutics.capture.ingest_stats import plain_text
                self.first_error[kind] = plain_text(exc)
            return False
        self.written[kind] += 1
        return True

    def write_event(self, ts: str, message: str):
        def write():
            with open(self._events_path, "a", newline="") as f:
                csv.writer(f).writerow([ts, message])
        with self._lock:
            return self._append("events", write)

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
        def write():
            with open(self._anomalies_path, "a", newline="") as f:
                csv.DictWriter(f, fieldnames=self._ANOMALY_FIELDS).writerow(row)
        with self._lock:
            return self._append("anomalies", write)
