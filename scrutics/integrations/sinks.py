"""
SIEM output sinks for Scrutics.
Supports: syslog over UDP/TCP (JSON, CEF, LEEF, plain) and Splunk HEC.
Multiple sinks can be active simultaneously via SinkManager.
"""

import datetime
import json
import queue
import socket
import ssl
import threading
import urllib.request
import urllib.error

# RFC 3164 syslog priorities: facility=1 (user-level messages)
_SEV_PRIORITY = {
    "HIGH":   11,   # facility=1, severity=3 (error)
    "MEDIUM": 12,   # facility=1, severity=4 (warning)
    "LOW":    13,   # facility=1, severity=5 (notice)
}
_SEV_CEF  = {"HIGH": 7, "MEDIUM": 5, "LOW": 3}
_HOSTNAME = socket.gethostname()
_PROGRAM  = "scrutics"


# ── Formatters ─────────────────────────────────────────────────────────────────

def _syslog_ts() -> str:
    return datetime.datetime.now().strftime("%b %d %H:%M:%S")


def format_json(anomaly: dict) -> str:
    sev  = anomaly.get("severity", "LOW")
    pri  = _SEV_PRIORITY.get(sev, 13)
    payload = {
        "timestamp":  datetime.datetime.fromtimestamp(
            anomaly.get("timestamp", 0)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "program":    _PROGRAM,
        "event_type": "anomaly",
        "ip":         anomaly.get("ip", ""),
        "type":       anomaly.get("type", ""),
        "severity":   sev,
        "detail":     anomaly.get("detail", ""),
    }
    return f"<{pri}>{_syslog_ts()} {_HOSTNAME} {_PROGRAM}: {json.dumps(payload)}"


def format_cef(anomaly: dict) -> str:
    sev    = anomaly.get("severity", "LOW")
    pri    = _SEV_PRIORITY.get(sev, 13)
    cef_sv = _SEV_CEF.get(sev, 3)
    atype  = anomaly.get("type", "UNKNOWN").replace("|", "/")
    detail = anomaly.get("detail", "").replace("\\", "\\\\").replace("\n", "\\n")
    ip     = anomaly.get("ip", "")
    rt     = int(anomaly.get("timestamp", 0)) * 1000
    msg = (
        f"CEF:0|Scrutics|Scrutics|v0.4|{atype}|{atype}|{cef_sv}|"
        f"src={ip} rt={rt} msg={detail}"
    )
    return f"<{pri}>{_syslog_ts()} {_HOSTNAME} {_PROGRAM}: {msg}"


def format_leef(anomaly: dict) -> str:
    sev    = anomaly.get("severity", "LOW")
    pri    = _SEV_PRIORITY.get(sev, 13)
    atype  = anomaly.get("type", "UNKNOWN")
    ip     = anomaly.get("ip", "")
    detail = anomaly.get("detail", "").replace("\t", " ")
    rt     = int(anomaly.get("timestamp", 0)) * 1000
    msg = (
        f"LEEF:1.0|Scrutics|Scrutics|v0.4|{atype}|"
        f"src={ip}\tsev={sev}\tdetail={detail}\trt={rt}"
    )
    return f"<{pri}>{_syslog_ts()} {_HOSTNAME} {_PROGRAM}: {msg}"


def format_plain(anomaly: dict) -> str:
    sev    = anomaly.get("severity", "LOW")
    pri    = _SEV_PRIORITY.get(sev, 13)
    ip     = anomaly.get("ip", "")
    atype  = anomaly.get("type", "")
    detail = anomaly.get("detail", "")
    msg = f"ip={ip} type={atype} severity={sev} detail={detail}"
    return f"<{pri}>{_syslog_ts()} {_HOSTNAME} {_PROGRAM}: {msg}"


_FORMATTERS = {
    "json":  format_json,
    "cef":   format_cef,
    "leef":  format_leef,
    "plain": format_plain,
}


# ── Sink classes ───────────────────────────────────────────────────────────────

class SyslogSink:
    """
    Syslog sink over UDP or TCP.
    Connects lazily on first emit. Reconnects on TCP failure.
    """

    def __init__(self, host: str, port: int, protocol: str, format: str):
        self._host      = host
        self._port      = port
        self._use_tcp   = protocol.lower() == "tcp"
        self._formatter = _FORMATTERS.get(format.lower(), format_json)
        self._sock      = None
        self._lock      = threading.Lock()

    def _connect(self):
        if self._use_tcp:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self._host, self._port))
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock = s

    def emit(self, anomaly: dict):
        msg = (self._formatter(anomaly) + "\n").encode("utf-8")
        with self._lock:
            for attempt in range(2):
                try:
                    if self._sock is None:
                        self._connect()
                    if self._use_tcp:
                        self._sock.sendall(msg)
                    else:
                        self._sock.sendto(msg, (self._host, self._port))
                    return
                except Exception:
                    self._sock = None
                    if attempt == 1:
                        raise

    def close(self):
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

    def __repr__(self):
        proto = "TCP" if self._use_tcp else "UDP"
        fmt = next((k for k, v in _FORMATTERS.items() if v is self._formatter), "json")
        return f"SyslogSink({proto} {self._host}:{self._port} fmt={fmt})"


class SplunkHECSink:
    """
    Splunk HTTP Event Collector sink.
    Sends anomaly events as JSON to a Splunk HEC endpoint.
    Uses only stdlib (no requests dependency).
    """

    def __init__(self, url: str, token: str, verify_ssl: bool = True, index: str = None):
        self._url       = url.rstrip("/") + "/services/collector/event"
        self._token     = token
        self._verify_ssl = verify_ssl
        self._index     = index

    def emit(self, anomaly: dict):
        event = {
            "ip":       anomaly.get("ip", ""),
            "type":     anomaly.get("type", ""),
            "severity": anomaly.get("severity", ""),
            "detail":   anomaly.get("detail", ""),
        }
        payload = {
            "time":       anomaly.get("timestamp", 0),
            "sourcetype": "scrutics:anomaly",
            "event":      event,
        }
        if self._index:
            payload["index"] = self._index

        body = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            self._url,
            data=body,
            headers={
                "Authorization": f"Splunk {self._token}",
                "Content-Type":  "application/json",
            },
            method="POST",
        )
        ctx = (ssl.create_default_context() if self._verify_ssl
               else ssl._create_unverified_context())
        with urllib.request.urlopen(req, context=ctx, timeout=5):
            pass

    def close(self):
        pass  # stateless HTTP

    def __repr__(self):
        return f"SplunkHECSink({self._url})"


# ── Manager ────────────────────────────────────────────────────────────────────

class SinkManager:
    """
    Manages multiple output sinks.
    Fan-out: one anomaly event emitted to all configured sinks.
    A failed sink never interrupts capture or other sinks.
    """

    def __init__(self, sinks_config: list = None, queue_size: int = 1000):
        self._sinks: list = []
        self._lock  = threading.Lock()
        self._queue = queue.Queue(maxsize=queue_size)
        self._closed = threading.Event()
        self._worker = threading.Thread(target=self._run, daemon=True)
        if sinks_config:
            self._load(sinks_config)
        self._worker.start()

    def _build(self, cfg: dict):
        kind = cfg.get("type", "").lower()
        if kind == "syslog":
            return SyslogSink(
                host=cfg.get("host", "127.0.0.1"),
                port=int(cfg.get("port", 514)),
                protocol=cfg.get("protocol", "udp"),
                format=cfg.get("format", "json"),
            )
        if kind == "splunk_hec":
            return SplunkHECSink(
                url=cfg["url"],
                token=cfg["token"],
                verify_ssl=cfg.get("verify_ssl", True),
                index=cfg.get("index"),
            )
        raise ValueError(f"Unknown sink type: {cfg.get('type')!r}")

    def _load(self, sinks_config: list) -> list:
        errors = []
        new_sinks = []
        for cfg in sinks_config:
            try:
                new_sinks.append(self._build(cfg))
            except Exception as e:
                errors.append(f"{cfg.get('type', '?')}: {e}")
        self._sinks = new_sinks
        return errors

    def reload(self, sinks_config: list) -> list:
        """Replace all sinks from new config. Returns list of error strings."""
        with self._lock:
            for s in self._sinks:
                try:
                    s.close()
                except Exception:
                    pass
            self._sinks = []
            return self._load(sinks_config)

    def emit_anomaly(self, anomaly: dict):
        """Queue anomaly delivery without blocking packet capture."""
        if self._closed.is_set():
            return
        try:
            self._queue.put_nowait(dict(anomaly))
        except queue.Full:
            pass

    def _run(self):
        while True:
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                break
            self._emit_now(item)
            self._queue.task_done()

    def _emit_now(self, anomaly: dict):
        with self._lock:
            sinks = list(self._sinks)
        for sink in sinks:
            try:
                sink.emit(anomaly)
            except Exception:
                pass  # never let a sink crash the capture

    def close(self):
        self._closed.set()
        try:
            self._queue.put(None, timeout=1)
        except queue.Full:
            pass
        if self._worker.is_alive():
            self._worker.join(timeout=2)
        with self._lock:
            for s in self._sinks:
                try:
                    s.close()
                except Exception:
                    pass
            self._sinks = []

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._sinks)

    def __repr__(self):
        return f"SinkManager({self._sinks!r})"
