"""File type detection for Scrutics file analysis mode."""

import os
import json

SUPPORTED_EXTENSIONS = {".pcap", ".pcapng", ".log", ".json"}
EXTENSION_DESCRIPTIONS = {
    ".pcap":   "PCAP packet capture",
    ".pcapng": "PCAP-NG packet capture",
    ".log":    "Zeek protocol log",
    ".json":   "Suricata EVE JSON",
}


def detect_file_type(filepath: str) -> str:
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".pcap":   return "pcap"
    if ext == ".pcapng": return "pcapng"
    if ext == ".log":    return _detect_zeek(filepath)
    if ext == ".json":   return _detect_suricata(filepath)
    return _detect_by_content(filepath)


def _detect_zeek(filepath: str) -> str:
    try:
        with open(filepath, "r", errors="ignore") as f:
            first = f.read(200)
            if "#separator" in first or "#fields" in first:
                return "zeek"
    except Exception:
        pass
    return "unknown"


def _detect_suricata(filepath: str) -> str:
    try:
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Skip comments
                if line.startswith("#"):
                    continue
                try:
                    obj = json.loads(line)
                    if "event_type" in obj or "src_ip" in obj:
                        return "suricata"
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass
    return "unknown"


def _detect_by_content(filepath: str) -> str:
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"): return "pcap"
            if magic == b"\x0a\x0d\x0d\x0a": return "pcapng"
    except Exception:
        pass
    return "unknown"
