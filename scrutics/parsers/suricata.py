"""Suricata EVE JSON parser for Scrutics."""

import json
from typing import Generator

PATH = "suricata"


def parse_eve_file(filepath: str) -> Generator[dict, None, None]:
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validation_error(event):
    """
    Why an EVE line cannot be used, or None. Types are checked, never coerced: a dest_port of
    "502", 502.0 or true is malformed, and so is one outside 0..65535. Fields that are absent keep
    today's defaults.
    """
    if not isinstance(event, dict):
        return "EVE line is not a JSON object"
    for field in ("src_ip", "dest_ip"):
        if event.get(field) is not None and not isinstance(event[field], str):
            return f"EVE field {field} is not a string"
    if event.get("dest_port") is not None and not _is_int(event["dest_port"]):
        return "EVE field dest_port is not an integer"
    if event.get("dest_port") is not None and not 0 <= event["dest_port"] <= 65535:
        return "EVE field dest_port is out of range (0-65535)"
    for field in ("proto", "event_type"):
        if field in event and not isinstance(event[field], str):
            return f"EVE field {field} is not a string"
    if "timestamp" in event:
        ts = event["timestamp"]
        if not (isinstance(ts, str) or (isinstance(ts, (int, float)) and not isinstance(ts, bool))):
            return "EVE field timestamp is neither a string nor a number"
    if event.get("event_type") == "alert" and "alert" in event:
        alert = event["alert"]
        if not isinstance(alert, dict):
            return "EVE field alert is not an object"
        if "severity" in alert and not _is_int(alert["severity"]):
            return "EVE field alert.severity is not an integer"
    return None


def _flow_from_event(event: dict):
    src_ip   = event.get("src_ip")
    dst_ip   = event.get("dest_ip")
    dst_port = event.get("dest_port")
    proto    = event.get("proto", "TCP").upper()
    ts_str   = event.get("timestamp", "")
    etype    = event.get("event_type", "")

    if not src_ip or not dst_ip:
        return None

    ts_float = 0.0
    if ts_str:
        try:
            from datetime import datetime
            ts_clean = ts_str.replace("+0000", "+00:00")
            ts_float = datetime.fromisoformat(ts_clean).timestamp()
        except Exception:
            try:    ts_float = float(ts_str)
            except: ts_float = 0.0

    flow = {"src_ip": src_ip, "src_mac": None, "dst_ip": dst_ip,
            "dst_port": dst_port, "proto": proto,
            "timestamp": ts_float, "source": f"suricata_{etype}"}

    if etype == "alert":
        alert_info = event.get("alert", {})
        flow["alert"] = {
            "signature": alert_info.get("signature", "Unknown"),
            "category":  alert_info.get("category", ""),
            "severity":  alert_info.get("severity", 3),
            "action":    alert_info.get("action", "allowed"),
        }
    if etype == "modbus": flow["dst_port"] = 502;   flow["source"] = "suricata_modbus"
    elif etype == "dnp3": flow["dst_port"] = 20000; flow["source"] = "suricata_dnp3"
    elif etype == "enip": flow["dst_port"] = 44818; flow["source"] = "suricata_enip"
    return flow


def iter_eve_flows(filepath: str, report=None) -> Generator[tuple, None, None]:
    """
    Yield (line number, flow) for each EVE line that describes a flow.

    Each line is handled on its own: a line that cannot be used is rejected or, if it raises
    unexpectedly, contained and skipped. `report` (optional) receives reject(reason, path, line)
    and contain(exception, path, line).
    """
    with open(filepath, "r", errors="ignore") as f:
        for line_no, line in enumerate(f, start=1):
            try:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    if report is not None:
                        report.reject("EVE line is not valid JSON", PATH, line_no)
                    continue
                problem = _validation_error(event)
                if problem:
                    if report is not None:
                        report.reject(problem, PATH, line_no)
                    continue
                flow = _flow_from_event(event)
            except Exception as exc:
                if report is not None:
                    report.contain(exc, PATH, line_no)
                continue
            if flow is not None:
                yield line_no, flow


def extract_flows_from_eve(filepath: str) -> list:
    return [flow for _, flow in iter_eve_flows(filepath)]
