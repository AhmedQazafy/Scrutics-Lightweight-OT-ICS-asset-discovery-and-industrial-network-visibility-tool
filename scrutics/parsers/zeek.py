"""Zeek log parser for Scrutics. Supports conn.log, modbus.log, dnp3.log, bacnet.log."""

import gzip
from typing import Generator

PATH = "zeek"


class ZeekFormatError(ValueError):
    """The log header cannot be used, so no line of the file can be read."""


def _open_zeek(filepath: str):
    if filepath.endswith(".gz"):
        return gzip.open(filepath, "rt", errors="ignore")
    return open(filepath, "r", errors="ignore")


def _iter_zeek_records(filepath: str, report=None) -> Generator[tuple, None, None]:
    """
    Yield (line number, record) for each usable data line.

    Each line is handled on its own: a line that cannot be used is rejected or, if it raises
    unexpectedly, contained and skipped. `report` (optional) receives reject(reason, path, line)
    and contain(exception, path, line).
    """
    with _open_zeek(filepath) as f:
        lines = f.readlines()

    meta = {"fields": [], "separator": "\t", "path": "unknown"}
    data_lines = []

    for line_no, line in enumerate(lines, start=1):
        try:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#separator"):
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    sep = parts[1].strip()
                    if not sep:
                        raise ZeekFormatError(
                            f"Zeek log header, line {line_no}: #separator is empty, "
                            "so the fields of the log cannot be split")
                    meta["separator"] = sep.replace("\\t", "\t").replace("\\x09", "\t")
            elif line.startswith("#fields"):
                meta["fields"] = line.split(meta["separator"])[1:]
            elif line.startswith("#path"):
                parts = line.split(meta["separator"])
                meta["path"] = parts[1] if len(parts) > 1 else line.split(" ", 1)[-1].strip()
            elif not line.startswith("#"):
                data_lines.append((line_no, line))
        except ZeekFormatError:
            raise
        except Exception as exc:
            if report is not None:
                report.contain(exc, PATH, line_no)

    fields = meta["fields"]
    sep    = meta["separator"]
    if not fields:
        if data_lines:
            raise ZeekFormatError(
                f"Zeek log has data (first at line {data_lines[0][0]}) but no #fields header "
                "naming its columns")
        return

    for line_no, line in data_lines:
        try:
            if not line.strip():
                continue
            values = line.split(sep)
            if len(values) != len(fields):
                if report is not None:
                    report.reject("Zeek line field count does not match #fields", PATH, line_no)
                continue
            record = dict(zip(fields, values))
            record["_path"] = meta["path"]
        except Exception as exc:
            if report is not None:
                report.contain(exc, PATH, line_no)
            continue
        yield line_no, record


def parse_zeek_log(filepath: str) -> Generator[dict, None, None]:
    for _, record in _iter_zeek_records(filepath):
        yield record


def _flow_from_record(record: dict):
    path   = record.get("_path", "")
    src_ip = record.get("id.orig_h", "-")
    dst_ip = record.get("id.resp_h", "-")
    ts     = record.get("ts", "0")
    if src_ip == "-" or dst_ip == "-":
        return None
    try:    ts_float = float(ts)
    except: ts_float = 0.0

    if path == "modbus":
        return {"src_ip": src_ip, "src_mac": None, "dst_ip": dst_ip,
                "dst_port": 502, "proto": "TCP", "timestamp": ts_float, "source": "zeek_modbus"}
    elif path == "dnp3":
        return {"src_ip": src_ip, "src_mac": None, "dst_ip": dst_ip,
                "dst_port": 20000, "proto": "TCP", "timestamp": ts_float, "source": "zeek_dnp3"}
    elif path == "bacnet":
        return {"src_ip": src_ip, "src_mac": None, "dst_ip": dst_ip,
                "dst_port": 47808, "proto": "UDP", "timestamp": ts_float, "source": "zeek_bacnet"}
    elif path == "conn":
        dst_port = record.get("id.resp_p", "-")
        proto    = record.get("proto", "tcp").upper()
        try:    dst_port_int = int(dst_port)
        except: dst_port_int = None
        return {"src_ip": src_ip, "src_mac": None, "dst_ip": dst_ip,
                "dst_port": dst_port_int, "proto": proto, "timestamp": ts_float, "source": "zeek_conn"}
    return None


def iter_zeek_flows(filepath: str, report=None) -> Generator[tuple, None, None]:
    """Yield (line number, flow) for each record that describes a flow."""
    for line_no, record in _iter_zeek_records(filepath, report):
        try:
            flow = _flow_from_record(record)
        except Exception as exc:
            if report is not None:
                report.contain(exc, PATH, line_no)
            continue
        if flow is not None:
            yield line_no, flow


def extract_flows_from_zeek(filepath: str) -> list:
    return [flow for _, flow in iter_zeek_flows(filepath)]
