"""
Semantic Tool API for Scrutics Evidence Packages.
Provides safe, read-only, structured evidence inspection for LLMs.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Any

from scrutics.db.inventory import split_conflicts
from scrutics.protocol_display import split_display_column
from scrutics.vendor_display import display_vendor_name, ot_service_observed, vendor_note_for
from scrutics.topology import read_manifest
from scrutics.csv_input import allow_large_fields

# Load status of one session file
LOAD_OK = "ok"
LOAD_PARTIAL = "partial"          # reading stopped part way; later rows were not loaded
LOAD_UNREADABLE = "unreadable"    # nothing could be read
LOAD_MISSING = "missing"          # named by the manifest but absent


def _saved_ports(text) -> list:
    """Ports from a saved "ports_seen" cell ("502|80"); anything that is not a number is skipped."""
    parts = (part.strip() for part in str(text or "").split("|"))
    return [int(part) for part in parts if part.isascii() and part.isdigit()]


class SessionContext:
    """
    Holds in-memory parsed session data for one evidence package.
    Caches parsed CSVs and JSON evidence to avoid disk I/O on repeated tool invocations.
    """

    def __init__(self, session_dir: str):
        self.session_dir = session_dir
        # One entry per session file read: what was loaded and what was not, and why
        self.load_report: list[dict[str, Any]] = []
        try:
            self.manifest = read_manifest(session_dir)
        except FileNotFoundError as e:
            # Check if this is an active or brand new session that was interrupted before the first checkpoint
            assets_exist = os.path.exists(os.path.join(session_dir, "assets.csv"))
            if assets_exist:
                raise FileNotFoundError(
                    f"manifest.json not found in '{session_dir}'. "
                    "This session may have been interrupted before its first checkpoint was written "
                    "(let live captures run for at least 15 seconds to ensure manifest and checkpoints are saved), "
                    "or it is an older legacy capture session missing manifest metadata."
                ) from e
            raise

        # Standard file mappings from manifest or defaults
        files_map = self.manifest.get("files", {})
        assets_filename = files_map.get("assets", "assets.csv")
        evidence_filename = files_map.get("evidence", "evidence.json")
        connections_filename = files_map.get("connections", "connections.csv")
        anomalies_filename = files_map.get("anomalies", "anomalies.csv")

        self._named_files = {name for name in files_map.values() if isinstance(name, str)}

        self.assets = self._load_assets(os.path.join(session_dir, assets_filename))
        self.evidence = self._load_evidence(os.path.join(session_dir, evidence_filename))
        self.connections = self._load_connections(os.path.join(session_dir, connections_filename))
        self.anomalies = self._load_anomalies(os.path.join(session_dir, anomalies_filename))

    @property
    def load_issues(self) -> list[dict[str, Any]]:
        """Report entries for files that were not loaded completely."""
        return [entry for entry in getattr(self, "load_report", [])
                if entry["status"] != LOAD_OK or entry["rows_not_loaded"]]

    def _record(self, filepath: str, status: str, rows_loaded: int, rows_not_loaded: int | None,
                reason: str = "") -> None:
        # A context whose loaders are called without __init__ starts its report here
        self.__dict__.setdefault("load_report", []).append({
            "file": os.path.basename(filepath),
            "status": status,
            "rows_loaded": rows_loaded,
            # None: reading stopped, so the number of rows after that point is unknown
            "rows_not_loaded": rows_not_loaded,
            "reason": reason,
        })

    def _file_present(self, filepath: str) -> bool:
        """True if the file exists. A file the manifest names but that is absent is recorded as missing;
        older sessions leave out files the manifest does not name, so those stay silent."""
        if os.path.exists(filepath):
            return True
        if os.path.basename(filepath) in getattr(self, "_named_files", ()):
            self._record(filepath, LOAD_MISSING, 0, None, "listed in manifest.json but not found")
        return False

    def _read_csv(self, filepath: str, convert) -> list[dict[str, Any]]:
        """Read a session CSV row by row. A row that cannot be converted is counted and skipped; a
        malformed or undecodable file stops at that point and the rows read so far are kept."""
        if not self._file_present(filepath):
            return []
        rows: list[dict[str, Any]] = []
        skipped = 0
        first_skip = ""
        allow_large_fields()
        try:
            with open(filepath, "r", encoding="utf-8", newline="") as f:
                for row in csv.DictReader(f):
                    try:
                        rows.append(convert(row))
                    except Exception as e:
                        skipped += 1
                        if not first_skip:
                            first_skip = f"row {len(rows) + skipped}: {type(e).__name__}: {e}"
        except (csv.Error, UnicodeDecodeError) as e:
            row_number = len(rows) + skipped + 1
            reason = f"reading stopped at row {row_number}: {type(e).__name__}: {e}"
            status = LOAD_PARTIAL if rows or skipped else LOAD_UNREADABLE
            self._record(filepath, status, len(rows), None, reason)
            return rows
        except OSError as e:
            self._record(filepath, LOAD_UNREADABLE, 0, None, f"{type(e).__name__}: {e}")
            return []
        self._record(filepath, LOAD_OK, len(rows), skipped,
                     f"{skipped} row(s) could not be read, first at {first_skip}" if skipped else "")
        return rows

    def _load_assets(self, filepath: str) -> list[dict[str, Any]]:
        """Load assets.csv into standardized asset dictionaries."""
        def convert(row: dict[str, Any]) -> dict[str, Any]:
            protocols_raw = row.get("protocol", "")
            protocols = [p.strip() for p in protocols_raw.split(",") if p.strip()] if protocols_raw else []
            # Sessions written before the protocol_display column show served protocols
            if "protocol_display" in row:
                protocol_display = split_display_column(row.get("protocol_display"))
            else:
                protocol_display = [p for p in protocols if p != "Unknown"]

            # Parse confidence percentage
            try:
                conf_pct = int(row.get("confidence_pct", 0))
            except (ValueError, TypeError):
                conf_pct = 0

            asset_type = row.get("type", "Unknown")
            if asset_type not in ("OT", "IT"):
                asset_type = "Unknown"

            return {
                "ip": row.get("ip", ""),
                "mac": row.get("mac", ""),
                "vendor": row.get("vendor", "Unknown"),
                "role": row.get("role", "Unclassified"),
                "type": asset_type,
                "confidence_pct": conf_pct,
                "protocols": protocols,
                "protocol_display": protocol_display,
                # Sessions written before the vendor_note column: derived from the stored values
                "vendor_note": (row.get("vendor_note") or "") if "vendor_note" in row else
                               vendor_note_for(row.get("vendor_class"), row.get("classification_type"),
                                               ot_service_observed(_saved_ports(row.get("ports_seen")))),
                "classification_reason": row.get("classification_reason", "") or "",
                "classification_conflicts": split_conflicts(row.get("classification_conflicts", "")),
                "_raw": row,
            }

        return self._read_csv(filepath, convert)

    def _load_evidence(self, filepath: str) -> dict[str, list[dict[str, Any]]]:
        """Load evidence.json mapped by asset IP."""
        if not self._file_present(filepath):
            return {}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
            self._record(filepath, LOAD_UNREADABLE, 0, None, f"{type(e).__name__}: {e}")
            return {}
        if not isinstance(data, dict):
            self._record(filepath, LOAD_UNREADABLE, 0, None,
                         f"expected a JSON object, found {type(data).__name__}")
            return {}
        self._record(filepath, LOAD_OK, len(data), 0)
        return data

    def _load_connections(self, filepath: str) -> list[dict[str, Any]]:
        """Load connections.csv into connection dictionaries."""
        def convert(row: dict[str, Any]) -> dict[str, Any]:
            try:
                count = int(row.get("count", 1))
            except (ValueError, TypeError):
                count = 1
            return {
                "source": row.get("source", ""),
                "destination": row.get("destination", ""),
                "protocol": row.get("protocol", "Unknown"),
                "count": count,
            }

        return self._read_csv(filepath, convert)

    def _load_anomalies(self, filepath: str) -> list[dict[str, Any]]:
        """Load anomalies.csv into anomaly dictionaries."""
        def convert(row: dict[str, Any]) -> dict[str, Any]:
            return {
                "timestamp": row.get("timestamp", ""),
                "ip": row.get("ip", ""),
                "severity": row.get("severity", "LOW").upper(),
                "type": row.get("type", "UNKNOWN"),
                "detail": row.get("detail", ""),
            }

        return self._read_csv(filepath, convert)


def describe_load_issue(entry: dict[str, Any]) -> str:
    """One line for the user about a session file that was not loaded completely."""
    name, status, reason = entry["file"], entry["status"], entry["reason"]
    if status == LOAD_MISSING:
        return f"{name}: {reason}"
    if status == LOAD_UNREADABLE:
        return f"{name}: not loaded ({reason})"
    if status == LOAD_PARTIAL:
        return f"{name}: {entry['rows_loaded']} row(s) loaded, the rest not loaded ({reason})"
    return f"{name}: {entry['rows_not_loaded']} row(s) not loaded ({reason})"


# ── The 5 Semantic Tools ───────────────────────────────────────────────────────

def get_statistics(ctx: SessionContext) -> dict[str, Any]:
    """
    Return aggregate session statistics.
    Uses manifest stats if present and non-zero; otherwise computes fresh from loaded data.
    When a session file was not loaded completely, or a count loaded differs from the manifest,
    the result also gives the loaded counts and the files that were not fully loaded.
    """
    manifest_stats = ctx.manifest.get("stats", {})

    ot_fresh = sum(1 for a in ctx.assets if a.get("type") == "OT")
    it_fresh = sum(1 for a in ctx.assets if a.get("type") == "IT")
    unknown_fresh = sum(1 for a in ctx.assets if a.get("type") not in ("OT", "IT"))

    asset_count = int(manifest_stats.get("asset_count", 0)) or len(ctx.assets)
    ot_count = int(manifest_stats.get("ot_count", 0)) or ot_fresh
    it_count = int(manifest_stats.get("it_count", 0)) or it_fresh
    unknown_count = int(manifest_stats.get("unknown_count", 0)) or unknown_fresh
    connection_count = int(manifest_stats.get("connection_count", 0)) or len(ctx.connections)
    anomaly_count = int(manifest_stats.get("anomaly_count", 0)) or len(ctx.anomalies)

    stats: dict[str, Any] = {
        "asset_count": asset_count,
        "ot_count": ot_count,
        "it_count": it_count,
        "unknown_count": unknown_count,
        "connection_count": connection_count,
        "anomaly_count": anomaly_count,
    }

    loaded = {
        "asset_count": len(ctx.assets),
        "connection_count": len(ctx.connections),
        "anomaly_count": len(ctx.anomalies),
    }
    issues = ctx.load_issues
    if issues or any(stats[name] != count for name, count in loaded.items()):
        stats["loaded"] = loaded
        stats["load_issues"] = [
            {key: entry[key] for key in ("file", "status", "rows_loaded", "rows_not_loaded", "reason")}
            for entry in issues
        ]
    return stats


def get_assets(
    ctx: SessionContext,
    asset_type: str | None = None,
    min_confidence: int | None = None,
    max_results: int = 100,
) -> list[dict[str, Any]] | dict[str, Any]:
    """
    Return a list of asset summaries matching optional filters.
    Results exceeding max_results are truncated with a descriptive wrapping dict.
    """
    results = []
    target_type = asset_type.strip().upper() if asset_type else None

    for a in ctx.assets:
        if target_type and a.get("type", "").upper() != target_type:
            continue
        if min_confidence is not None and a.get("confidence_pct", 0) < min_confidence:
            continue

        results.append({
            "ip": a["ip"],
            "mac": a["mac"],
            "vendor": display_vendor_name(a["vendor"]),
            "vendor_note": a.get("vendor_note", ""),
            "role": a["role"],
            "type": a["type"],
            "confidence_pct": a["confidence_pct"],
            "protocols": a["protocols"],
            "protocol_display": a.get("protocol_display", a["protocols"]),
        })

    if len(results) > max_results:
        return {
            "assets": results[:max_results],
            "truncated": True,
            "total_count": len(results),
        }
    return results


def get_asset(ctx: SessionContext, ip: str) -> dict[str, Any]:
    """
    Return full details for a single asset by IP.
    Returns an error dictionary if not found (never raises).
    """
    target_ip = str(ip).strip()
    for a in ctx.assets:
        if a.get("ip") == target_ip:
            detail = dict(a.get("_raw", {}))
            detail["vendor"] = display_vendor_name(a.get("vendor", "Unknown"))
            detail["vendor_note"] = a.get("vendor_note", "")
            detail["classification_reason"] = a.get("classification_reason", "")
            detail["classification_conflicts"] = list(a.get("classification_conflicts", []))
            detail["evidence"] = ctx.evidence.get(target_ip, [])
            return detail

    return {"error": f"no asset found for ip {target_ip}"}


def get_connections(
    ctx: SessionContext,
    ip: str | None = None,
    protocol: str | None = None,
    max_results: int = 100,
) -> list[dict[str, Any]] | dict[str, Any]:
    """
    Return network connections filtered by IP (source or destination) and/or protocol.
    Results exceeding max_results are truncated with a descriptive wrapping dict.
    """
    results = []
    target_ip = ip.strip() if ip else None
    target_proto = protocol.strip().lower() if protocol else None

    for c in ctx.connections:
        if target_ip and (c.get("source") != target_ip and c.get("destination") != target_ip):
            continue
        if target_proto and c.get("protocol", "").lower() != target_proto:
            continue
        results.append(c)

    if len(results) > max_results:
        return {
            "connections": results[:max_results],
            "truncated": True,
            "total_count": len(results),
        }
    return {"connections": results, "truncated": False, "total_count": len(results)}


def get_anomalies(
    ctx: SessionContext,
    severity: str | None = None,
) -> list[dict[str, Any]]:
    """
    Return behavioral anomalies, optionally filtered by severity (HIGH, MEDIUM, LOW).
    """
    target_sev = severity.strip().upper() if severity else None
    if not target_sev:
        return {"anomalies": list(ctx.anomalies), "total_count": len(ctx.anomalies)}

    results = [anom for anom in ctx.anomalies if anom.get("severity", "").upper() == target_sev]
    return {"anomalies": results, "total_count": len(results)}


# ── OpenAI-Compatible Tool Definitions ─────────────────────────────────────────

def get_tool_definitions() -> list[dict[str, Any]]:
    """
    Return OpenAI-compatible tool definitions for passing to LLMProvider.chat().
    """
    return [
        {
            "type": "function",
            "function": {
                "name": "get_statistics",
                "description": (
                    "Retrieve high-level asset, connection, and anomaly count statistics "
                    "for the captured OT/ICS network session. If some session data could not be "
                    "loaded, the result also has 'loaded' (the counts actually available to the "
                    "other tools) and 'load_issues' (each file not fully loaded and why); the other "
                    "tools then see only the loaded part, so say so in the answer."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_assets",
                "description": (
                    "List discovered network assets with summary details. "
                    "Can filter by asset type ('OT', 'IT', 'Unknown') and minimum confidence percentage."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "asset_type": {
                            "type": "string",
                            "enum": ["OT", "IT", "Unknown"],
                            "description": "Filter assets by classification type.",
                        },
                        "min_confidence": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 100,
                            "description": "Only return assets with confidence percentage >= min_confidence.",
                        },
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_asset",
                "description": (
                    "Look up comprehensive details for a specific device by its IP address, "
                    "including full evidence list, MAC vendor, and observed services."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "IPv4 address of the target asset (e.g. '192.168.100.10').",
                        },
                    },
                    "required": ["ip"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_connections",
                "description": (
                    "Query observed network communication flows between devices, "
                    "optionally filtered by IP address and/or protocol."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "Filter for connections where this IP is either source or destination.",
                        },
                        "protocol": {
                            "type": "string",
                            "description": "Filter by ICS/IT protocol name (e.g. 'Modbus TCP', 'S7comm', 'EtherNet/IP').",
                        },
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_anomalies",
                "description": (
                    "List behavioral anomalies detected during the session (e.g. new peer violations, "
                    "directionality changes, interval anomalies). Can filter by severity."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["HIGH", "MEDIUM", "LOW"],
                            "description": "Filter anomalies by severity level.",
                        },
                    },
                    "required": [],
                },
            },
        },
    ]
