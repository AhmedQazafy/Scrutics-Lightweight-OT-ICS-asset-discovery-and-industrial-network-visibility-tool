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
from scrutics.topology import read_manifest


class SessionContext:
    """
    Holds in-memory parsed session data for one evidence package.
    Caches parsed CSVs and JSON evidence to avoid disk I/O on repeated tool invocations.
    """

    def __init__(self, session_dir: str):
        self.session_dir = session_dir
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

        self.assets = self._load_assets(os.path.join(session_dir, assets_filename))
        self.evidence = self._load_evidence(os.path.join(session_dir, evidence_filename))
        self.connections = self._load_connections(os.path.join(session_dir, connections_filename))
        self.anomalies = self._load_anomalies(os.path.join(session_dir, anomalies_filename))

    def _load_assets(self, filepath: str) -> list[dict[str, Any]]:
        """Load assets.csv into standardized asset dictionaries."""
        if not os.path.exists(filepath):
            return []
        assets = []
        try:
            with open(filepath, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    protocols_raw = row.get("protocol", "")
                    protocols = [p.strip() for p in protocols_raw.split(",") if p.strip()] if protocols_raw else []

                    # Parse confidence percentage
                    try:
                        conf_pct = int(row.get("confidence_pct", 0))
                    except (ValueError, TypeError):
                        conf_pct = 0

                    asset_type = row.get("type", "Unknown")
                    if asset_type not in ("OT", "IT"):
                        asset_type = "Unknown"

                    assets.append({
                        "ip": row.get("ip", ""),
                        "mac": row.get("mac", ""),
                        "vendor": row.get("vendor", "Unknown"),
                        "role": row.get("role", "Unclassified"),
                        "type": asset_type,
                        "confidence_pct": conf_pct,
                        "protocols": protocols,
                        "classification_reason": row.get("classification_reason", "") or "",
                        "classification_conflicts": split_conflicts(row.get("classification_conflicts", "")),
                        "_raw": row,
                    })
        except Exception:
            pass
        return assets

    def _load_evidence(self, filepath: str) -> dict[str, list[dict[str, Any]]]:
        """Load evidence.json mapped by asset IP."""
        if not os.path.exists(filepath):
            return {}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {}

    def _load_connections(self, filepath: str) -> list[dict[str, Any]]:
        """Load connections.csv into connection dictionaries."""
        if not os.path.exists(filepath):
            return []
        connections = []
        try:
            with open(filepath, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        count = int(row.get("count", 1))
                    except (ValueError, TypeError):
                        count = 1
                    connections.append({
                        "source": row.get("source", ""),
                        "destination": row.get("destination", ""),
                        "protocol": row.get("protocol", "Unknown"),
                        "count": count,
                    })
        except Exception:
            pass
        return connections

    def _load_anomalies(self, filepath: str) -> list[dict[str, Any]]:
        """Load anomalies.csv into anomaly dictionaries."""
        if not os.path.exists(filepath):
            return []
        anomalies = []
        try:
            with open(filepath, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    anomalies.append({
                        "timestamp": row.get("timestamp", ""),
                        "ip": row.get("ip", ""),
                        "severity": row.get("severity", "LOW").upper(),
                        "type": row.get("type", "UNKNOWN"),
                        "detail": row.get("detail", ""),
                    })
        except Exception:
            pass
        return anomalies


# ── The 5 Semantic Tools ───────────────────────────────────────────────────────

def get_statistics(ctx: SessionContext) -> dict[str, int]:
    """
    Return aggregate session statistics.
    Uses manifest stats if present and non-zero; otherwise computes fresh from loaded data.
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

    return {
        "asset_count": asset_count,
        "ot_count": ot_count,
        "it_count": it_count,
        "unknown_count": unknown_count,
        "connection_count": connection_count,
        "anomaly_count": anomaly_count,
    }


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
            "vendor": a["vendor"],
            "role": a["role"],
            "type": a["type"],
            "confidence_pct": a["confidence_pct"],
            "protocols": a["protocols"],
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
                    "for the captured OT/ICS network session."
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
