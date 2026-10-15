"""
Writing a capture session's files, and stating what the export holds.

Two kinds of file make up a session:
- Append-only files, events.csv and anomalies.csv: RollingWriter appends each record as it happens
  and is their only writer. They are never rewritten from the in-memory display buffers, which
  keep only the most recent entries. A failed append is a lost record.
- Snapshot files, assets.csv, evidence.json, the topology files with connections.csv, and
  manifest.json: rewritten whole at every checkpoint and at the end, so a failed write is
  repaired by the next successful one.

The manifest's "records" block gives, per record kind, how many were observed, exported and
dropped, with the reasons. "export_complete" is true only in the final write, when nothing is
missing from the final files: no lost append, every snapshot file's last write succeeded and no
record was left out of its file. "export_errors" lists every write error, and a snapshot error
that a later write repaired is marked "recovered". A shortened topology view (topology.json keeps
the 2,000 busiest edges) is counted but does not make the export incomplete: connections.csv
holds every edge.
"""

import json
import os
from collections import deque

from scrutics.capture.ingest_stats import plain_text

APPEND_KINDS = ("events", "anomalies")
APPEND_FILES = {"events": "events.csv", "anomalies": "anomalies.csv"}

REASON_WRITE_ERROR = "write error"
REASON_NO_WRITER = "no session file writer"
REASON_NOT_PASSED = "not passed to the session file writer"
REASON_SHARED_IP = "another device has the same IP"


class CountingDeque(deque):
    """A bounded deque that also counts every append, including entries it no longer holds."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.appended = 0

    def append(self, item):
        self.appended += 1
        super().append(item)


class SnapshotLog:
    """Write results of the whole-file session artifacts, per file."""

    def __init__(self):
        self._files: dict = {}   # name -> {"count", "first_error", "last_ok"}

    def run(self, name: str, write) -> bool:
        try:
            write()
        except Exception as exc:
            entry = self._files.setdefault(name, {"count": 0, "first_error": plain_text(exc), "last_ok": False})
            entry["count"] += 1
            entry["last_ok"] = False
            return False
        if name in self._files:
            self._files[name]["last_ok"] = True
        return True

    def failed(self, name: str, message: str) -> None:
        entry = self._files.setdefault(name, {"count": 0, "first_error": plain_text(message), "last_ok": False})
        entry["count"] += 1
        entry["last_ok"] = False

    def errors(self) -> list:
        return [{"file": name, "count": e["count"], "first_error": e["first_error"], "recovered": e["last_ok"]}
                for name, e in sorted(self._files.items())]

    def unrecovered(self) -> list:
        return [name for name, e in sorted(self._files.items()) if not e["last_ok"]]


def _record(observed: int, exported: int, reasons: dict) -> dict:
    reasons = {r: n for r, n in reasons.items() if n}
    return {"observed": observed, "exported": exported, "dropped": observed - exported,
            "dropped_by_reason": reasons}


def _append_record(kind: str, observed: int, writer) -> dict:
    if writer is None:
        return _record(observed, 0, {REASON_NO_WRITER: observed})
    written, failed = writer.written[kind], writer.failed[kind]
    return _record(observed, written, {REASON_WRITE_ERROR: failed,
                                       REASON_NOT_PASSED: observed - written - failed})


def write_session_snapshot(session_dir: str, inventory, engine, capture_started=None, final: bool = False) -> dict:
    """
    Write the snapshot files and the manifest. Returns {"records", "export_complete",
    "export_errors", "topology_paths", "manifest_ok"}. Never raises.
    """
    from scrutics.topology import export_topology, write_manifest

    log = getattr(engine, "snapshot_log", None) if engine else None
    if log is None:
        log = SnapshotLog()
        if engine is not None:
            engine.snapshot_log = log
    writer = getattr(engine, "writer", None) if engine else None
    edges = engine.topology_edges if engine else None

    log.run("assets.csv", lambda: inventory.export_csv(os.path.join(session_dir, "assets.csv")))

    # evidence.json is keyed by IP: when two devices share an IP only one entry can be written
    evidence_data = {}
    with_evidence = 0
    for asset in inventory.get_all():
        if asset.evidence:
            with_evidence += 1
            evidence_data[asset.ip] = [ev.to_dict() for ev in asset.evidence]

    def write_evidence():
        if evidence_data:
            with open(os.path.join(session_dir, "evidence.json"), "w", encoding="utf-8") as f:
                json.dump(evidence_data, f, indent=2)
    evidence_ok = log.run("evidence.json", write_evidence)

    topology_stats: dict = {}
    topology_paths: dict = {}

    def write_topology():
        topology_paths.update(export_topology(inventory, edges, session_dir, stats=topology_stats))
    topology_ok = log.run("topology", write_topology)

    edge_count = len(edges) if edges else 0
    shared_ip = with_evidence - len(evidence_data)
    records = {
        "events": _append_record("events", engine.event_log.appended if engine else 0, writer),
        "anomalies": _append_record("anomalies", engine.baseline.anomaly_log.appended if engine else 0, writer),
        "evidence": _record(with_evidence, len(evidence_data) if evidence_ok else 0,
                            {REASON_SHARED_IP: shared_ip,
                             REASON_WRITE_ERROR: 0 if evidence_ok else len(evidence_data)}),
    }
    if topology_ok:
        connections = topology_stats.get("connections_written", 0)
        records["connections"] = _record(edge_count, connections, {})
        records["topology_edges"] = _record(edge_count, topology_stats.get("edges_exported", 0),
                                            topology_stats.get("edge_drops", {}))
    else:
        records["connections"] = _record(edge_count, 0, {REASON_WRITE_ERROR: edge_count})
        records["topology_edges"] = _record(edge_count, 0, {REASON_WRITE_ERROR: edge_count})

    export_errors = list(log.errors())
    if writer is not None:
        for kind in APPEND_KINDS:
            if writer.failed[kind]:
                export_errors.append({"file": APPEND_FILES[kind], "count": writer.failed[kind],
                                      "first_error": writer.first_error[kind], "recovered": False})
    missing = (any(records[k]["dropped"] for k in ("events", "anomalies", "evidence", "connections"))
               or bool(log.unrecovered()))
    complete = final and not missing

    manifest_errors: list = []
    write_manifest(session_dir, metadata={
        "inventory": inventory,
        "edges": edges,
        "engine": engine,
        "capture_started": capture_started,
        "records": records,
        "export_complete": complete,
        "export_errors": export_errors,
    }, errors=manifest_errors)
    manifest_ok = not manifest_errors
    if manifest_errors:
        log.failed("manifest.json", manifest_errors[0])
        complete = False
        # Not in the manifest itself (it could not be written), but returned to the caller
        export_errors = ([e for e in export_errors if e["file"] != "manifest.json"]
                         + [e for e in log.errors() if e["file"] == "manifest.json"])
    elif "manifest.json" in log.unrecovered():
        log.run("manifest.json", lambda: None)
    return {"records": records, "export_complete": complete, "export_errors": export_errors,
            "topology_paths": topology_paths, "manifest_ok": manifest_ok,
            "unrecovered": log.unrecovered()}


def export_summary_line(result) -> str:
    """One plain-text line when the final export is incomplete, else ""."""
    if not result or result.get("export_complete"):
        return ""
    parts = []
    for kind, record in result["records"].items():
        if kind == "topology_edges" or not record["dropped"]:
            continue
        reasons = ", ".join(f"{r}: {n}" for r, n in sorted(record["dropped_by_reason"].items()))
        parts.append(f"{kind} {record['observed']} observed, {record['exported']} written, "
                     f"{record['dropped']} not written ({reasons})")
    for name in result.get("unrecovered", []):
        error = next((e["first_error"] for e in result["export_errors"] if e["file"] == name), "")
        parts.append(f"{name} not written" + (f" ({error})" if error else ""))
    for error in result["export_errors"]:
        if error["file"] in APPEND_FILES.values():
            parts.append(f"first {error['file']} error: {error['first_error']}")
    if not parts:
        parts.append("the session files could not all be written")
    return "Export incomplete: " + "; ".join(parts) + "."
