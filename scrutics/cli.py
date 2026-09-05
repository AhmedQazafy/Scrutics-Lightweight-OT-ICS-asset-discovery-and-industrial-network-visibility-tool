"""
Scrutics CLI — headless and scriptable interface.

Examples:
  scrutics                                         # launch TUI (recommended)
  scrutics --live eth0                             # TUI with interface pre-loaded
  scrutics --live eth0 --headless                  # headless live capture
  scrutics --live eth0 --duration 0 --headless     # infinite until Ctrl+C
  scrutics --file capture.pcap                     # analyze PCAP file
  scrutics --file big.pcap --no-baseline           # fast inventory, no anomaly detection
  scrutics --file eve.json --headless              # analyze Suricata EVE log
  scrutics doctor                                  # print diagnostic info

Rule reload:
  Edit scrutics/config/custom_rules.yaml while running — Scrutics detects
  the change and reloads automatically within 2-3 seconds.
  Press R in the TUI for an immediate manual reload.
  On Linux, SIGHUP is also available for headless workflows.

Background processes:
  Do NOT use & (background) with --duration 0. Ctrl+C on a backgrounded
  process sends SIGINT to the shell, not to Scrutics. assets.csv will not
  be saved. Use SIGTERM or bring the process to the foreground first.
"""

import argparse
import itertools
import sys
import os
import signal
import datetime
import threading
import time
import json
import csv

from scrutics.diagnostics import (
    VERSION, check_dependencies, full_report,
    list_interfaces, suggest_interface, check_output_dir,
)
from scrutics.db.inventory import AssetInventory
from scrutics.topology import export_topology

SESSION_FLUSH_INTERVAL = 15.0


# ── Argument parser ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scrutics",
        description="Scrutics — Passive OT/ICS Network Asset Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  scrutics                              launch TUI (recommended for first use)
  scrutics --live eth0                  TUI with interface pre-loaded
  scrutics --live eth0 --headless       headless live capture, 60s
  scrutics --live eth0 --duration 0 --headless
                                        headless infinite capture (Ctrl+C to stop)
  scrutics --file capture.pcap          TUI file analysis
  scrutics --file capture.pcap --headless --no-baseline
                                        fast headless inventory, no anomaly detection
  scrutics doctor                       print diagnostics for bug reports

output files (written to output/scrutics_TIMESTAMP/):
  assets.csv    full asset inventory   — written on session end
  events.csv    classification log     — written continuously
  anomalies.csv behavioral anomalies   — written continuously

config:
  edit scrutics/config/custom_rules.yaml to add custom rules and SIEM sinks
  run 'scrutics doctor' to verify config is loaded correctly
        """
    )

    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser(
        "doctor",
        help="print diagnostic information for bug reports and troubleshooting",
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", metavar="INTERFACE",
                      help="network interface to capture on (e.g. eth0, br-abc123)")
    mode.add_argument("--file", metavar="FILEPATH",
                      help="file to analyze (.pcap, .pcapng, .log, .json)")
    parser.add_argument("--duration", type=int, default=60, metavar="SECONDS",
                        help="capture duration. 0 = run until Ctrl+C (default: 60)")
    parser.add_argument("--baseline", type=int, default=60, metavar="SECONDS",
                        help="baseline observation window in seconds (default: 60)")
    parser.add_argument("--output", default="output", metavar="DIR",
                        help="output directory (default: ./output)")
    parser.add_argument("--headless", action="store_true",
                        help="run without TUI — results printed to console")
    parser.add_argument("--no-baseline", action="store_true", dest="no_baseline",
                        help="skip anomaly detection — inventory only. "
                             "recommended for large PCAP files")
    parser.add_argument("--version", action="version", version=f"Scrutics {VERSION}")
    return parser


# ── scrutics doctor ────────────────────────────────────────────────────────────

def run_doctor(output_dir: str = "output"):
    """Print full diagnostic report. Paste the output in GitHub issues."""
    report = full_report(headless=True, output_dir=output_dir)
    w = 56

    print(f"\n  Scrutics doctor — {report['version']}")
    print(f"  {'─' * w}")
    print(f"  Python    {report['python']}")
    print(f"  Platform  {report['platform']}")
    print()

    print(f"  Dependencies")
    for dep in report["deps"]:
        status = "✓" if dep["ok"] else "✗"
        ver    = dep["version"] or "missing"
        print(f"  {status}  {dep['name']:<12} {ver}")
        if not dep["ok"]:
            print(f"       install: {dep['install_cmd']}")

    lp = report["libpcap"]
    status = "✓" if lp["ok"] else "✗"
    print(f"  {status}  {'libpcap':<12} {lp['detail']}")
    if not lp["ok"] and "fix" in lp:
        print(f"       fix: {lp['fix']}")

    print()
    cfg = report["config"]
    print(f"  Configuration")
    if cfg["error"]:
        print(f"  ✗  error: {cfg['error']}")
    else:
        if cfg["using_default"]:
            if cfg["user_rules"] == 0:
                label = "scrutics/config/custom_rules.yaml  (default — no custom rules yet)"
            else:
                n = cfg["user_rules"]
                label = f"scrutics/config/custom_rules.yaml  ({n} custom rule{'s' if n != 1 else ''} active)"
        else:
            label = cfg["path"]
        print(f"  ✓  config:        {label}")
        print(f"     built-in rules: {cfg['builtin_rules']}")
        if not cfg["using_default"] or cfg["user_rules"] > 0:
            print(f"     custom rules:   {cfg['user_rules']}")
        sinks = cfg["sinks"]
        if sinks:
            print(f"     sinks:          {sinks} ({', '.join(cfg['sink_types'])})")
        else:
            print(f"     sinks:          none configured")

    print()
    out = report["output_dir"]
    status = "✓" if out["ok"] else "✗"
    print(f"  Output directory")
    print(f"  {status}  {out['path']}  ({out['detail']})")

    print()
    ifaces = report["interfaces"]
    print(f"  Network interfaces ({len(ifaces)} found)")
    for iface in ifaces[:12]:
        desc = f"  — {iface['description']}" if iface["description"] else ""
        print(f"     {iface['name']}{desc}")
    if len(ifaces) > 12:
        print(f"     ... and {len(ifaces) - 12} more")

    print(f"\n  {'─' * w}")
    all_ok = (
        all(d["ok"] for d in report["deps"])
        and report["libpcap"]["ok"]
        and not cfg.get("error")
        and out["ok"]
    )
    if all_ok:
        print("  ✓  Everything looks good.\n")
    else:
        print("  ✗  Some issues found above. Fix them before running Scrutics.\n")

    return 0 if all_ok else 1


# ── Interface error helper ─────────────────────────────────────────────────────

def _interface_error(interface: str):
    """Print a helpful error when the requested interface is not found."""
    ifaces = list_interfaces()
    print(f"\n[!] Interface not found: {interface}")
    if ifaces:
        print("    Available interfaces:")
        for iface in ifaces:
            desc = f"  — {iface['description']}" if iface["description"] else ""
            print(f"      {iface['name']}{desc}")
        suggestion = suggest_interface()
        if suggestion and suggestion != interface:
            print(f"\n    Suggested: scrutics --live {suggestion} --headless")
    else:
        print("    No interfaces found. Are you running as root?")
    print()


# ── Output helpers ─────────────────────────────────────────────────────────────

def _make_session_dir(base: str) -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(base, f"scrutics_{ts}")
    os.makedirs(path, exist_ok=True)
    return path


def _print_table(inventory: AssetInventory):
    assets = sorted(inventory.get_all(), key=lambda x: x.ip)
    if not assets:
        print("[!] No assets discovered.")
        return
    print(f"\n{'─'*110}")
    print(f"{'IP':<18} {'MAC':<20} {'VENDOR':<22} {'PROTOCOL':<18} {'ROLE':<28} {'CONF%':<7} {'TYPE'}")
    print(f"{'─'*110}")
    for a in assets:
        proto  = ", ".join(a.protocols)[:18] if a.protocols else "Unknown"
        type_s = "OT" if a.is_ot is True else "IT" if a.is_ot is False else "?"
        print(f"{a.ip:<18} {a.mac:<20} {a.vendor[:22]:<22} {proto:<18} "
              f"{a.role[:28]:<28} {a.confidence_pct:<7}% {type_s}")
    print(f"{'─'*110}")
    print(f"Total: {inventory.count()} assets\n")


def _run_spinner(done_event: threading.Event, abort_event: threading.Event,
                 message: str = "Processing"):
    """ASCII spinner for silent phases. Stops on done or abort."""
    frames = itertools.cycle(["/", "-", "\\", "|"])
    while not done_event.is_set():
        if abort_event.is_set():
            print()
            return
        print(f"\r  {next(frames)}  {message} ...", end="", flush=True)
        done_event.wait(0.12)
    print(f"\r  ✓  {message}    ", flush=True)


def _periodic_table(inventory: AssetInventory, done_event: threading.Event,
                    stop_event: threading.Event, interval: int = 60):
    """Print asset snapshot every `interval` seconds during live headless capture."""
    elapsed = 0
    while not done_event.is_set() and not stop_event.is_set():
        done_event.wait(timeout=1.0)
        elapsed += 1
        if elapsed % interval == 0 and inventory.count() > 0:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"\n\n[{ts}] Asset snapshot ({elapsed}s elapsed):")
            _print_table(inventory)


def _checkpoint_session(inventory, engine, session_dir, lock):
    """Atomic checkpoint for headless mode – writes all data + topology."""
    if not session_dir or not inventory:
        return
    with lock:
        try:
            # 1. Write standard inventory & evidence
            inventory.export_csv(os.path.join(session_dir, "assets.csv"))
            
            evidence_path = os.path.join(session_dir, "evidence.json")
            evidence_data = {}
            for asset in inventory.get_all():
                if asset.evidence:
                    evidence_data[asset.ip] = [ev.to_dict() for ev in asset.evidence]
            if evidence_data:
                with open(evidence_path, "w", encoding="utf-8") as f:
                    json.dump(evidence_data, f, indent=2)
            
            # Events & anomalies
            if engine:
                events_path = os.path.join(session_dir, "events.csv")
                with open(events_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["timestamp", "message", "type"])
                    for ts, msg, typ in engine.event_log:
                        writer.writerow([ts, msg, typ])
                
                anomalies_path = os.path.join(session_dir, "anomalies.csv")
                with open(anomalies_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["timestamp", "ip", "severity", "type", "detail"])
                    for anom in engine.baseline.get_anomalies():
                        writer.writerow([
                            datetime.datetime.fromtimestamp(anom.get("timestamp", 0)).isoformat(),
                            anom.get("ip", ""),
                            anom.get("severity", ""),
                            anom.get("type", ""),
                            anom.get("detail", ""),
                        ])
            
            # 2. Now call export_topology for topology files
            from scrutics.topology import export_topology
            export_topology(inventory, engine.topology_edges if engine else None, session_dir)
            
        except Exception as e:
            print(f"\r[!] Checkpoint failed: {e}", flush=True)

# ── Main headless runner ───────────────────────────────────────────────────────

def run_headless(args) -> int:
    from scrutics.capture.engine import CaptureEngine
    from scrutics.db.writer import RollingWriter
    from scrutics.integrations.sinks import SinkManager
    from scrutics.config.loader import load_sinks_config
    import scrutics.signals as signals

    inventory   = AssetInventory()
    session_dir = _make_session_dir(args.output)
    engine      = CaptureEngine(inventory=inventory, baseline_window=args.baseline)
    engine.writer      = RollingWriter(session_dir)
    engine.no_baseline = getattr(args, "no_baseline", False)

    try:
        sinks_cfg = load_sinks_config(strict=True)
        if sinks_cfg:
            engine.sink_manager = SinkManager(sinks_cfg)
    except Exception as e:
        print(f"[!] Config error: {e}")
        return 1

    _last_reload_error = [None]

    def _reload():
        from scrutics.classifier.protocol import reload_rules
        try:
            reload_rules()
            new_sinks = load_sinks_config(strict=True)
            if engine.sink_manager:
                errors = engine.sink_manager.reload(new_sinks)
            elif new_sinks:
                engine.sink_manager = SinkManager(new_sinks)
                errors = []
            else:
                errors = []
            if errors:
                raise ValueError("; ".join(errors))
            _last_reload_error[0] = None
            print("\n[+] Rules and sinks reloaded.", flush=True)
        except Exception as e:
            msg = str(e)
            if msg != _last_reload_error[0]:
                _last_reload_error[0] = msg
                print(f"\n[!] Reload failed (old rules kept): {msg}", flush=True)

    signals.set_reload_callback(_reload)
    signals.start_file_watch()

    stop_event = threading.Event()

    def handle_stop(sig, frame):
        print("\n[*] Stopping...")
        stop_event.set()
        engine.request_stop()

    signal.signal(signal.SIGINT, handle_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_stop)

    # ── Checkpoint thread ─────────────────────────────────────────────────────
    checkpoint_lock = threading.Lock()

    def checkpoint_loop():
        while not stop_event.is_set():
            stop_event.wait(SESSION_FLUSH_INTERVAL)
            if not stop_event.is_set():
                _checkpoint_session(inventory, engine, session_dir, checkpoint_lock)

    checkpoint_thread = threading.Thread(target=checkpoint_loop, daemon=True)
    checkpoint_thread.start()

    # ── Live capture ──────────────────────────────────────────────────────────
    if args.live:
        dur_str = "infinite (Ctrl+C to stop)" if args.duration == 0 else f"{args.duration}s"
        print(f"\n[*] Scrutics {VERSION} — Headless")
        print(f"[*] Interface    : {args.live}")
        print(f"[*] Duration     : {dur_str}")
        print(f"[*] Baseline     : {'disabled' if engine.no_baseline else f'{args.baseline}s'}")
        if engine.sink_manager:
            print(f"[*] Sinks        : {engine.sink_manager.count} configured")
        print(f"[*] Output       : {session_dir}")
        print()

        _first_packet = threading.Event()

        def on_progress(count: int):
            if not _first_packet.is_set():
                _first_packet.set()
            if count % 100 == 0:
                print(f"\r  packets: {count}  assets: {inventory.count()}",
                      end="", flush=True)
        engine.progress_callback = on_progress

        def _quiet_warning():
            _first_packet.wait(timeout=30)
            if not _first_packet.is_set() and not stop_event.is_set():
                print(
                    f"\n[!] No packets seen on {args.live} after 30 seconds."
                    f"\n    Is this the correct interface? "
                    f"Try: sudo tcpdump -i {args.live} -c 5"
                    f"\n    Run 'scrutics doctor' to list available interfaces.\n",
                    flush=True,
                )

        capture_done = threading.Event()

        def run_capture():
            try:
                engine.start_live(interface=args.live, timeout=args.duration)
            except Exception as e:
                err = str(e)
                if any(kw in err.lower() for kw in
                       ("no such device", "invalid", "not found",
                        "does not exist", "cannot open", "no interface")):
                    print()
                    _interface_error(args.live)
                elif isinstance(e, PermissionError) or "permission" in err.lower():
                    print(
                        "\n[!] Permission denied — live capture requires root.\n"
                        "    Run with: sudo scrutics --live ...\n"
                        "    Or grant capability: "
                        "sudo setcap cap_net_raw+eip $(which python3)\n"
                    )
                else:
                    print(f"\n[!] Capture error: {e}")
            finally:
                capture_done.set()

        threading.Thread(target=run_capture, daemon=True).start()
        threading.Thread(target=_quiet_warning, daemon=True).start()
        threading.Thread(
            target=_periodic_table,
            args=(inventory, capture_done, stop_event, 60),
            daemon=True,
        ).start()

        while not capture_done.is_set() and not stop_event.is_set():
            capture_done.wait(timeout=1.0)

        if stop_event.is_set() and not capture_done.is_set():
            capture_done.wait(timeout=2.0)

    # ── File analysis ─────────────────────────────────────────────────────────
    elif args.file:
        if not os.path.exists(args.file):
            print(f"[!] File not found: {args.file}")
            return 1

        print(f"\n[*] Scrutics {VERSION} — Headless")
        print(f"[*] File         : {args.file}")
        print(f"[*] Baseline     : "
              f"{'disabled' if engine.no_baseline else f'{args.baseline}s window'}")
        print(f"[*] Output       : {session_dir}\n")

        spin_done  = threading.Event()
        file_error = [None]

        def run_file():
            try:
                engine.start_file(args.file)
            except Exception as e:
                file_error[0] = e
            finally:
                spin_done.set()

        threading.Thread(target=run_file, daemon=True).start()
        _run_spinner(spin_done, stop_event, f"Analyzing {os.path.basename(args.file)}")

        if stop_event.is_set():
            print("[*] Interrupted — saving partial results.")
        elif file_error[0]:
            print(f"[!] Error: {file_error[0]}")
            return 1

    # ── Final checkpoint ─────────────────────────────────────────────────────
    _checkpoint_session(inventory, engine, session_dir, checkpoint_lock)

    print()
    _print_table(inventory)

    try:
        # Ensure final export (non-atomic) for cleanliness
        from scrutics.topology import export_topology
        topology_paths = export_topology(inventory, engine.topology_edges, session_dir)

        if not engine.no_baseline:
            anomaly_count = len(engine.baseline.get_anomalies())
            if anomaly_count:
                print(f"[!] {anomaly_count} anomalies — see {session_dir}/anomalies.csv")
            else:
                print("[+] No anomalies detected.")

        print(f"\n[+] Session saved to: {session_dir}")
        if topology_paths:
            print(f"[+] Topology map saved to: {topology_paths['html']}")
            if "connections_csv" in topology_paths:
                print(f"[+] Connections saved to: {topology_paths['connections_csv']}")
        return 0 if inventory.count() > 0 else 2

    finally:
        if engine.sink_manager:
            engine.sink_manager.close()
        signals.stop_file_watch()


def should_use_tui(args) -> bool:
    if getattr(args, "command", None) == "doctor":
        return False
    if getattr(args, "headless", False):
        return False
    if not sys.stdout.isatty():
        return False
    return True