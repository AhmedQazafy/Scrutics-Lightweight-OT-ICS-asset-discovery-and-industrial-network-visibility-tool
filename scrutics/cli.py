"""
Scrutics CLI: headless and scriptable interface.

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
  Edit scrutics/config/custom_rules.yaml while running; Scrutics detects
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
from scrutics.db.inventory import AssetInventory, limit_summary_line
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

    # OUI database management command
    oui_parser = subparsers.add_parser(
        "oui",
        help="manage OUI database lifecycle, validation, and freshness",
    )
    oui_subparsers = oui_parser.add_subparsers(dest="oui_action")

    # status
    oui_subparsers.add_parser(
        "status",
        help="display active OUI database status, tiers, and freshness",
    )

    # validate
    v_parser = oui_subparsers.add_parser(
        "validate",
        help="validate an OUI database text file",
    )
    v_parser.add_argument("file", help="path to OUI text file to validate")

    # update
    u_parser = oui_subparsers.add_parser(
        "update",
        help="download and install the latest IEEE OUI database",
    )
    u_parser.add_argument(
        "--url",
        default="https://standards-oui.ieee.org/oui/oui.txt",
        help="URL to download OUI database from",
    )

    # import
    i_parser = oui_subparsers.add_parser(
        "import",
        help="import an offline OUI database text file",
    )
    i_parser.add_argument("file", help="path to OUI text file to import")

    # List available AI models command
    list_models_parser = subparsers.add_parser(
        "list-models",
        help="list available AI models for a provider",
    )
    list_models_parser.add_argument(
        "provider",
        choices=["gemini", "openai", "anthropic", "ollama"],
        help="AI provider to query",
    )
    list_models_parser.add_argument(
        "--key",
        metavar="API_KEY",
        help="API key (reads from environment if not provided)",
    )

    # Register 'ai' subcommand (primary) and 'ask' as a hidden backward-compat alias
    ai_parser = subparsers.add_parser(
        "ai",
        help="ask Scrutics AI a natural-language question about a capture session",
    )
    ask_parser = subparsers.add_parser(
        "ask",
        help=argparse.SUPPRESS,  # hidden from help; use 'scrutics ai' instead
    )
    # Both subcommands accept the same arguments
    for sp in (ai_parser, ask_parser):
        sp.add_argument(
            "question",
            nargs="*",  # optional: if omitted, enter interactive mode
            default=[],
            help="question to ask (omit for interactive mode)",
        )
        sp.add_argument(
            "--session",
            metavar="PATH",
            help="path to Scrutics session directory (default: most recent in output/)",
        )
        sp.add_argument(
            "--output",
            default="output",
            metavar="DIR",
            help="output directory to search for sessions (default: ./output)",
        )
        sp.add_argument(
            "--provider",
            metavar="NAME",
            help="LLM provider override (e.g. ollama)",
        )
        sp.add_argument(
            "--model",
            metavar="NAME",
            help="LLM model override (e.g. qwen3.5:4b)",
        )
        sp.add_argument(
            "--reconfigure",
            action="store_true",
            help="re-run the AI setup wizard to change provider or model",
        )
        sp.add_argument(
            "--disable",
            action="store_true",
            help="disable AI assistant (sets enabled: false in ai.yaml)",
        )
        sp.add_argument(
            "--reset",
            action="store_true",
            help="delete ai.yaml config file (requires re-setup)",
        )
        sp.add_argument(
            "--diagnose",
            action="store_true",
            help="run 14-stage progressive diagnostics suite on configured AI provider",
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


# ── scrutics list-models ───────────────────────────────────────────────────────

def run_list_models(args) -> int:
    """List available models for a provider."""
    provider = args.provider
    api_key = getattr(args, "key", None)
    
    # If no key provided, try to read from environment
    if not api_key:
        env_vars = {
            "gemini": "GEMINI_API_KEY",
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
        }
        var_name = env_vars.get(provider)
        if var_name:
            api_key = os.environ.get(var_name, "")
    
    print(f"\n  Fetching {provider} models...")
    print(f"  {'─' * 60}")
    
    from scrutics.ai.model_discovery import fetch_models, _FALLBACK_MODELS
    
    try:
        base_url = "http://localhost:11434" if provider == "ollama" else ""
        models = fetch_models(provider, api_key, base_url, timeout=10.0, max_results=50)
        
        if not models:
            print(f"  ✗ Failed to fetch models from {provider}.")
            if provider == "ollama":
                print(f"  Is Ollama running? Try: ollama serve")
            elif not api_key:
                print(f"  No API key found. Set {env_vars.get(provider, 'API_KEY')} or use --key")
            else:
                print(f"  Possible causes:")
                print(f"    • Invalid or expired API key")
                print(f"    • Network connectivity issue")
                print(f"    • Provider API is down")
                print(f"    • Rate limit exceeded")
            
            # Show fallback list with warning
            fallback = _FALLBACK_MODELS.get(provider, [])
            if fallback:
                print(f"\n  Fallback list (may be outdated, {len(fallback)} models):\n")
                for i, model in enumerate(fallback, 1):
                    print(f"  {i:2d}. {model}")
            print()
            return 1
        
        print(f"  ✓ Found {len(models)} models:\n")
        for i, model in enumerate(models, 1):
            print(f"  {i:2d}. {model}")
        print()
        return 0
    except Exception as e:
        sys.stderr.write(f"  ✗ Error: {e}\n")
        return 1


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

    print()
    oui_info = report.get("oui", {})
    if oui_info and oui_info.get("exists"):
        freshness = oui_info.get("freshness", "Current")
        status = "✓" if freshness == "Current" else "⚠"
        tiers = oui_info.get("tiers", {})
        t_str = f"MA-L: {tiers.get('ma_l', 0):,}, MA-M: {tiers.get('ma_m', 0):,}, MA-S: {tiers.get('ma_s', 0):,}"
        print(f"  OUI Database")
        print(f"  {status}  database:       {oui_info['path']}  ({oui_info['db_type']})")
        print(f"     entries:        {oui_info['entry_count']:,}  ({t_str})")
        print(f"     age:            {oui_info['age_days']} days ({freshness})")
        if freshness != "Current":
            print(f"     notice:         Run 'scrutics oui update' to install the latest IEEE database.")
    else:
        print(f"  OUI Database")
        print(f"  ⚠  No OUI database found. Run 'scrutics oui update' to install.")

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


# ── scrutics oui ───────────────────────────────────────────────────────────────

def run_oui(args) -> int:
    """Entry point for 'scrutics oui' subcommands."""
    action = getattr(args, "oui_action", None)
    if action == "status":
        return run_oui_status(args)
    elif action == "validate":
        return run_oui_validate(args)
    elif action == "update":
        return run_oui_update(args)
    elif action == "import":
        return run_oui_import(args)
    else:
        parser = build_parser()
        subparsers_actions = [
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        ]
        for sa in subparsers_actions:
            if "oui" in sa.choices:
                sa.choices["oui"].print_help()
                break
        return 0


def run_oui_status(args) -> int:
    """Display active OUI database status, breakdown, and operational freshness."""
    from scrutics.classifier.oui import get_oui_freshness, FRESHNESS_CURRENT
    info = get_oui_freshness()
    w = 56
    print("\n  Scrutics OUI Database Status")
    print(f"  {'─' * w}")
    if not info["path"]:
        print("  Status:          No active database found")
        print("  Action needed:   Run 'scrutics oui update' or 'scrutics oui import <file>'")
        print(f"  {'─' * w}\n")
        return 0

    status_icon = "✓" if info["freshness"] == FRESHNESS_CURRENT else "⚠"
    tiers = info["tiers"]
    print(f"  Active Database: {info['path']}")
    print(f"  Database Type:   {info['db_type']}")
    print(f"  Total Entries:   {info['entry_count']:,}")
    print(f"    MA-L (24-bit): {tiers['ma_l']:,}")
    print(f"    MA-M (28-bit): {tiers['ma_m']:,}")
    print(f"    MA-S (36-bit): {tiers['ma_s']:,}")
    if info.get("source"):
        print(f"  Source:          {info['source']}")
    if info.get("source_date"):
        print(f"  Source Date:     {info['source_date']}")
    if info.get("local_update_time"):
        print(f"  Last Updated:    {info['local_update_time']}")
    print(f"  Database Age:    {info['age_days']} days")
    print(f"  Freshness:       {status_icon} {info['freshness']}")
    if info.get("sha256"):
        print(f"  SHA-256:         {info['sha256']}")
    if info["freshness"] != FRESHNESS_CURRENT:
        print(f"\n  [!] Database is {info['freshness'].lower()} (≥180 days old).")
        print("      Run 'scrutics oui update' to install the latest IEEE database.")
    print(f"  {'─' * w}\n")
    return 0


def run_oui_validate(args) -> int:
    """Validate an OUI database text file."""
    from scrutics.classifier.oui import validate_oui_file
    filepath = args.file
    print(f"\n[*] Validating OUI database file: {filepath}")
    report = validate_oui_file(filepath)
    if not report["valid"]:
        print(f"[✗] Validation failed: {report.get('error', 'Unknown error')}\n")
        return 1

    tiers = report["tiers"]
    print(f"[✓] Valid OUI database:")
    print(f"    Total entries:   {report['entry_count']:,}")
    print(f"    MA-L (24-bit):   {tiers['ma_l']:,}")
    print(f"    MA-M (28-bit):   {tiers['ma_m']:,}")
    print(f"    MA-S (36-bit):   {tiers['ma_s']:,}")
    print(f"    Total lines:     {report['total_lines']:,}")
    if report["malformed_count"] > 0:
        print(f"    Malformed lines: {report['malformed_count']:,} (skipped)")
    print(f"    SHA-256:         {report['sha256']}\n")
    return 0


def run_oui_update(args) -> int:
    """Download and install the latest IEEE OUI database."""
    from scrutics.classifier.oui import download_ieee_oui
    url = args.url
    print(f"\n[*] Updating OUI database from {url}...")
    ok, msg, report = download_ieee_oui(url=url)
    if not ok:
        print(f"[✗] Update failed: {msg}\n")
        return 1
    print(f"[✓] {msg}")
    if report and "tiers" in report:
        tiers = report["tiers"]
        print(f"    Entries: {report['entry_count']:,} (MA-L: {tiers['ma_l']:,}, MA-M: {tiers['ma_m']:,}, MA-S: {tiers['ma_s']:,})")
        print(f"    SHA-256: {report['sha256']}")
    print("[+] Updated ~/.scrutics/oui.txt successfully.\n")
    return 0


def run_oui_import(args) -> int:
    """Import an offline OUI database file."""
    from scrutics.classifier.oui import import_oui_file
    filepath = args.file
    print(f"\n[*] Importing OUI database from {filepath}...")
    ok, msg, report = import_oui_file(filepath)
    if not ok:
        print(f"[✗] Import failed: {msg}\n")
        return 1
    print(f"[✓] {msg}")
    if report and "tiers" in report:
        tiers = report["tiers"]
        print(f"    Entries: {report['entry_count']:,} (MA-L: {tiers['ma_l']:,}, MA-M: {tiers['ma_m']:,}, MA-S: {tiers['ma_s']:,})")
        print(f"    SHA-256: {report['sha256']}")
    print("[+] Imported into ~/.scrutics/oui.txt successfully.\n")
    return 0


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
            from scrutics.topology import export_topology, write_manifest
            export_topology(inventory, engine.topology_edges if engine else None, session_dir)

            # 3. Write manifest
            write_manifest(session_dir, metadata={
                "inventory": inventory,
                "edges": engine.topology_edges if engine else None,
                "engine": engine,
                "capture_started": getattr(engine, "capture_started", None) if engine else None,
            })
            
        except Exception as e:
            print(f"\r[!] Checkpoint failed: {e}", flush=True)

# ── Main headless runner ───────────────────────────────────────────────────────

def run_headless(args) -> int:
    if getattr(args, "command", None) in ("ai", "ask"):
        return run_ai(args)
    if getattr(args, "command", None) == "oui":
        return run_oui(args)

    from scrutics.capture.engine import CaptureEngine
    from scrutics.db.writer import RollingWriter
    from scrutics.integrations.sinks import SinkManager
    from scrutics.config.loader import load_sinks_config
    import scrutics.signals as signals

    inventory   = AssetInventory()
    session_dir = _make_session_dir(args.output)
    engine      = CaptureEngine(inventory=inventory, baseline_window=args.baseline)
    engine.capture_started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
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

    # ── Initial checkpoint & Checkpoint thread ─────────────────────────────────
    checkpoint_lock = threading.Lock()
    # Write an initial checkpoint immediately so Scrutics AI in other terminals
    # can immediately recognize and query the active session
    _checkpoint_session(inventory, engine, session_dir, checkpoint_lock)

    def checkpoint_loop():
        while not stop_event.is_set():
            stop_event.wait(SESSION_FLUSH_INTERVAL)
            if not stop_event.is_set():
                _checkpoint_session(inventory, engine, session_dir, checkpoint_lock)

    checkpoint_thread = threading.Thread(target=checkpoint_loop, daemon=True)
    checkpoint_thread.start()

    from scrutics.classifier.oui import get_oui_freshness, FRESHNESS_CURRENT
    oui_info = get_oui_freshness()
    if oui_info.get("path") and oui_info.get("freshness") != FRESHNESS_CURRENT:
        print(f"[!] OUI database is {oui_info['age_days']} days old ({oui_info['freshness']}) — run 'scrutics oui update'")

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

        # Rejected input and contained errors, printed as plain text
        if engine.ingest_stats.has_issues():
            print(f"[!] {engine.ingest_stats.summary_line()}")
        else:
            print("[+] Input: 0 rejected | 0 contained errors")
        # Entries a device did not keep because a per-device retention limit was reached
        limits = inventory.limit_totals()
        print(f"[{'!' if any(limits.values()) else '+'}] {limit_summary_line(limits)}")

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
    if getattr(args, "command", None) in ("doctor", "ai", "ask", "list-models", "oui"):
        return False
    if getattr(args, "headless", False):
        return False
    if not sys.stdout.isatty():
        return False
    return True


# ── scrutics ai ────────────────────────────────────────────────────────────────

SCRUTICS_BANNER_LINES = [
    r" ███████╗ ██████╗██████╗ ██╗   ██╗████████╗██╗ ██████╗███████╗     █████╗ ██╗",
    r" ██╔════╝██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║██╔════╝██╔════╝    ██╔══██╗██║",
    r" ███████╗██║     ██████╔╝██║   ██║   ██║   ██║██║     ███████╗    ███████║██║",
    r" ╚════██║██║     ██╔══██╗██║   ██║   ██║   ██║██║     ╚════██║    ██╔══██║██║",
    r" ███████║╚██████╗██║  ██║╚██████╔╝   ██║   ██║╚██████╗███████║    ██║  ██║██║",
    r" ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝ ╚═════╝╚══════╝    ╚═╝  ╚═╝╚═╝",
    r"                       OT/ICS Passive AI Assistant                     ",
]

# Workflow hint shown when no session exists yet
_AI_WORKFLOW_GUIDANCE = (
    "\n'scrutics ai' answers questions about a completed capture session.\n"
    "Run a capture first:\n"
    "  sudo scrutics --live <interface> --duration 60 --headless\n"
    "Then ask:\n"
    "  scrutics ai \"What PLCs were discovered?\"\n"
    "Or start an interactive session:\n"
    "  scrutics ai"
)


def _print_ask_banner() -> None:
    """
    Print Scrutics AI wordmark banner with a 7-step truecolor gradient from
    OT Orange (#e07b39 / RGB 224,123,57) to IT Blue (#4a90d9 / RGB 74,144,217).
    Honors NO_COLOR environment variable and isatty checks.
    """
    color_enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    start_rgb = (224, 123, 57)
    end_rgb   = (74, 144, 217)
    n = len(SCRUTICS_BANNER_LINES)

    for i, line in enumerate(SCRUTICS_BANNER_LINES):
        if color_enabled:
            t = i / max(1, n - 1)
            r = int(start_rgb[0] + t * (end_rgb[0] - start_rgb[0]))
            g = int(start_rgb[1] + t * (end_rgb[1] - start_rgb[1]))
            b = int(start_rgb[2] + t * (end_rgb[2] - start_rgb[2]))
            print(f"\033[38;2;{r};{g};{b}m{line}\033[0m")
        else:
            print(line)
    print()


def _print_session_context(session_dir: str, ctx: object) -> None:
    """
    Print a one-line summary of the session being analyzed so the user knows
    exactly what data the AI is drawing from.
    """
    session_name = os.path.basename(session_dir)
    # Summarize asset/anomaly counts from loaded context
    asset_count   = len(getattr(ctx, "assets", []))
    anomaly_count = len(getattr(ctx, "anomalies", []))
    conn_count    = len(getattr(ctx, "connections", []))

    # Try to extract a human-readable timestamp from the session folder name
    # (format: scrutics_YYYYMMDD_HHMMSS)
    parts = session_name.split("_")
    if len(parts) >= 3:
        try:
            date_str = parts[1]
            time_str = parts[2]
            ts = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:]}  {time_str[:2]}:{time_str[2:4]}:{time_str[4:]}"
        except (IndexError, ValueError):
            ts = session_name
    else:
        ts = session_name

    dim   = "\033[2m"   if sys.stdout.isatty() else ""
    reset = "\033[0m"   if sys.stdout.isatty() else ""
    bold  = "\033[1m"   if sys.stdout.isatty() else ""
    print(
        f"{dim}Session :{reset} {bold}{ts}{reset}  "
        f"{dim}({asset_count} assets · {conn_count} connections · {anomaly_count} anomalies){reset}\n"
        f"{dim}Path    :{reset} {session_dir}"
    )
    print()


class Spinner:
    """
    Animated in-place terminal spinner using standard library threading.
    Cycles through Braille characters and supports dynamic message updates.
    Clears the line completely before the caller prints output.
    """
    FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

    def __init__(self, message: str = "Thinking..."):
        self.message  = message
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock    = threading.Lock()

    def set_message(self, message: str) -> None:
        """Update the spinner label (thread-safe)."""
        with self._lock:
            self.message = message

    def _spin(self) -> None:
        frame_idx = 0
        while self._running:
            with self._lock:
                msg = self.message
            char = self.FRAMES[frame_idx % len(self.FRAMES)]
            frame_idx += 1
            if sys.stdout.isatty():
                sys.stdout.write(f"\r\033[2K{char} {msg}")
                sys.stdout.flush()
            time.sleep(0.08)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=0.5)
        self.clear()

    def clear(self) -> None:
        if sys.stdout.isatty():
            sys.stdout.write("\r\033[2K\r")
            sys.stdout.flush()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


def resolve_session_dir(session_arg: str | None, output_base: str = "output") -> str:
    """
    Resolve session directory by explicit path, or by finding the newest session
    directory under output_base.
    Raises FileNotFoundError with actionable guidance if no session is found.
    """
    if session_arg:
        if not os.path.isdir(session_arg):
            raise FileNotFoundError(
                f"Session directory '{session_arg}' does not exist.{_AI_WORKFLOW_GUIDANCE}"
            )
        return session_arg

    if not os.path.isdir(output_base):
        raise FileNotFoundError(
            f"Output directory '{output_base}' does not exist. "
            f"Run a capture first or specify --session <path>.{_AI_WORKFLOW_GUIDANCE}"
        )

    all_candidates = [
        d for d in os.listdir(output_base)
        if d.startswith("scrutics_") and os.path.isdir(os.path.join(output_base, d))
    ]
    if not all_candidates:
        raise FileNotFoundError(
            f"No Scrutics sessions found in '{output_base}'. "
            f"Run a capture first or specify --session <path>.{_AI_WORKFLOW_GUIDANCE}"
        )

    # Filter to candidates that have a valid manifest.json (e.g. Completed or live checkpointed)
    valid_candidates = [
        d for d in all_candidates
        if os.path.exists(os.path.join(output_base, d, "manifest.json"))
    ]
    candidates_to_sort = valid_candidates if valid_candidates else all_candidates

    # Newest first by mtime; session name is the tiebreaker
    candidates_to_sort.sort(
        key=lambda d: (os.path.getmtime(os.path.join(output_base, d)), d),
        reverse=True,
    )
    return os.path.join(output_base, candidates_to_sort[0])


def _ask_one(
    provider: object,
    ctx: object,
    question: str,
    conversation_history: list,
    status_callback: object = None,
) -> str | None:
    """
    Submit a single question through the agent loop, using conversation_history
    so follow-up questions retain context.  Returns the answer string, or None
    on an LLM error (errors are printed to stderr by the caller).
    """
    from scrutics.ai.agent import run_agent_loop
    # run_agent_loop builds its own message list from scratch each call,
    # so we pass prior Q&A pairs as extra context injected into the question.
    # This gives the model full conversation awareness without changing the
    # agent API.
    if conversation_history:
        prior = "\n".join(
            f"User: {q}\nAssistant: {a}"
            for q, a in conversation_history
        )
        full_question = (
            f"[Previous conversation]\n{prior}\n\n"
            f"[New question]\n{question}"
        )
    else:
        full_question = question

    return run_agent_loop(
        provider=provider,
        ctx=ctx,
        user_message=full_question,
        status_callback=status_callback,
    )


def _run_ai_repl(provider, ctx, session_dir: str, initial_question: str | None) -> int:
    """
    Interactive REPL loop for Scrutics AI.  Prints the banner + session context
    once, then loops asking for questions until the user types 'exit'/'quit'/Ctrl-D.
    If initial_question is given, answers it first before entering the loop.

    Returns an exit code (0 = clean exit, 130 = Ctrl-C abort).
    """
    from scrutics.ai.provider import (
        LLMConnectionError,
        LLMTimeoutError,
        LLMResponseError,
        LLMProviderError,
    )

    is_tty = sys.stdout.isatty()
    dim    = "\033[2m"  if is_tty else ""
    reset  = "\033[0m"  if is_tty else ""
    bold   = "\033[1m"  if is_tty else ""

    _print_ask_banner()
    _print_session_context(session_dir, ctx)

    if is_tty:
        print(
            f"{dim}Type your question and press Enter. "
            f"Type {bold}exit{reset}{dim} or press Ctrl-D to quit.{reset}\n"
        )

    conversation_history: list[tuple[str, str]] = []
    spinner = Spinner("Thinking...")

    def _cli_retry_callback(attempt: int, total: int, delay: float) -> None:
        if delay > 0:
            spinner.set_message(f"Waiting {int(round(delay))}s before retry (attempt {attempt} of {total})...")
        else:
            spinner.set_message(f"Retrying (attempt {attempt} of {total})...")

    if hasattr(provider, "set_retry_callback"):
        provider.set_retry_callback(_cli_retry_callback)
    elif hasattr(provider, "retry_callback"):
        provider.retry_callback = _cli_retry_callback

    def _do_question(question: str) -> int | None:
        """Ask one question. Returns non-zero exit code on fatal error, else None."""
        nonlocal conversation_history, ctx
        try:
            # Refresh session context from disk in case a live capture is currently appending data
            from scrutics.ai.tools import SessionContext
            try:
                ctx = SessionContext(session_dir)
            except Exception:
                pass

            spinner.set_message("Thinking...")
            spinner.start()
            try:
                answer = _ask_one(
                    provider,
                    ctx,
                    question,
                    conversation_history,
                    status_callback=spinner.set_message,
                )
            finally:
                spinner.stop()
        except KeyboardInterrupt:
            spinner.stop()
            sys.stderr.write("\nCancelled.\n")
            return 130
        except LLMConnectionError as e:
            spinner.stop()
            sys.stderr.write(
                f"Error: Could not reach LLM provider ({e}).\n"
                f"Is Ollama running? Try: ollama serve\n"
            )
            return 1
        except LLMTimeoutError as e:
            spinner.stop()
            sys.stderr.write(f"Error: Request to LLM provider timed out ({e}).\n")
            return 1
        except LLMResponseError as e:
            spinner.stop()
            sys.stderr.write(f"Error: LLM provider response error: {e}\n")
            return 1
        except LLMProviderError as e:
            spinner.stop()
            sys.stderr.write(f"Error: LLM provider error: {e}\n")
            return 1

        print(answer)
        print()
        conversation_history.append((question, answer))
        return None

    # If a question was supplied on the command line, answer it first
    if initial_question:
        rc = _do_question(initial_question)
        if rc is not None:
            return rc
        # Non-interactive mode: question was provided → single shot, then exit
        if not is_tty:
            return 0

    # Interactive loop, only reached when running in a real terminal
    while True:
        try:
            if is_tty:
                sys.stdout.write(f"{bold}You:{reset} ")
                sys.stdout.flush()
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            sys.stderr.write("\nCancelled.\n")
            return 130

        if not line:
            # Ctrl-D / EOF
            if is_tty:
                print()
            return 0

        question = line.strip()
        if not question:
            continue
        if question.lower() in ("exit", "quit", "q", ":q"):
            return 0

        rc = _do_question(question)
        if rc is not None and rc != 130:
            # Non-fatal LLM error: print it and let user keep asking
            continue
        if rc == 130:
            return 130


_CLI_ONBOARDING_PROVIDERS = [
    ("gemini",    "Google Gemini  (free tier — recommended)", "gemini-3.8-flash",  "GEMINI_API_KEY",    "https://aistudio.google.com/app/apikey"),
    ("openai",    "OpenAI                                   ", "gpt-4o-mini",       "OPENAI_API_KEY",    "https://platform.openai.com/api-keys"),
    ("anthropic", "Anthropic                                ", "claude-haiku-4-5",  "ANTHROPIC_API_KEY", "https://console.anthropic.com/settings/keys"),
    ("ollama",    "Ollama (local, no key needed)            ", "qwen3.5:4b",        None,                None),
]


def _run_ai_onboarding_cli() -> dict | None:
    """
    Interactive first-time setup wizard for the CLI.
    Prompts for provider and API key, writes ~/.bashrc and ai.yaml.
    Returns a config dict ready for build_provider(), or None if the user skipped.
    """
    import getpass
    import re as _re

    print("\n✦ Scrutics AI — First-Time Setup")
    print("─" * 50)
    print("AI is not configured yet. Let's set it up.\n")

    for i, (_, label, _, _, _) in enumerate(_CLI_ONBOARDING_PROVIDERS, 1):
        print(f"  {i}. {label}")
    print(f"  {len(_CLI_ONBOARDING_PROVIDERS) + 1}. Skip for now\n")

    while True:
        try:
            raw = input(f"  Choose 1-{len(_CLI_ONBOARDING_PROVIDERS) + 1}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSkipped.")
            return None
        if raw.isdigit():
            idx = int(raw) - 1
            if idx == len(_CLI_ONBOARDING_PROVIDERS):
                print("\nSkipped. Run 'scrutics ai' again to set up later.")
                return None
            if 0 <= idx < len(_CLI_ONBOARDING_PROVIDERS):
                break
        print(f"  Please enter a number between 1 and {len(_CLI_ONBOARDING_PROVIDERS) + 1}.")

    provider_id, _, model, var_name, key_url = _CLI_ONBOARDING_PROVIDERS[idx]

    api_key = ""
    if var_name:
        if key_url:
            print(f"\nGet your API key at:\n  {key_url}\n")
        try:
            api_key = getpass.getpass("  Paste API key (hidden): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSkipped.")
            return None
        if not api_key:
            print("\nNo key entered. Skipped.")
            return None

        # Save to ~/.bashrc
        bashrc = os.path.join(os.path.expanduser("~"), ".bashrc")
        try:
            content = open(bashrc, encoding="utf-8").read() if os.path.exists(bashrc) else ""
            content = _re.sub(rf"^export {var_name}=.*\n?", "", content, flags=_re.MULTILINE)
            with open(bashrc, "a", encoding="utf-8") as f:
                if content and not content.endswith("\n"):
                    f.write("\n")
                f.write(f'export {var_name}="{api_key}"\n')
            os.environ[var_name] = api_key
        except Exception:
            pass

    # Discover available models
    print("\n  Checking available models...", end="", flush=True)
    try:
        from scrutics.ai.model_discovery import fetch_models
        base_url = "" if provider_id != "ollama" else "http://localhost:11434"
        available = fetch_models(provider_id, api_key, base_url, timeout=6.0)
    except Exception:
        available = []

    if available:
        print(f" found {len(available)}")
        print()
        for i, m in enumerate(available, 1):
            print(f"    {i}. {m}")
        print()
        while True:
            try:
                raw = input(f"  Select model (1-{len(available)}, default=1): ").strip()
            except (EOFError, KeyboardInterrupt):
                raw = ""
            if not raw:
                model = available[0]
                break
            if raw.isdigit() and 1 <= int(raw) <= len(available):
                model = available[int(raw) - 1]
                break
            print(f"  Enter a number between 1 and {len(available)}.")
        print(f"  Selected: {model}")
    else:
        print(" using default")

    # Write ai.yaml
    timeout = 180 if provider_id == "ollama" else 60
    try:
        import scrutics as _sc
        # Write to ~/.scrutics/ai.yaml (user config); never overwrite the packaged template
        user_scrutics_dir = os.path.join(os.path.expanduser("~"), ".scrutics")
        os.makedirs(user_scrutics_dir, exist_ok=True)
        yaml_path = os.path.join(user_scrutics_dir, "ai.yaml")
        lines = [
            "# Scrutics AI Configuration\n",
            "# Configured via CLI onboarding. Run scrutics_ai_setup.sh to reconfigure.\n",
            "enabled: true\n",
            f"provider: {provider_id}\n",
            f"model: {model}\n",
        ]
        if var_name:
            lines.append(f"api_key: ${{{var_name}}}\n")
        lines += ["temperature: 0.3\n", "max_tokens: 1024\n", f"timeout: {timeout}\n"]
        if provider_id == "ollama":
            lines += ["base_url: http://localhost:11434\n", "reasoning_effort: low\n"]
        with open(yaml_path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
    except Exception:
        pass

    print("\n✓ Scrutics AI is ready.\n")

    cfg: dict = {
        "enabled": True,
        "provider": provider_id,
        "model": model,
        "temperature": 0.3,
        "max_tokens": 1024,
        "timeout": timeout,
    }
    if var_name:
        cfg["api_key"] = f"${{{var_name}}}"
    return cfg


def run_ai(args) -> int:
    """
    Scrutics AI entry point.

    One-shot:    scrutics ai "What PLCs were on the network?"
    Interactive: scrutics ai                  (prompts for questions)
    """
    # ── Diagnose command ───────────────────────────────────────────────────────
    raw_question = getattr(args, "question", [])
    q_tokens = [raw_question] if isinstance(raw_question, str) else list(raw_question)
    is_diagnose = getattr(args, "diagnose", False) or (q_tokens and str(q_tokens[0]).strip().lower() == "diagnose")
    if is_diagnose:
        from scrutics.ai.diagnostics import run_ai_diagnostics
        provider_override = getattr(args, "provider", None)
        return run_ai_diagnostics(provider_name=provider_override)

    session_arg = getattr(args, "session", None)
    output_base = getattr(args, "output", "output")

    # ── Resolve and validate session ──────────────────────────────────────────
    try:
        session_dir = resolve_session_dir(session_arg, output_base)
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1

    from scrutics.ai.tools import SessionContext
    try:
        ctx = SessionContext(session_dir)
    except Exception as e:
        sys.stderr.write(
            f"Error: Invalid session directory '{session_dir}': {e}\n"
            f"{_AI_WORKFLOW_GUIDANCE}\n"
        )
        return 1

    # ── Build LLM provider ────────────────────────────────────────────────────
    from scrutics.ai.config import load_ai_config, build_provider
    from scrutics.ai.provider import LLMProviderError

    try:
        cfg = load_ai_config()
    except LLMProviderError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1

    provider_override = getattr(args, "provider", None)
    model_override    = getattr(args, "model", None)
    reconfigure       = getattr(args, "reconfigure", False)
    disable           = getattr(args, "disable", False)
    reset             = getattr(args, "reset", False)
    
    # --disable: set enabled: false in ai.yaml
    if disable:
        yaml_path = os.path.join(os.path.expanduser("~"), ".scrutics", "ai.yaml")
        if not os.path.exists(yaml_path):
            sys.stderr.write("AI config not found. Nothing to disable.\n")
            return 1
        try:
            import re
            content = open(yaml_path, encoding="utf-8").read()
            content = re.sub(r"^enabled:\s*true", "enabled: false", content, flags=re.MULTILINE)
            with open(yaml_path, "w", encoding="utf-8") as f:
                f.write(content)
            print("✓ AI assistant disabled. Delete ai.yaml or run 'scrutics ai --reconfigure' to re-enable.")
            return 0
        except Exception as e:
            sys.stderr.write(f"Error: Failed to disable AI: {e}\n")
            return 1
    
    # --reset: delete ai.yaml
    if reset:
        yaml_path = os.path.join(os.path.expanduser("~"), ".scrutics", "ai.yaml")
        if not os.path.exists(yaml_path):
            sys.stderr.write("AI config not found. Nothing to reset.\n")
            return 1
        try:
            os.remove(yaml_path)
            print("✓ AI config deleted. Run 'scrutics ai --reconfigure' to set up again.")
            return 0
        except Exception as e:
            sys.stderr.write(f"Error: Failed to reset config: {e}\n")
            return 1

    # --reconfigure or AI not yet configured → run interactive onboarding
    if reconfigure or (not provider_override and (not cfg or cfg.get("enabled") is False)):
        if reconfigure:
            print("\n✦ Scrutics AI — Reconfigure")
            print("─" * 50)
        cfg = _run_ai_onboarding_cli()
        if not cfg:
            return 1

    if provider_override:
        cfg["provider"] = provider_override
    if model_override:
        cfg["model"] = model_override

    try:
        provider = build_provider(cfg)
    except LLMProviderError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1

    # ── Extract initial question (may be empty → interactive mode) ─────────────
    raw_question = getattr(args, "question", [])
    if isinstance(raw_question, list):
        initial_question = " ".join(raw_question).strip() or None
    else:
        initial_question = str(raw_question).strip() or None

    # ── Enter REPL ────────────────────────────────────────────────────────────
    return _run_ai_repl(provider, ctx, session_dir, initial_question)


# Backward-compat alias: old code and old tests that call run_ask() still work
def run_ask(args) -> int:
    """Backward-compatible alias for run_ai()."""
    return run_ai(args)