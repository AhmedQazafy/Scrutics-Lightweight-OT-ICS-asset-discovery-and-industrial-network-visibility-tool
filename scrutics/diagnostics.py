"""
Scrutics diagnostics — shared checks used by startup logging and scrutics doctor.

All checks return plain dicts so callers can choose how to format output.
"""

import os
import sys
import platform
import shutil


VERSION = "v0.6.1"
_PKG_DIR = os.path.dirname(__file__)


# ── Dependency checks ──────────────────────────────────────────────────────────

def check_dependencies(headless: bool = False) -> list[dict]:
    """
    Return dependency results for startup blocking.
    headless=True: only check scapy and pyyaml (textual not needed).
    headless=False: also check textual.
    For a complete report including textual, use check_all_dependencies().
    """
    checks = [
        ("scapy", "pip install scapy --break-system-packages"),
        ("yaml",  "pip install pyyaml --break-system-packages"),
    ]
    if not headless:
        checks.append(("textual", "pip install textual --break-system-packages"))
    return _run_dep_checks(checks)


def check_all_dependencies() -> list[dict]:
    """
    Return all dependency results including textual.
    Used by scrutics doctor so the full picture is always shown.
    """
    checks = [
        ("scapy",   "pip install scapy --break-system-packages"),
        ("yaml",    "pip install pyyaml --break-system-packages"),
        ("textual", "pip install textual --break-system-packages"),
    ]
    return _run_dep_checks(checks)


def _run_dep_checks(checks: list) -> list[dict]:
    results = []
    for pkg, install_cmd in checks:
        display = "pyyaml" if pkg == "yaml" else pkg
        try:
            mod = __import__(pkg)
            version = getattr(mod, "__version__", "installed")
            results.append({"name": display, "ok": True,
                            "version": version, "install_cmd": install_cmd})
        except ImportError:
            results.append({"name": display, "ok": False,
                            "version": None, "install_cmd": install_cmd})
    return results


def _is_wsl() -> bool:
    """Detect WSL2 environment."""
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def check_libpcap() -> dict:
    """Check whether libpcap / WinPcap is available for live capture."""
    if _is_wsl():
        return {
            "ok": True,
            "detail": "WSL2 — uses AF_PACKET directly, libpcap not required",
        }
    try:
        import ctypes
        import ctypes.util
        if sys.platform == "win32":
            ctypes.cdll.LoadLibrary("wpcap")
        else:
            lib = ctypes.util.find_library("pcap")
            if lib:
                ctypes.cdll.LoadLibrary(lib)
            else:
                for candidate in ("libpcap.so.0.8", "libpcap.so.1", "libpcap.so"):
                    try:
                        ctypes.cdll.LoadLibrary(candidate)
                        break
                    except OSError:
                        continue
                else:
                    raise OSError("libpcap not found")
        return {"ok": True, "detail": "libpcap found"}
    except OSError:
        if sys.platform == "win32":
            return {"ok": False,
                    "detail": "WinPcap / Npcap not found",
                    "fix": "Install Npcap from https://npcap.com"}
        else:
            return {"ok": False,
                    "detail": "libpcap not found",
                    "fix": "sudo apt install libpcap-dev   (Debian/Ubuntu)\n"
                           "       sudo dnf install libpcap-devel  (Fedora/RHEL)"}


# ── Interface discovery ────────────────────────────────────────────────────────

def _clean_iface_desc(name: str, raw_desc: str) -> str:
    """
    Return a clean description for display.
    Scapy often returns the interface name as its own description — suppress that.
    Add friendly labels for well-known prefixes.
    """
    if raw_desc and raw_desc != name:
        return raw_desc
    if name.startswith("br-"):
        return "Docker bridge"
    if name.startswith("veth"):
        return "Docker veth"
    if name.startswith("virbr"):
        return "libvirt bridge"
    if name == "lo":
        return "loopback"
    if name == "docker0":
        return "Docker bridge"
    return ""


def list_interfaces() -> list[dict]:
    """
    Return available network interfaces with basic metadata.
    Works without Scapy if Scapy is unavailable.
    """
    try:
        from scapy.arch import get_if_list
        from scapy.interfaces import IFACES
        ifaces = []
        for name in get_if_list():
            iface    = IFACES.dev_from_name(name) if hasattr(IFACES, "dev_from_name") else None
            raw_desc = getattr(iface, "description", "") or ""
            desc     = _clean_iface_desc(name, raw_desc)
            ifaces.append({"name": name, "description": desc})
        return ifaces
    except Exception:
        ifaces = []
        try:
            with open("/proc/net/dev") as f:
                for line in f.readlines()[2:]:
                    name = line.split(":")[0].strip()
                    if name:
                        ifaces.append({"name": name,
                                       "description": _clean_iface_desc(name, "")})
        except Exception:
            pass
        return ifaces


def suggest_interface() -> str | None:
    """
    Return the most likely useful interface for OT monitoring.
    Prefers: bridge interfaces, then physical ethernet, skips loopback.
    """
    ifaces = list_interfaces()
    skip = {"lo", "docker0"}
    prefer_prefixes = ("br-", "eth", "ens", "enp", "eno")
    candidates = [i["name"] for i in ifaces if i["name"] not in skip]

    for prefix in prefer_prefixes:
        for name in candidates:
            if name.startswith(prefix):
                return name
    return candidates[0] if candidates else None


# ── Config checks ──────────────────────────────────────────────────────────────

def check_config() -> dict:
    """Return info about the active config file."""
    import yaml as _yaml
    from scrutics.config.loader import (
        get_active_user_config_path, load_builtin_rules,
        load_user_rules, load_sinks_config, load_inventory_config,
        _CUSTOM_TEMPLATE,
    )
    path         = get_active_user_config_path()
    using_default = (path == _CUSTOM_TEMPLATE)

    # First check for YAML syntax errors directly
    try:
        with open(path) as f:
            _yaml.safe_load(f)
    except _yaml.YAMLError as e:
        return {
            "path":          path,
            "using_default": using_default,
            "builtin_rules": len(load_builtin_rules()),
            "user_rules":    0,
            "sinks":         0,
            "sink_types":    [],
            "inventory":     {},
            "error":         f"YAML syntax error in {os.path.basename(path)}: {e}",
        }
    except OSError as e:
        return {
            "path":          path,
            "using_default": using_default,
            "builtin_rules": 0,
            "user_rules":    0,
            "sinks":         0,
            "sink_types":    [],
            "inventory":     {},
            "error":         f"Cannot read config file: {e}",
        }

    # Then check for semantic errors (invalid field types, missing required fields)
    try:
        builtin_rules = load_builtin_rules()
        user_rules    = load_user_rules(strict=True) if hasattr(load_user_rules, '__code__') else load_user_rules()
        sinks         = load_sinks_config()
        inv_config    = load_inventory_config()
        error         = None
    except Exception as e:
        builtin_rules = load_builtin_rules()
        user_rules    = []
        sinks         = []
        inv_config    = {}
        error         = str(e)

    return {
        "path":          path,
        "using_default": using_default,
        "builtin_rules": len(builtin_rules),
        "user_rules":    len(user_rules),
        "sinks":         len(sinks),
        "sink_types":    [s.get("type") for s in sinks],
        "inventory":     inv_config,
        "error":         error,
    }


# ── Output directory ───────────────────────────────────────────────────────────

def check_output_dir(output_dir: str = "output") -> dict:
    """Check if the output directory is writable."""
    abs_path = os.path.abspath(output_dir)
    if not os.path.exists(abs_path):
        try:
            os.makedirs(abs_path, exist_ok=True)
            return {"path": abs_path, "ok": True, "detail": "created"}
        except OSError as e:
            return {"path": abs_path, "ok": False, "detail": str(e)}
    writable = os.access(abs_path, os.W_OK)
    return {
        "path":   abs_path,
        "ok":     writable,
        "detail": "writable" if writable else "permission denied — check directory ownership",
    }


# ── OUI database check ─────────────────────────────────────────────────────────

def check_oui_db() -> dict:
    """Check active OUI database status, count, and freshness."""
    from scrutics.classifier.oui import get_oui_freshness
    try:
        info = get_oui_freshness()
        return {
            "path": info["path"],
            "db_type": info["db_type"],
            "entry_count": info["entry_count"],
            "tiers": info["tiers"],
            "age_days": info["age_days"],
            "freshness": info["freshness"],
            "sha256": info["sha256"],
            "source": info["source"],
            "source_date": info["source_date"],
            "exists": bool(info["path"]),
            "ok": True,
        }
    except Exception as e:
        return {
            "path": "",
            "db_type": "none",
            "entry_count": 0,
            "tiers": {"ma_l": 0, "ma_m": 0, "ma_s": 0},
            "age_days": 9999,
            "freshness": "Outdated",
            "sha256": "",
            "source": "none",
            "source_date": None,
            "exists": False,
            "ok": True,
            "error": str(e),
        }


# ── Full report ────────────────────────────────────────────────────────────────

def full_report(headless: bool = True, output_dir: str = "output") -> dict:
    """Collect all diagnostic data into one dict. Used by scrutics doctor."""
    return {
        "version":     VERSION,
        "python":      sys.version.split()[0],
        "platform":    platform.platform(),
        "deps":        check_all_dependencies(),
        "libpcap":     check_libpcap(),
        "interfaces":  list_interfaces(),
        "config":      check_config(),
        "output_dir":  check_output_dir(output_dir),
        "oui":         check_oui_db(),
    }


# ── Startup logging (non-doctor path) ─────────────────────────────────────────

def print_startup_info(interface: str = None, filepath: str = None,
                       output_dir: str = "output", headless: bool = True):
    """
    Print transparent startup messages so users know what was loaded.
    Called before capture begins.
    """
    cfg = check_config()
    out = check_output_dir(output_dir)

    print(f"[*] Scrutics {VERSION}")

    if cfg["error"]:
        print(f"[!] Config error: {cfg['error']}")
    else:
        src = "scrutics/config/custom_rules.yaml (default)" if cfg["using_default"] else cfg["path"]
        print(f"[*] Config       : {src}")
        print(f"[*] Rules        : {cfg['builtin_rules']} built-in, "
              f"{cfg['user_rules']} custom")
        if cfg["sinks"]:
            types = ", ".join(cfg["sink_types"])
            print(f"[*] Sinks        : {cfg['sinks']} configured ({types})")

    if interface:
        print(f"[*] Interface    : {interface}")
    if filepath:
        print(f"[*] File         : {filepath}")

    if not out["ok"]:
        print(f"[!] Output dir   : {out['path']} — {out['detail']}")
    else:
        print(f"[*] Output       : {out['path']}")

    oui_info = check_oui_db()
    if oui_info.get("exists") and oui_info.get("freshness") != "Current":
        print(f"[!] OUI database is {oui_info['age_days']} days old ({oui_info['freshness']}) — run 'scrutics oui update'")