"""
OUI (Organizationally Unique Identifier) lookup.
Maps the first 3 bytes of a MAC address to a vendor name.

Load priority:
  1. Full IEEE OUI database (oui.txt) if present alongside this file
     → run scripts/download_oui.py to fetch it (requires internet)
  2. Bundled ICS vendor database (ics_oui.txt) — always present in repo
     → covers all major OT/ICS vendors for air-gapped deployments

This tool is designed for OT environments that may have no internet access.
The bundled database covers vendor identification without any outbound connection.
"""

import os
import json
import re
import datetime
import hashlib
import shutil

# Paths
_DIR = os.path.dirname(__file__)
OUI_USER_DIR             = os.path.join(os.path.expanduser("~"), ".scrutics")
OUI_USER_PATH            = os.path.join(OUI_USER_DIR, "oui.txt")
OUI_USER_BAK_PATH        = os.path.join(OUI_USER_DIR, "oui.txt.bak")
OUI_META_PATH            = os.path.join(OUI_USER_DIR, "oui_meta.json")
OUI_FULL_PATH            = os.path.join(_DIR, "oui.txt")       # local repo IEEE db
OUI_BUNDLED_PATH         = os.path.join(_DIR, "ics_oui.txt")   # bundled ICS db (always present)
CURATED_OUI_BUNDLED_PATH = os.path.join(_DIR, "curated_oui.yaml")
CURATED_OUI_USER_PATH    = os.path.join(OUI_USER_DIR, "curated_oui.yaml")
IEEE_OUI_URL             = "https://standards-oui.ieee.org/oui/oui.txt"

# Freshness classification constants
FRESHNESS_CURRENT  = "Current"
FRESHNESS_AGING    = "Aging"
FRESHNESS_OUTDATED = "Outdated"

# Vendor classification constants
VENDOR_CLASS_OT = "OT"
VENDOR_CLASS_IT = "IT"
VENDOR_CLASS_NEUTRAL = "NEUTRAL"
VENDOR_CLASS_UNKNOWN = "UNKNOWN"

# Authoritative mapping of vendor substring patterns to vendor classes.
# Vendor classification is an evidence input, not the final asset classification.
VENDOR_CLASS_MAPPING = {
    # Pure OT / Industrial Automation
    "siemens": VENDOR_CLASS_OT,
    "schneider": VENDOR_CLASS_OT,
    "rockwell": VENDOR_CLASS_OT,
    "allen-bradley": VENDOR_CLASS_OT,
    "moxa": VENDOR_CLASS_OT,
    "phoenix contact": VENDOR_CLASS_OT,
    "beckhoff": VENDOR_CLASS_OT,
    "advantech": VENDOR_CLASS_OT,
    "wago": VENDOR_CLASS_OT,
    "hilscher": VENDOR_CLASS_OT,
    "prosoft": VENDOR_CLASS_OT,
    "red lion": VENDOR_CLASS_OT,
    "kepware": VENDOR_CLASS_OT,
    "opto 22": VENDOR_CLASS_OT,
    "b&r": VENDOR_CLASS_OT,
    "pilz": VENDOR_CLASS_OT,
    "sick": VENDOR_CLASS_OT,
    "turck": VENDOR_CLASS_OT,
    "murrelektronik": VENDOR_CLASS_OT,
    "eaton": VENDOR_CLASS_OT,
    "abb": VENDOR_CLASS_OT,
    "honeywell": VENDOR_CLASS_OT,
    "emerson": VENDOR_CLASS_OT,
    "yokogawa": VENDOR_CLASS_OT,
    "ge": VENDOR_CLASS_OT,
    "mitsubishi": VENDOR_CLASS_OT,
    "omron": VENDOR_CLASS_OT,
    "delta": VENDOR_CLASS_OT,
    "invensys": VENDOR_CLASS_OT,
    "foxboro": VENDOR_CLASS_OT,
    "endress": VENDOR_CLASS_OT,
    "ifm": VENDOR_CLASS_OT,
    "pepperl": VENDOR_CLASS_OT,
    "contemporary controls": VENDOR_CLASS_OT,

    # Neutral / Dual-use / Industrial Network Infrastructure
    "belden": VENDOR_CLASS_NEUTRAL,
    "hirschmann": VENDOR_CLASS_NEUTRAL,
    "lantronix": VENDOR_CLASS_NEUTRAL,
    "digi international": VENDOR_CLASS_NEUTRAL,

    # IT / Enterprise Networking / Computing
    # Cisco is classified as IT/networking signal, not OT.
    "cisco": VENDOR_CLASS_IT,
    "dell": VENDOR_CLASS_IT,
    "hp": VENDOR_CLASS_IT,
    "hewlett packard": VENDOR_CLASS_IT,
    "apple": VENDOR_CLASS_IT,
    "intel": VENDOR_CLASS_IT,
    "lenovo": VENDOR_CLASS_IT,
    "microsoft": VENDOR_CLASS_IT,
    "vmware": VENDOR_CLASS_IT,
    "supermicro": VENDOR_CLASS_IT,
}

# Backward compatibility set of OT vendors (frozenset)
OT_VENDORS = frozenset(k for k, v in VENDOR_CLASS_MAPPING.items() if v == VENDOR_CLASS_OT)


def _parse_oui_file(path: str) -> dict:
    """
    Parse an IEEE-format OUI text file into { 'PREFIX': 'Vendor Name' }.

    Supports IEEE allocation tiers:
      - MA-L (24-bit): 6 hexadecimal nibbles (e.g. 00-50-C2)
      - MA-M (28-bit): 7 hexadecimal nibbles (e.g. AA-BB-CC-D)
      - MA-S (36-bit): 9 hexadecimal nibbles (e.g. AA-BB-CC-DD-E)

    Keys are stored normalized: uppercase, hexadecimal, no separators, exactly
    6, 7, or 9 characters.

    Duplicate prefixes: If the same normalized prefix appears more than once,
    the last occurrence wins (standard dictionary assignment).

    Malformed lines (missing '(hex)', non-hex characters, prefix length not in
    {6, 7, 9}, or empty vendor) are skipped safely without raising exceptions.
    """
    oui_map = {}
    if not os.path.exists(path):
        return oui_map

    HEX_DIGITS = frozenset("0123456789ABCDEF")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" not in line:
                continue
            parts = line.split("(hex)", 1)
            if len(parts) != 2:
                continue
            # Remove separators (hyphen, colon, period, tab, space)
            raw_prefix = (
                parts[0]
                .strip()
                .replace("-", "")
                .replace(":", "")
                .replace(".", "")
                .replace(" ", "")
                .replace("\t", "")
                .upper()
            )
            if len(raw_prefix) not in (6, 7, 9):
                continue
            if not all(c in HEX_DIGITS for c in raw_prefix):
                continue
            vendor = parts[1].strip()
            if not vendor:
                continue
            # Last occurrence wins
            oui_map[raw_prefix] = vendor
    return oui_map


def get_active_oui_path() -> tuple[str, str]:
    """
    Return (path, source_type) for the highest-priority available OUI database.
    Precedence:
      1. ~/.scrutics/oui.txt  ('user-updated')
      2. scrutics/classifier/oui.txt  ('local')
      3. scrutics/classifier/ics_oui.txt  ('bundled')
      4. ('', 'none')
    """
    if os.path.exists(OUI_USER_PATH):
        return OUI_USER_PATH, "user-updated"
    if os.path.exists(OUI_FULL_PATH):
        return OUI_FULL_PATH, "local"
    if os.path.exists(OUI_BUNDLED_PATH):
        return OUI_BUNDLED_PATH, "bundled"
    return "", "none"


def load_oui_db(verbose: bool = True) -> dict:
    """
    Load OUI database.
    Resolution order:
      1. User-updated ~/.scrutics/oui.txt (full IEEE database installed by operator)
      2. Local repository oui.txt (downloaded during development)
      3. Bundled ICS vendor database ics_oui.txt (always present)
    Never attempts a network download.
    """
    path, db_type = get_active_oui_path()
    if path:
        if verbose:
            label_map = {
                "user-updated": "user OUI database from",
                "local": "full OUI database from",
                "bundled": "bundled ICS OUI database from",
            }
            label = label_map.get(db_type, "OUI database from")
            print(f"[*] Loading {label} {path}")
        return _parse_oui_file(path)

    if verbose:
        print("[!] No OUI database found. Run 'scrutics oui update' to fetch the database.")
        print("[!] Falling back to empty OUI map — vendor lookup will return 'Unknown'.")
    return {}


def lookup_vendor(mac: str, oui_db: dict) -> str:
    """
    Look up vendor for a MAC address using longest-prefix matching.

    OUI lookup identifies the IEEE assignment holder for the MAC prefix. The
    assignment holder may be a chipset manufacturer, module manufacturer,
    contract manufacturer, or other registered entity and is not necessarily the
    product/vendor brand of the actual OT/ICS device. Therefore, OUI is a
    supporting, low-confidence identification signal — not definitive product
    identification.

    Accepts common MAC representations:
      - Colon-separated: 00:50:C2:00:0A:BB
      - Hyphen-separated: 00-50-C2-00-0A-BB
      - Dotted: 0050.C200.0ABB
      - Lowercase or mixed case

    Performs longest-prefix matching in order:
      MA-S (9 chars) -> MA-M (7 chars) -> MA-L (6 chars)

    Returns vendor string or 'Unknown'. Inputs shorter than 6 hexadecimal
    characters or malformed inputs safely return 'Unknown' without raising.
    """
    if not mac or not isinstance(mac, str):
        return "Unknown"

    # Normalize MAC: strip colons, hyphens, periods, whitespace, tabs, uppercase
    normalized = (
        mac.strip()
        .replace(":", "")
        .replace("-", "")
        .replace(".", "")
        .replace(" ", "")
        .replace("\t", "")
        .upper()
    )

    HEX_DIGITS = frozenset("0123456789ABCDEF")
    if len(normalized) < 6 or not all(c in HEX_DIGITS for c in normalized):
        return "Unknown"

    # Longest prefix match: 9 (MA-S) -> 7 (MA-M) -> 6 (MA-L)
    for length in (9, 7, 6):
        if len(normalized) >= length:
            prefix = normalized[:length]
            if prefix in oui_db:
                return oui_db[prefix]

    return "Unknown"


def classify_vendor(vendor: str | None) -> str:
    """
    Determine vendor classification ('OT', 'IT', 'NEUTRAL', 'UNKNOWN') from vendor string.
    Authoritative mechanism for determining vendor class from a vendor identity.
    Vendor classification is an evidence input, NOT the final asset classification.
    """
    if not vendor or not vendor.strip() or vendor.strip().lower() == "unknown":
        return VENDOR_CLASS_UNKNOWN

    vendor_lower = vendor.strip().lower()
    for pattern, vclass in VENDOR_CLASS_MAPPING.items():
        if pattern in vendor_lower:
            return vclass

    return VENDOR_CLASS_UNKNOWN


def is_ot_vendor(vendor: str) -> bool:
    """
    Backward-compatible helper. Returns True if vendor is classified as OT.
    """
    return classify_vendor(vendor) == VENDOR_CLASS_OT


# ── Curated OUI Metadata ───────────────────────────────────────────────────────

_CURATED_OUI_CACHE: dict | None = None


def load_curated_oui_metadata(force_reload: bool = False) -> dict:
    """
    Load curated OUI metadata.
    Resolution order:
      1. Loads bundled curated_oui.yaml.
      2. Overlays user-local ~/.scrutics/curated_oui.yaml if present (per-prefix override).
    Returns mapping of normalized prefix (upper hex, 6/7/9 chars) -> dict of metadata.
    """
    global _CURATED_OUI_CACHE
    if _CURATED_OUI_CACHE is not None and not force_reload:
        return _CURATED_OUI_CACHE

    import yaml
    HEX_DIGITS = frozenset("0123456789ABCDEF")
    merged: dict[str, dict] = {}

    def _load_yaml(path: str) -> dict:
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = yaml.safe_load(f)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    # 1. Bundled metadata
    bundled_data = _load_yaml(CURATED_OUI_BUNDLED_PATH)
    for k, v in bundled_data.items():
        norm_k = (
            str(k)
            .strip()
            .replace("-", "")
            .replace(":", "")
            .replace(".", "")
            .replace(" ", "")
            .upper()
        )
        if len(norm_k) in (6, 7, 9) and all(c in HEX_DIGITS for c in norm_k) and isinstance(v, dict):
            merged[norm_k] = v

    # 2. User-local overrides (overrides bundled on per-prefix basis)
    user_data = _load_yaml(CURATED_OUI_USER_PATH)
    for k, v in user_data.items():
        norm_k = (
            str(k)
            .strip()
            .replace("-", "")
            .replace(":", "")
            .replace(".", "")
            .replace(" ", "")
            .upper()
        )
        if len(norm_k) in (6, 7, 9) and all(c in HEX_DIGITS for c in norm_k) and isinstance(v, dict):
            merged[norm_k] = v

    _CURATED_OUI_CACHE = merged
    return merged


def lookup_oui_metadata(prefix_or_mac: str, curated_meta: dict | None = None) -> dict | None:
    """
    Look up curated device family metadata for a MAC address or prefix.

    OUI device family hint is supporting identification evidence (os_hint).
    It NEVER independently establishes or overwrites classification_type.

    Accepts full MAC address (colon, hyphen, dotted, or unseparated) or prefix.
    Performs longest-prefix matching in order:
      MA-S (9 chars) -> MA-M (7 chars) -> MA-L (6 chars)

    Returns copy of metadata dict (e.g. {'device_family_hint': '...', ...}) or None.
    """
    if not prefix_or_mac or not isinstance(prefix_or_mac, str):
        return None

    norm = (
        prefix_or_mac.strip()
        .replace(":", "")
        .replace("-", "")
        .replace(".", "")
        .replace(" ", "")
        .replace("\t", "")
        .upper()
    )
    HEX_DIGITS = frozenset("0123456789ABCDEF")
    if len(norm) < 6 or not all(c in HEX_DIGITS for c in norm):
        return None

    if curated_meta is None:
        curated_meta = load_curated_oui_metadata()

    for length in (9, 7, 6):
        if len(norm) >= length:
            prefix = norm[:length]
            if prefix in curated_meta:
                return dict(curated_meta[prefix])

    return None


# ── OUI Database Lifecycle & Validation ────────────────────────────────────────

def validate_oui_file(path: str) -> dict:
    """
    Validate an IEEE-format OUI text file and compute structural stats.
    Returns:
      {
          'valid': bool,
          'entry_count': int,
          'tiers': {'ma_l': int, 'ma_m': int, 'ma_s': int},
          'malformed_count': int,
          'total_lines': int,
          'sha256': str,
          'error': str | None,
      }
    """
    if not path or not os.path.exists(path):
        return {
            "valid": False,
            "entry_count": 0,
            "tiers": {"ma_l": 0, "ma_m": 0, "ma_s": 0},
            "malformed_count": 0,
            "total_lines": 0,
            "sha256": "",
            "error": f"File does not exist: {path}",
        }

    HEX_DIGITS = frozenset("0123456789ABCDEF")
    h = hashlib.sha256()
    total_lines = 0
    malformed_count = 0
    tiers = {"ma_l": 0, "ma_m": 0, "ma_s": 0}
    seen_prefixes = set()

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                total_lines += 1
                h.update(line.encode("utf-8", errors="ignore"))
                if "(hex)" not in line:
                    continue
                parts = line.split("(hex)", 1)
                if len(parts) != 2:
                    malformed_count += 1
                    continue
                raw_prefix = (
                    parts[0]
                    .strip()
                    .replace("-", "")
                    .replace(":", "")
                    .replace(".", "")
                    .replace(" ", "")
                    .replace("\t", "")
                    .upper()
                )
                vendor = parts[1].strip()
                if len(raw_prefix) not in (6, 7, 9) or not all(c in HEX_DIGITS for c in raw_prefix) or not vendor:
                    malformed_count += 1
                    continue

                if raw_prefix not in seen_prefixes:
                    seen_prefixes.add(raw_prefix)
                    if len(raw_prefix) == 6:
                        tiers["ma_l"] += 1
                    elif len(raw_prefix) == 7:
                        tiers["ma_m"] += 1
                    elif len(raw_prefix) == 9:
                        tiers["ma_s"] += 1

        entry_count = len(seen_prefixes)
        return {
            "valid": entry_count > 0,
            "entry_count": entry_count,
            "tiers": tiers,
            "malformed_count": malformed_count,
            "total_lines": total_lines,
            "sha256": h.hexdigest(),
            "error": None if entry_count > 0 else "File contains no valid OUI entries",
        }
    except Exception as e:
        return {
            "valid": False,
            "entry_count": 0,
            "tiers": {"ma_l": 0, "ma_m": 0, "ma_s": 0},
            "malformed_count": 0,
            "total_lines": total_lines,
            "sha256": h.hexdigest(),
            "error": str(e),
        }


def read_oui_meta() -> dict | None:
    """Read ~/.scrutics/oui_meta.json if present."""
    if not os.path.exists(OUI_META_PATH):
        return None
    try:
        with open(OUI_META_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def write_oui_meta(source: str, entry_count: int, tiers: dict, sha256: str,
                   source_date: str | None = None) -> bool:
    """Write ~/.scrutics/oui_meta.json atomically."""
    try:
        os.makedirs(OUI_USER_DIR, exist_ok=True)
        meta = {
            "source": source,
            "source_date": source_date,
            "local_update_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "entry_count": entry_count,
            "tiers": tiers,
            "sha256": sha256,
            "format_version": 1,
        }
        tmp_meta = os.path.join(OUI_USER_DIR, f"oui_meta.json.tmp.{os.getpid()}")
        with open(tmp_meta, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        os.replace(tmp_meta, OUI_META_PATH)
        return True
    except Exception:
        return False


def get_oui_freshness(now: datetime.datetime | None = None) -> dict:
    """
    Calculate freshness of the active OUI database.
    Freshness policy:
      - age < 180 days: Current (✓)
      - 180 <= age < 365 days: Aging (⚠)
      - age >= 365 days: Outdated (⚠)
    """
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)

    path, db_type = get_active_oui_path()
    if not path:
        return {
            "path": "",
            "db_type": "none",
            "entry_count": 0,
            "tiers": {"ma_l": 0, "ma_m": 0, "ma_s": 0},
            "sha256": "",
            "source": "none",
            "source_date": None,
            "local_update_time": None,
            "age_days": 9999,
            "freshness": FRESHNESS_OUTDATED,
        }

    val = validate_oui_file(path)
    meta = read_oui_meta() if db_type == "user-updated" else None

    source = "bundled" if db_type == "bundled" else ("local" if db_type == "local" else "user-updated")
    source_date = None
    local_update_time = None

    if meta:
        source = meta.get("source", source)
        source_date = meta.get("source_date")
        local_update_time = meta.get("local_update_time")

    age_days = None
    if source_date:
        try:
            sd = datetime.datetime.strptime(str(source_date)[:10], "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
            age_days = (now - sd).days
        except Exception:
            pass

    if age_days is None and local_update_time:
        try:
            ut = datetime.datetime.fromisoformat(local_update_time)
            if ut.tzinfo is None:
                ut = ut.replace(tzinfo=datetime.timezone.utc)
            age_days = (now - ut).days
        except Exception:
            pass

    if age_days is None:
        if db_type == "bundled":
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for _ in range(10):
                        line = f.readline()
                        if "last updated:" in line.lower():
                            m = re.search(r"(\d{4}(?:-\d{2}-\d{2})?)", line)
                            if m:
                                d_str = m.group(1)
                                if len(d_str) == 4:
                                    d_str += "-01-01"
                                bd = datetime.datetime.strptime(d_str, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
                                age_days = (now - bd).days
                                source_date = d_str
                                break
            except Exception:
                pass
            if age_days is None:
                bd = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
                age_days = (now - bd).days
                source_date = "2025-01-01"
        else:
            try:
                mtime = os.path.getmtime(path)
                mt = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc)
                age_days = (now - mt).days
                source_date = mt.strftime("%Y-%m-%d")
            except Exception:
                age_days = 9999

    age_days = max(0, int(age_days))
    if age_days < 180:
        freshness = FRESHNESS_CURRENT
    elif age_days < 365:
        freshness = FRESHNESS_AGING
    else:
        freshness = FRESHNESS_OUTDATED

    return {
        "path": path,
        "db_type": db_type,
        "entry_count": val["entry_count"],
        "tiers": val["tiers"],
        "sha256": val["sha256"],
        "source": source,
        "source_date": source_date,
        "local_update_time": local_update_time,
        "age_days": age_days,
        "freshness": freshness,
    }


def install_oui_database(source_data_or_file: str | bytes, source_type: str,
                         source_date: str | None = None, min_entries: int = 1) -> tuple[bool, str, dict | None]:
    """
    Atomically install an OUI database to ~/.scrutics/oui.txt with .bak backup.
    Returns (success, message, validation_report).
    """
    temp_path = None
    try:
        os.makedirs(OUI_USER_DIR, exist_ok=True)
        temp_path = os.path.join(OUI_USER_DIR, f"oui.txt.tmp.{os.getpid()}")

        if isinstance(source_data_or_file, bytes):
            with open(temp_path, "wb") as f:
                f.write(source_data_or_file)
        elif isinstance(source_data_or_file, str) and os.path.isfile(source_data_or_file):
            shutil.copyfile(source_data_or_file, temp_path)
        elif isinstance(source_data_or_file, str):
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(source_data_or_file)
        else:
            return False, "Invalid source data", None

        val = validate_oui_file(temp_path)
        if not val["valid"]:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False, f"Validation failed: {val.get('error') or 'no valid entries'}", val

        if val["entry_count"] < min_entries:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False, f"Validation failed: found {val['entry_count']} entries (expected at least {min_entries})", val

        # Backup current user db if present
        if os.path.exists(OUI_USER_PATH):
            shutil.copyfile(OUI_USER_PATH, OUI_USER_BAK_PATH)

        # Atomic replace
        os.replace(temp_path, OUI_USER_PATH)

        # Update metadata
        write_oui_meta(
            source=source_type,
            entry_count=val["entry_count"],
            tiers=val["tiers"],
            sha256=val["sha256"],
            source_date=source_date,
        )

        return True, f"Successfully installed OUI database ({val['entry_count']:,} entries)", val

    except Exception as e:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        # Rollback if OUI_USER_PATH missing and backup exists
        if not os.path.exists(OUI_USER_PATH) and os.path.exists(OUI_USER_BAK_PATH):
            try:
                shutil.copyfile(OUI_USER_BAK_PATH, OUI_USER_PATH)
            except OSError:
                pass
        return False, f"Installation error: {e}", None


def download_ieee_oui(url: str = IEEE_OUI_URL, timeout: int = 30) -> tuple[bool, str, dict | None]:
    """
    Download IEEE OUI database from URL and install to ~/.scrutics/oui.txt.
    Network access is ONLY made when this function is explicitly invoked.
    """
    import urllib.request
    import urllib.error
    from email.utils import parsedate_to_datetime

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Scrutics/v0.5.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = response.read()
            last_mod = response.headers.get("Last-Modified")
            source_date = None
            if last_mod:
                try:
                    dt = parsedate_to_datetime(last_mod)
                    source_date = dt.strftime("%Y-%m-%d")
                except Exception:
                    pass

        return install_oui_database(
            source_data_or_file=data,
            source_type=url,
            source_date=source_date,
            min_entries=1000,
        )
    except urllib.error.URLError as e:
        return False, f"Network error downloading OUI database: {e}", None
    except Exception as e:
        return False, f"Error updating OUI database: {e}", None


def import_oui_file(filepath: str) -> tuple[bool, str, dict | None]:
    """
    Import an offline OUI database file into ~/.scrutics/oui.txt.
    Zero network calls.
    """
    if not os.path.exists(filepath):
        return False, f"Source file not found: {filepath}", None

    return install_oui_database(
        source_data_or_file=filepath,
        source_type=f"file:{os.path.abspath(filepath)}",
        min_entries=1,
    )
