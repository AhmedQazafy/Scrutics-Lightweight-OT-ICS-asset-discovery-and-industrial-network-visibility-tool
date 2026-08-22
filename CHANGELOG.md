# Changelog

All notable changes to Scrutics are documented here.

---

## [0.4.0] — First Public Release

### Added

**scrutics doctor** — new diagnostic subcommand. Checks all dependencies, libpcap availability (with WSL2 detection), loaded configuration, output directory permissions, and available network interfaces. Designed to be pasted into GitHub issues for troubleshooting.

**Entry point** — `pyproject.toml` added. After `pip install -e .`, the bare `scrutics` command works without `python3 -m`.

**Interface error guidance** — when a nonexistent interface is specified, Scrutics now lists all available interfaces and suggests the most likely candidate based on interface naming heuristics.

**No-traffic warning** — if no packets are seen within 30 seconds of starting live capture, Scrutics prints a warning with the exact `tcpdump` command to verify whether traffic is present on the interface.

**Startup transparency** — version, config path, rule counts, sink count, and output directory are printed at startup so users know exactly what was loaded.

**Reload error deduplication** — if a broken config file causes repeated reload failures (e.g. from an editor that saves twice), the error is printed once and suppressed for identical subsequent failures.

**Interface description labels** — interfaces in doctor output now show human-readable labels (loopback, Docker bridge, Docker veth) instead of repeating the interface name.

### Changed

**Configuration file structure simplified** — `scrutics/config/custom_rules.yaml` is now the single user-editable config file. Users edit it directly in the repository — no copy, rename, or working directory file required. `scrutics/config/builtin_rules.yaml` remains read-only. `default_rules.yaml` removed (was unused).

**Config search path updated** — `~/.scrutics/scrutics.yaml` remains as an advanced machine-wide override. The previous `scrutics_rules.yaml` working directory convention is deprecated.

**doctor** now always checks textual regardless of headless mode — ensures TUI dependency issues are caught and reported even when running without a terminal.

**textual version constraint** fixed — `pyproject.toml` no longer specifies an upper bound that caused pip to downgrade textual on fresh installs.

**WSL2 libpcap check** — doctor no longer incorrectly reports libpcap as missing on WSL2, where Scapy uses AF_PACKET directly.

### Fixed

- `--no-baseline` flag now correctly suppresses the entire anomaly detection and scoring path, not just the baseline observe call
- Interface error handling broadened to catch all Scapy interface-not-found error variants regardless of exact wording
- `custom_rules.yaml` duplicate `rules:` key removed — previously caused user-defined rules to be silently overwritten by the empty default
- `using_template` key renamed to `using_default` consistently across diagnostics and CLI
- Stale references to `scrutics_rules.yaml`, `config.yaml`, and `scope_cidrs`/`allow_public` removed from all files
- Test filenames updated to match current config file naming

---

## [0.3.0] — Phase 3: Output, SIEM, Rules

### Added

**Real-time output** — `events.csv` and `anomalies.csv` are written continuously during capture via `RollingWriter`. Data is never lost to a crash or unexpected exit. `assets.csv` is written on clean session end.

**SIEM sink integration** — `SinkManager` forwards anomaly events in real time to syslog (JSON, CEF, LEEF, plain — UDP or TCP) and Splunk HEC. Multiple sinks active simultaneously. Non-blocking background queue ensures a slow SIEM never stalls packet capture.

**Behavioral rule constraints** — rules in `custom_rules.yaml` can now include `never_initiates`, `allowed_peers`, `allowed_ports`, `alert_on_new_port`, and `max_new_peers_per_hour`. Violations fire immediately as `BEHAVIORAL_VIOLATION` anomalies (severity HIGH), independent of the baseline window.

**YAML rules externalized** — ICS port definitions moved from hardcoded Python to `scrutics/config/builtin_rules.yaml`. Hardcoded dict retained as fallback. Custom rules take precedence over built-in rules.

**Hot reload** — file-watch polling checks `custom_rules.yaml` every 2.5 seconds. Valid changes reload rules and sinks without restarting. Invalid YAML is rejected and the previous configuration remains active. SIGHUP supported as fallback on Linux. TUI `R` key triggers immediate reload.

**`--no-baseline` flag** — skips behavioral baseline and anomaly detection. Inventory and classification only. Recommended for large PCAP files.

**Headless live enhancements** — periodic asset table printed to console every 60 seconds. `finally` block guarantees `assets.csv` is saved on Ctrl+C or SIGTERM. ASCII spinner shown during file analysis.

**TUI Reload Rules button** — `R` key and toolbar button trigger rule reload. Green status bar confirmation on success. Errors shown inline.

### Changed

- Port directionality fixed — `ports_seen` now means listener/service ports only. Contacted destination ports tracked separately in `contacted_ports`. Classification uses listener ports only.
- Inventory scoping added — RFC1918 private addresses tracked by default. Public IPs recorded as peers only. Configurable via `cidrs` and `include_public_ips`.
- Streaming `PcapReader` replaces `rdpcap()` — no memory cliff on large PCAP files.
- Packet timestamps used for offline PCAP baseline analysis instead of wall-clock processing time.
- Anomaly deduplication and cooldown rate limiting — `NEW_PEER` fires once per peer, `DIRECTIONALITY_CHANGE` has 300s cooldown, `INTERVAL_ANOMALY` has 60s cooldown.
- `mac_prefix` matching bug fixed in loader.

### Fixed

- Duplicate anomaly emission on Suricata alert path removed
- `get_event_buffer()` retained as compatibility shim after `_event_buffer` removal

---

## [0.2.0] — Phase 2: Baseline and TUI

### Added

- Behavioral baseline engine — learns per-device communication patterns (peers, intervals, directionality)
- Anomaly detection — NEW_PEER, DIRECTIONALITY_CHANGE, INTERVAL_ANOMALY
- Multi-factor confidence scoring — OUI, protocol, behavioral, directionality
- Textual TUI with live asset table, event log, and anomaly feed
- Full keyboard navigation (custom panel routing, not Textual default Tab chain)
- Interface selection modal with ChoiceField
- Headless CLI mode with `--live`, `--file`, `--duration`, `--baseline` flags
- Suricata EVE JSON parser — alert events imported as anomalies
- Zeek conn.log and ICS log parsers
- Docker OT simulation — Schneider, Siemens, Rockwell, and BACnet containers

---

## [0.1.0] — Phase 1: Foundation

### Added

- Passive packet capture via Scapy with passive enforcement layer
- MAC OUI lookup against bundled ICS vendor database
- Protocol classification — Modbus TCP, S7comm, EtherNet/IP, DNP3, BACnet/IP, OPC-UA, Niagara Fox, and IT protocols
- Asset inventory with first/last seen timestamps
- Session CSV export — assets, events
- PCAP file analysis
- 18 unit tests
