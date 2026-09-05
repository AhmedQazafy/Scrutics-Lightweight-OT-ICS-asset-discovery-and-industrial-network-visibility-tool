# Changelog

All notable changes to Scrutics are documented here.

---

## [0.5.0] - 2026-08-30

### Added

- **Interactive topology HTML export** : force-directed graph with isolated-node side panel, drag, and zoom
- **Excel export (`.xlsx`)** : client-side download from the topology HTML with three sheets: Assets, Connections, Summary
- **Periodic checkpointing** : session data (assets, evidence, events, anomalies, topology) written every 15 seconds using atomic file replacement
- **Behavioral constraints apply from first packet** : rules with `never_initiates`, `allowed_peers`, `allowed_ports`, `alert_on_new_port`, and `max_new_peers_per_hour` fire immediately for client-only assets (no listening ports)
- **TUI checkpoint** : periodic flush in the TUI, final flush on exit. Asset table and evidence now survive checkpoints

### Fixed

- TUI refresh crash that could occur during checkpointing
- Behavioral constraints now correctly applied from contacted ports for assets without listening ports

### Changed

- `connections.csv` is now written as part of the session export
- Topology HTML uses stronger repulsion for networks >30 nodes

---

## [0.4.0] - First Public Release

### Added

- **`scrutics doctor`** : diagnostic subcommand. Checks dependencies, libpcap availability (with WSL2 detection), loaded configuration, output directory permissions, and available network interfaces. Designed to be pasted into GitHub issues for troubleshooting
- **Entry point** : `pyproject.toml` added. After `pip install -e .`, the bare `scrutics` command works without `python3 -m`
- **Interface error guidance** : when a nonexistent interface is specified, lists all available interfaces and suggests the most likely candidate
- **No-traffic warning** : if no packets are seen within 30 seconds of starting live capture, prints a warning with the exact `tcpdump` command to verify traffic
- **Startup transparency** : version, config path, rule counts, sink count, and output directory are printed at startup
- **Reload error deduplication** : repeated identical reload failures from a broken config are printed once and then suppressed
- **Interface description labels** : doctor output shows human-readable labels (loopback, Docker bridge, Docker veth)

### Changed

- **Configuration file structure simplified** : `scrutics/config/custom_rules.yaml` is now the single user-editable config file. `builtin_rules.yaml` remains read-only. `default_rules.yaml` removed
- **Config search path updated** : `~/.scrutics/scrutics.yaml` remains as an advanced machine-wide override. The previous `scrutics_rules.yaml` working-directory convention is deprecated
- **`doctor`** now always checks Textual regardless of headless mode
- **Textual version constraint** fixed : no longer specifies an upper bound that caused pip to downgrade Textual on fresh installs
- **WSL2 libpcap check** : doctor no longer incorrectly reports libpcap as missing on WSL2

### Fixed

- `--no-baseline` flag now correctly suppresses the entire anomaly detection and scoring path
- Interface error handling broadened to catch all Scapy interface-not-found variants
- Duplicate `rules:` key in `custom_rules.yaml` removed (previously caused user-defined rules to be overwritten)
- `using_template` key renamed to `using_default` consistently
- Stale references to `scrutics_rules.yaml`, `config.yaml`, and `scope_cidrs`/`allow_public` removed
- Test filenames updated to match current config file naming

---

## [0.3.0] - Phase 3: Output, SIEM, Rules

### Added

- **Real-time output** : `events.csv` and `anomalies.csv` written continuously during capture. `assets.csv` written on clean session end
- **SIEM sink integration** : forwards anomaly events in real time to syslog (JSON, CEF, LEEF, plain : UDP or TCP) and Splunk HEC. Multiple sinks can be active simultaneously. Non-blocking background queue ensures a slow SIEM never stalls packet capture
- **Behavioral rule constraints** : rules can include `never_initiates`, `allowed_peers`, `allowed_ports`, `alert_on_new_port`, and `max_new_peers_per_hour`. Violations fire immediately as `BEHAVIORAL_VIOLATION` anomalies
- **YAML rules externalized** : ICS port definitions moved to `scrutics/config/builtin_rules.yaml`. Custom rules take precedence
- **Hot reload** : file-watch polling checks `custom_rules.yaml` every 2.5 seconds. Valid changes reload without restart. Invalid YAML is rejected and the previous configuration remains active. SIGHUP supported as fallback. TUI `R` key triggers immediate reload
- **`--no-baseline` flag** : skips behavioral baseline and anomaly detection (inventory and classification only). Recommended for large PCAP files
- **Headless live enhancements** : periodic asset table printed to console every 60 seconds. `finally` block guarantees `assets.csv` is saved on Ctrl+C or SIGTERM
- **TUI Reload Rules** : `R` key and toolbar button trigger rule reload with status confirmation

### Changed

- Port directionality fixed : `ports_seen` now means listener/service ports only. Contacted destination ports tracked separately in `contacted_ports`
- Inventory scoping added : RFC1918 private addresses tracked by default. Public IPs recorded as peers only. Configurable via `cidrs` and `include_public_ips`
- Streaming `PcapReader` replaces `rdpcap()` : no memory cliff on large PCAP files
- Packet timestamps used for offline PCAP baseline analysis instead of wall-clock processing time
- Anomaly deduplication and cooldown rate limiting added
- `mac_prefix` matching bug fixed in loader

### Fixed

- Duplicate anomaly emission on Suricata alert path removed
- `get_event_buffer()` retained as compatibility shim after internal buffer rename

---

## [0.2.0] - Phase 2: Baseline and TUI

### Added

- Behavioral baseline engine: learns per-device communication patterns (peers, intervals, directionality)
- Anomaly detection: `NEW_PEER`, `DIRECTIONALITY_CHANGE`, `INTERVAL_ANOMALY`
- Multi-factor confidence scoring: OUI, protocol, behavioral, directionality
- Textual TUI with live asset table, event log, and anomaly feed
- Full keyboard navigation
- Interface selection modal
- Headless CLI mode with `--live`, `--file`, `--duration`, `--baseline` flags
- Suricata EVE JSON parser
- Zeek `conn.log` and ICS log parsers
- Docker OT simulation (Schneider, Siemens, Rockwell, BACnet)

---

## [0.1.0] : Phase 1: Foundation

### Added

- Passive packet capture via Scapy with passive enforcement layer
- MAC OUI lookup against bundled ICS vendor database
- Protocol classification : Modbus TCP, S7comm, EtherNet/IP, DNP3, BACnet/IP, OPC-UA, Niagara Fox, and common IT protocols
- Asset inventory with first/last seen timestamps
- Session CSV export : assets, events
- PCAP file analysis
- Initial unit test suite
