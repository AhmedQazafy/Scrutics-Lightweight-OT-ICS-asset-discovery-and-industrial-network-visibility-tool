# Changelog

All notable changes to Scrutics are documented here.

## [Unreleased]

### Fixed — Input Robustness
- **Faster processing of client traffic**: classification rules are loaded once and reused instead of being re-read from disk for every packet from a device without a listening service (about 30 times faster on such traffic). Behavioral constraints now follow a rule reload (`R` key, SIGHUP or the config file watcher) like the rest of classification, and an invalid edit keeps the rules in use.
- **One bad packet or log line no longer stops an analysis**: live capture, PCAP/PCAP-NG files, Zeek logs and Suricata EVE logs skip an item that cannot be processed and continue. The run summary reports how many items were rejected as malformed and how many unexpected errors were contained.
- **ARP frames with a non-IPv4 protocol address** are ignored instead of stopping processing.
- **mDNS queries with a malformed question or a name that is not valid UTF-8**: the name is ignored and the rest of the message is still used.
- **Timestamps outside the representable date range** (NaN, infinite, beyond year 9999) reject that packet or log record instead of stopping the run.

### Fixed — Processing Speed Under Scans and Floods
- **A host that contacts many addresses no longer slows processing down**: the work done for each of its packets no longer grows with the number of addresses it has already contacted.
- **A host that contacts many ports no longer slows processing down**: rule and signature lookups for its packets no longer go through every port it has contacted.
- **A host that announces many names no longer slows processing down**: mDNS names, DHCP host names and DHCP client FQDNs are looked up directly instead of being compared with every record the host already has.
- **Behavioral constraints from port rules are chosen the same way every time**: when a device without a listening service has contacted several ports whose rules set behavioral constraints, the rule of the highest such port is applied, whatever order the ports were contacted in. Before, the choice depended on internal ordering.

### Changed — Log Import Validation
- A Zeek log whose header cannot be used (an empty `#separator`, or data without a `#fields` header) is reported as a clear file error.
- Suricata EVE lines are type-checked one by one: a line that is not a JSON object, or has a field of the wrong type (for example a `dest_port` given as a string or a fraction, or a non-integer alert severity), is rejected and the rest of the file is imported.

## [0.6.1] — 2026-09-19

### Fixed — AI Reliability & Tool-Calling Protocol
- **Gemini Wire Protocol Compliance**:
  - Restored strict FunctionCall ID round-trip preservation without falling back to function names.
  - Aligned `thoughtSignature` placement to Google Gemini REST specification as a property on `Part` rather than inside `FunctionCall`, preventing HTTP 400 rejection on multi-turn tool replay.
  - Implemented `ChatResult` (inheriting from `str`) preserving opaque `thought_signature` across plain-text and tool turns without breaking string assertions or agent consumers.
  - Unified parallel tool calls into single `model` Content blocks with signature on initial call, and grouped all consecutive function responses into a single `user` Content block.
- **Model Baseline Unification**:
  - Replaced deprecated/EOL default models across all surfaces (`cli.py`, `config.py`, `gemini_provider.py`, `model_discovery.py`, setup scripts) with GA `gemini-3.8-flash`.
- **Bounded Exponential Backoff & Error Taxonomy**:
  - Implemented bounded exponential backoff with full jitter (max 4 attempts, retry on 408/429/500/502/503/504 and transient connection drops).
  - Added support for Google `google.rpc.RetryInfo.retryDelay` in string (`"30s"`) and protobuf struct formats.
  - Added sanitized logging and taxonomy mapping for Google RPC status codes (`INVALID_ARGUMENT`, `UNAUTHENTICATED`, `RESOURCE_EXHAUSTED`, `UNAVAILABLE`, etc.) guaranteeing zero leakage of API keys, prompts, IPs, or MAC addresses.
- **CI & Optional Dependency Boundary**:
  - Isolated core package from optional `requests` requirement using PEP 562 lazy loading in `scrutics.ai`.
  - Updated CI test workflow to install `.[ai]` extra ensuring end-to-end coverage.

### Added — Progressive AI Diagnostics
- **14-Stage Diagnostic Engine** (`scrutics/ai/diagnostics.py`): Progressive verification from configuration and environment to DNS, TLS, authentication, schema handling, function calling, thought signatures, round-trip replay, and full agent execution loop.
- **Diagnostics CLI**: Integrated `scrutics ai --diagnose` and `scrutics ai diagnose` command with layer-specific remediation guidance.

### Added — Retry Progress Indication
- **CLI & TUI Backoff Visibility**:
  - Thread-safe `retry_callback` in `GeminiProvider` reporting attempt number, total attempts, and resolved delay before backoff sleeps.
  - CLI `Spinner` dynamically updates to reflect retry backoff delays (`Waiting Ns before retry (attempt X of Y)...`) and in-flight retried requests (`Retrying (attempt X of Y)...`) without extra line breaks. Non-TTY invocations remain silent.
  - TUI `AIAssistantModal` status label displays real-time retry progress across worker thread boundaries.

### Known Limitations
- **Text-part signatures are now load-bearing**: With `gemini-3.8-flash` as default (GA Flash model; `gemini-2.0-flash` EOL June 2026), Gemini emits a `thoughtSignature` on the final text part of most responses. The C2 preservation path is exercised on every turn, not only tool-calling turns.
- **Live rate-limit behavior unverified against real API**: Retry logic was built against documented status codes and documented `RetryInfo` schemas. Confirmation of live 429 `RetryInfo.retryDelay` wire population requires active testing (see post-release verification list: `docs/post-release-verification-v0.6.1.md`).
- **Multi-turn REPL text-part signature loss**: Multi-turn CLI/TUI REPL sessions concatenate prior turns into a contextual prompt string; signatures attached to text parts in earlier turns are not replayed. This does not affect the agent loop's internal tool-calling rounds, which preserve signatures verbatim.
- **Default model chosen on EOL/GA status, not full cost comparison**: `gemini-3.8-flash` was selected because `gemini-2.0-flash` reached EOL. A full cost/latency comparison across the GA model tier was not performed in v0.6.1 (see Part 2 of the v0.6.1a micro-contract).

Post-release verification checklist: see `docs/post-release-verification-v0.6.1.md`.

---

## [0.6.0] — 2026-09-16

> **Unstable release.** Core features are functional and passing tests, but some
> integrations (Topology AI panel, end-to-end LLM flows) have not been validated
> in production. Gemini API compatibility may require updates.

### Added — AI Intelligence Layer
- **LLM Provider abstraction** (`scrutics/ai/`) with pluggable providers:
  Ollama (local, offline), OpenAI (gpt-4o-mini), Anthropic (claude-haiku-4-5),
  Gemini (gemini-2.0-flash). Shared HTTP layer via `_openai_compat.OpenAICompatMixin`
  for OpenAI-shaped endpoints; native translators for Anthropic and Gemini
  (`tool_use`/`tool_result` and `functionCall`/`functionResponse` respectively)
- **`thought_signature` preservation** for Gemini 3+ multi-turn function calling —
  required field otherwise causes HTTP 400 on follow-up turns
- **Semantic Tool API** (`scrutics/ai/tools.py`): `SessionContext` + 5 read-only tools
  (`get_statistics`, `get_assets`, `get_asset`, `get_connections`, `get_anomalies`)
  + OpenAI-style tool schema via `get_tool_definitions()`
- **Agent loop** (`scrutics/ai/agent.py`): `run_agent_loop()` with up to 5 tool-call
  iterations, `OT_SYSTEM_PROMPT` (anti-hallucination guardrails)
- **`scrutics ask` / `scrutics ai` CLI** with interactive REPL, session browser,
  `--provider` / `--model` overrides, `--reconfigure` / `--disable` / `--reset`
- **`scrutics list-models <provider>`** — queries provider model discovery API
- **TUI AI Assistant panel** (`AIAssistantModal` + onboarding modals) with
  background `@work(thread=True)` execution, session browser, freshness badge
- **Topology HTML AI sidebar** — BYOK client-side chat, API key in browser memory
  only, disclaimer, provider selector (Gemini / OpenAI / Anthropic)
- **WSL2 diagnostics** (`diagnose_gemini.py`) for DNS / HTTPS / API-key issues

### Added — Vendor & OUI Foundation
- **Vendor classification taxonomy** `vendor_class ∈ {OT, IT, NEUTRAL, UNKNOWN}`.
  `classification_type` remains canonical; `is_ot` is now a derived property.
  Cisco reclassified from OT to IT
- **IEEE MA-L / MA-M / MA-S prefix support** with longest-prefix matching
  (9→7→6 hex nibbles). Universal MAC normalization (colon/hyphen/dot/case)
- **Passive DHCPv4 enrichment** — options 12 (hostname), 55 (fingerprint),
  60 (vendor class, two-layer evidence), 81 (FQDN, E-bit aware). Client identity
  via `BOOTP.chaddr`. Bounded pending buffer (1,000 entries) with FIFO eviction
- **Curated OUI metadata** (`curated_oui.yaml`, 30 industrial prefixes) with
  `device_family_hint` as low-weight `os_hint` evidence. User override via
  `~/.scrutics/curated_oui.yaml`
- **OUI lifecycle commands** — `scrutics oui status|validate|update|import`.
  Atomic install with `.bak` rollback; SHA-256 checksum; MA-L/M/S tier counts.
  Freshness policy < 180d / 180–364d / ≥ 365d. Doctor + startup warnings
  (non-blocking)

### Added — Identity & Topology
- **MAC-based primary asset identity** with IP fallback. `Asset.primary_key`,
  `Asset.ip_history` chronological episodes
- **`AssetInventory.get_or_create()`** with 5-branch resolution: known MAC,
  MAC-change (creates separate Asset), MAC-less, learning MAC, brand new
- **`DEVICE_MOVED` (MEDIUM) and `MAC_CHANGED` (HIGH) anomalies**
- **Asset-centric topology edges** keyed by `primary_key`

### Added — Evidence Package v1
- **`manifest.json`** in every session directory via `write_manifest()` /
  `read_manifest()`. Atomic write, required-field validation, graceful defaults

### Changed
- `Asset.is_ot` converted from stored field to derived property (with setter
  for backward compat)
- `chat()` return type: `str | Iterator[str]` → `ChatResult | Iterator[str]`
  to support tool-call responses
- Default Ollama timeout 30s → 180s (real CPU-inference turns measured at 53s+)
- `valid_efforts` set: added `"max"`
- Default model: `gemini-2.0-flash`
- `fetch_models()` no longer silently falls back; returns empty list on failure
- Cisco reclassified from `vendor_class=OT` to `IT`
- `classification_type` now has 4 values: `OT | IT | Infrastructure | Unknown`

### Fixed
- `KeyboardInterrupt` during `scrutics ask` no longer produces raw traceback
- Gemini 3+ function-calling HTTP 400 (`thought_signature` preservation)
- TUI onboarding modal no longer dismisses mid-fetch
- `AIModelSelectionModal` now centered
- DHCP `chaddr` used for client identity (not Ethernet `src_mac`)
- OUI parser handles dotted MACs and non-string input safely
- 8-second timeout on TUI error notifications (was instant-dismiss)

### Known Issues
- Topology AI panel button may not respond to click in some browsers
- Interactive `scrutics ai` end-to-end flow not fully tested with valid API key
- Gemini API may require model name updates as Google releases new versions
- `Asset.add_evidence()` still calls `_update_classification_type()` on every
  evidence addition (Phase 1 observation, deferred)
- Session directory naming uses local time, not UTC

### Deferred to v0.7+
- Firmware active querying (`--query-firmware`)
- True LLM-backed topology sidebar (requires local HTTP server)
- Multi-turn CLI chat persistence
- Streaming for Anthropic / Gemini providers
- Software self-update (`scrutics update`)
- Phase C (Modbus DPI), D (behavioral), E (baselines), F (Purdue), G (protocols)
- ML anomaly detection
- Fixes for already documented bugs

### Tests
- 245 → 299 passing, 0 failures
- New test files: `test_tier2_asset_identity.py`, `test_tier2_topology.py`,
  `test_ai_agent.py`, `test_ai_provider.py`, `test_cli_ask.py`, `test_cli_ask_ux.py`,
  `test_phase6_providers.py`, `test_tui_ai_assistant.py`, `test_phase_b1_vendor.py`,
  `test_phase_b2_oui.py`, `test_phase_b3_dhcp.py`, `test_phase_b4_b5_oui.py`

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
