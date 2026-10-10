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
- **A device with a new-peer rate limit (`max_new_peers_per_hour`) that contacts many addresses no longer slows processing down**: counting its recent new peers no longer goes through its whole peer history.
- **A host that contacts many ports no longer slows processing down**: rule and signature lookups for its packets no longer go through every port it has contacted.
- **A host that announces many names no longer slows processing down**: mDNS names, DHCP host names and DHCP client FQDNs are looked up directly instead of being compared with every record the host already has.
- **Behavioral constraints from port rules are chosen the same way every time**: when a device without a listening service has contacted several ports whose rules set behavioral constraints, the rule of the highest such port is applied, whatever order the ports were contacted in. Before, the choice depended on internal ordering.

### Fixed — Bounded Memory Per Device
- **A device that announces many names or identifiers no longer grows without limit**: each kind of evidence keeps the first 64 distinct values seen for a device (for example mDNS names, DHCP host names, DHCP vendor class identifiers), and the DNS name list keeps the first 64 names. Further values are counted instead of stored. A value already kept is still recorded from additional sources. A saved session loads with the same limits.
- **A host that contacts very many addresses no longer grows without limit**: a device keeps its first 4096 peer addresses, and the same limit applies to the first-contact times kept for `max_new_peers_per_hour`. `peer_count` is the number of peers kept. Once a device has 4096 peers, a further new peer is not reported as a new peer by the behavioral baseline and is not counted toward its new-peer rate; it still appears in the topology. Every refused addition is counted, repeats included.
- **A device that keeps changing IP address no longer grows without limit**: its IP history keeps the most recent 256 address changes, and older entries are counted as dropped. Returning to a forgotten address gives the same behavioral results as before.
- **Repeat-alert suppression no longer keeps an entry forever for every peer, port or MAC/IP pair alerted on**: each entry is forgotten once its cooldown has passed by a margin of one more cooldown (`MAC_CHANGED`, `DEVICE_MOVED` and behavioral-constraint violations). Alerts are unchanged for traffic in time order. For input out of time order (for example merged captures), a packet more than one cooldown older than the newest one seen can raise an alert that an older run would have suppressed, at most once per cooldown for each alert key. The set of known ports for `alert_on_new_port` is kept for the whole run as before.

### Added — Per-Device Limit Reporting
- **Entries not kept because of a per-device limit are reported, never silently dropped**: `assets.csv` gains the columns `ip_history_dropped`, `evidence_overflow` (with a per-type breakdown in `evidence_overflow_by_type`, for example `hostname:6|dns:2`), `dns_names_overflow`, `peer_additions_rejected` and `peer_first_seen_overflow`. They are appended after the existing columns and read 0 (empty for the breakdown) for a device that stayed within every limit. The per-asset JSON export carries the same counts. Loading a saved session reads them back; older sessions load with 0. The CLI run summary prints the totals over all devices, and the TUI shows the total in its status line and a warning when anything was not kept.

### Changed — Port Labels
- **Port 20547/TCP is labeled ProConOS** (the Phoenix Contact PLC runtime) instead of PCWorx; port 1962/TCP keeps the PCWorx label. The port evidence, event log line and classification reason for 20547 now name ProConOS. A device serving both ports is credited with two OT services instead of one, so its classification reason lists both, and a user rule that classifies it as IT lists both as conflicts. Class, confidence, role and evidence weights are unchanged. A saved session keeps its stored text until the device is seen again.

### Changed — Log Import Validation
- A Zeek log whose header cannot be used (an empty `#separator`, or data without a `#fields` header) is reported as a clear file error.
- Suricata EVE lines are type-checked one by one: a line that is not a JSON object, or has a field of the wrong type (for example a `dest_port` given as a string or a fraction, or a non-integer alert severity), is rejected and the rest of the file is imported.
- A destination port must be a port number (0 to 65535). A Zeek `conn.log` line whose `id.resp_p` is not a decimal port number from 0 to 65535 (other than `-`, meaning unset) is now rejected as a whole line; before, such a line was kept with no port. A Suricata EVE line whose `dest_port` is outside that range is rejected likewise. Rejected lines are counted in the run summary.

### Changed — Protocol Column
- **The protocol column says how each protocol of a device is known**, so a client such as an HMI polling PLCs no longer shows "Unknown". Entries are listed in this order: protocols the device serves, shown by name when a protocol parser saw the device answer as a server and with ` (port)` when only a listening port shows it; protocols a parser saw the device request as a client, with ` (client)` (for example `Modbus TCP (client)`); and OT services the device only contacted by port, with ` (client, port)` (for example `S7comm / IEC 61850 MMS / ICCP (client, port)`). "Unknown" appears only when none of these is known. This applies to the TUI asset table (live and reloaded sessions), the CLI table, the topology node label and tooltip, the TUI asset export and the AI asset tools. Classification, confidence and evidence are unchanged.
- The protocol column in the TUI and CLI tables is wider (32 characters). When text still has to be shortened, the protocol name is cut (marked `~`) and the qualifier is kept; entries that still do not fit are counted as `+N`.
- `assets.csv` gains a last column, `protocol_display`, with the same entries separated by `|`. The `protocol` column still lists only the served protocols, unlabeled. Sessions saved before this column existed show their served protocols as saved.
- Known limitation: a served protocol named by a user rule that matched the device by MAC alone is still shown with ` (port)`.

### Fixed — Which Side of a Connection Offers the Service
- **Fewer false OT devices from client source ports**: a device is credited with a listening service only from packets it sends itself, never from packets sent to it. A port counts only on its own transport: a TCP-only signature such as IEC 60870-5-104 (2404) is never credited from a UDP packet, nor a UDP-only one such as BACnet/IP (47808) from TCP. A user rule port without `protocol` takes the transport of the port's signature (both transports when the port has none). When both ports of a packet are service ports and nothing else shows which side serves, the lower port is taken as the service, so a workstation that uses 44818 as its temporary port for DNS lookups is no longer shown as an EtherNet/IP device.
- **Unanswered connection attempts no longer create devices**: a TCP SYN that gets no answer, a UDP datagram that gets no reply and Zeek `conn.log` records in state S0 or REJ (and RSTOS0, SH) no longer create a device at the probed address, and no longer give it the probed port. A port scan of empty addresses therefore no longer fills the inventory with OT devices. The scanning host still records the ports it contacted. A device seen through its own traffic or other evidence keeps its entry, without the probed port. A device that only receives traffic in a capture (for example a mirror port that copies one direction) is no longer listed from the ports it was contacted on.
- **Replies no longer mark a device as initiating connections**: a PLC that only answers its polling HMI is no longer reported as initiating, so a `never_initiates` rule no longer alerts on its replies. Initiation evidence now carries a confidence: MEDIUM from a TCP SYN or a validated Modbus request, LOW when only the port numbers show which side is the client. A device keeps one initiation record, raised from LOW to MEDIUM and never lowered. A `never_initiates` alert states when it was triggered by LOW evidence.
- **Contacted ports are service ports only**: a reply sent to a client's temporary port is no longer recorded as a port the server contacted, so a server answering a client whose temporary port happens to be an OT port no longer shows a false ` (client, port)` protocol entry. A TCP SYN still records the port it was sent to.
- **Modbus observations follow the TCP handshake**: when the TCP flags of a packet show which side serves, a Modbus message in it is counted for that side even if port 502 suggests the other. A Modbus message in a TCP reset, or between two 502 ports, is counted with no direction (its evidence reads `direction=unresolved`). Function codes, exceptions and counts are unchanged.
- **Contradictory packets attribute nothing**: a Modbus exception response (which only a server sends) carried in a TCP SYN or reset is counted as a field warning in the run summary instead of crediting either side.
- **Zeek `conn.log` uses `conn_state`**: the responder is credited with its port only for states where it answered (S1, SF, S2, S3, RSTO, RSTR), and the originator counts as initiating only for states where it opened the connection. Records in states RSTRH, SHR or OTH, and `conn.log` files without a `conn_state` column, attribute no direction (no listening port, no initiation, no contacted port). For UDP, a record whose both sides sent (SF) is decided from its port numbers, using `id.orig_p`. A responder that answered on a port without a signature is listed as a device without that port. An unusable `id.orig_p` is ignored and counted as a field warning; the line is kept. Zeek `modbus.log`, `dnp3.log` and `bacnet.log` are unchanged.
- **Suricata EVE flow events need packets to the client**: the destination of a `flow` event is credited with its port only when `flow.pkts_toclient` is above 0, and not when the server's TCP flags (`tcp.tcp_flags_tc`) show a reset without a SYN. A malformed `pkts_toclient`, `tcp_flags_tc` or `src_port` is ignored and counted as a field warning; the line is kept. Suricata `modbus`, `dnp3` and `enip` events are unchanged.
- **Suricata alerts never credit ports**: an alert's addresses follow the packet that triggered it, so an alert on a server's reply no longer credits the client's temporary port or marks the server as initiating. Alerts are still reported. Other Suricata event types (for example `dns`, `http`, `tls`, `netflow`) no longer credit a port or mark an initiator.
- **ICMP records no longer credit ports**: a Zeek or Suricata ICMP record no longer gives a device a TCP/UDP service port.
- Known limitations: a session seen only from the middle (no SYN in the capture) that the server ends with a reset is not credited from Suricata flow events. A one-way UDP flow in Zeek or Suricata does not credit the sender's own port. Suricata event types other than `flow`, `modbus`, `dnp3` and `enip` record no direction.

### Fixed — Topology Assistant
- **The assistant panel in `topology.html` works again**: a page-template escaping error broke its script, so the AI button, the panel and the chat did nothing. The assistant is now also given the devices, protocols and connections of the graph; before, its context described an empty network.
- The topology chat uses the same default models as the AI configuration for OpenAI, Anthropic and Gemini, instead of its own model names (it named the retired `gemini-2.0-flash`). The API key stays in page memory only and is never stored.

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
- **Default model chosen on EOL/GA status, not full cost comparison**: `gemini-3.8-flash` was selected because `gemini-2.0-flash` reached EOL. A full cost/latency comparison across the GA model tier was not performed in v0.6.1.

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
