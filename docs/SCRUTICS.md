# Scrutics v0.7: what it does and what it does not

This document describes Scrutics as it is in v0.7: what it observes, how it decides, what it
writes, and where it stops. It states only what the code does or what was measured. Usage
details are in the [README](../README.md); every change and known gap of the release is in the
[CHANGELOG](../CHANGELOG.md).

---

## 1. Purpose

Scrutics builds an inventory of the devices on an industrial (OT/ICS) network from traffic it
receives: a live network interface, a packet capture file, or Zeek and Suricata logs. For each
device it records what it observed (evidence) and, from that evidence, decides a class (OT, IT or
Unknown), a role, and the reasons for both. It can also learn each device's normal communication
and report deviations, and check devices against user rules.

Scrutics is in the 0.x series: the configuration format and internal interfaces may change before
1.0.

---

## 2. Passive operation

**What holds:**

- Scrutics never sends packets to the monitored network. Capture only receives; there is no
  probing, scanning or active query of any device.
- Before a live or file capture starts, Scrutics replaces Scapy's send functions (`send`, `sendp`,
  `sendpfast`, `sr`, `sr1`, `srp`, `srp1`, `srloop`, `srploop`, `srflood`, `srpflood`, `sndrcv`
  in `scapy.sendrecv` and `scapy.all`) with a function that raises `PermissionError`, prints the
  call stack, and appends it to `output/scrutics_passive_audit.log` (relative to the working
  directory). A live capture refuses to start if any of them is still the original.
- Live capture opens the interface in promiscuous mode, which changes what the host receives, not
  what it sends.

**What it does not cover:**

- The guard covers those named Scapy functions only. It is a safeguard against Scrutics' own code
  calling them, not a sandbox: code that sends by another route (a raw socket, or a Scapy socket
  used directly) is not intercepted. Scrutics' capture code has no such route.
- Scrutics itself opens network connections only for features the user configures or starts, and
  never to monitored devices as part of capture:

| Feature | Destination | When |
|---|---|---|
| SIEM sinks | the configured syslog server (UDP or TCP) or Splunk HEC URL | each anomaly, when sinks are configured |
| AI assistant (`scrutics ai`, TUI) | the configured provider (Gemini, OpenAI, Anthropic, or your Ollama server) | each question, when AI is set up |
| `scrutics ai --diagnose`, `list-models`, AI setup | the provider | when run |
| `scrutics oui update` | `https://standards-oui.ieee.org/oui/oui.txt`, or `--url` | when run |
| Topology page chat | the provider you pick, from your browser | only after you enter a key and ask |

Nothing else in Scrutics makes network connections. The topology page loads no external
resources; its Excel export runs in the browser from a bundled library. The Docker simulation in
`sim/` is a separate lab that does generate traffic (section 14).

---

## 3. Inputs

| Input | How | Notes |
|---|---|---|
| Live interface | `--live IFACE` or the TUI | Linux or WSL2; needs capture privileges |
| `.pcap`, `.pcapng` | `--file` | read with Scapy |
| Zeek logs (`.log`) | `--file` | `conn.log`, `modbus.log`, `dnp3.log`, `bacnet.log`; detected from the `#separator`/`#fields` header |
| Suricata EVE (`.json`) | `--file` | one JSON event per line |

**Packet captures.** Devices are built from Ethernet frames carrying IPv4 or ARP. Linux cooked
captures (SLL and SLL2, as written by `tcpdump -i any` or capture on the `any` pseudo-interface),
raw-IP captures without a link layer, and IPv6 produce no devices. Such frames, and other
ethertypes (PROFINET, GOOSE, Sampled Values, LLDP, IEEE 802.3 LLC such as STP), are counted by
kind in the run summary, and a capture that produces no devices says why.

**Which addresses become devices.** By default only private IPv4 addresses (including the
RFC 1918 ranges) and link-local addresses (169.254.0.0/16) become devices; public addresses appear
only as peers. Broadcast, multicast, loopback, unspecified and reserved addresses, and any address
ending in `.255`, never become devices. The `inventory` section of the configuration can set `include_public_ips: true`
or limit discovery to listed `cidrs`.

**Damaged files.** Reading stops at the first damaged record and the summary says whether the
last record was incomplete or the file is damaged before its end. Scrutics does not resynchronize
after a damaged record. A corrupted length that still fits in the file is not detected. With
Scapy 2.8 a pcapng packet that names an undescribed interface is skipped without a Scrutics report;
with Scapy 2.7 the read stops there and Scrutics reports damage.

**Zeek and Suricata logs.** Records give addresses and ports only; no MAC address is read, so
these devices have no vendor and are identified by IP address. `modbus.log`, `dnp3.log` and
`bacnet.log` records, and Suricata `modbus` and `dnp3` events, are used as observations of the
protocol's standard port; their application-layer fields (function codes, objects) are not used.
Zeek `conn.log` uses `conn_state`, and Suricata `flow` events use `pkts_toclient`, to decide which
side served. Suricata alerts are reported as `SURICATA_ALERT` anomalies and never credit ports.

**Live capture limits.** Live capture restarts Scapy's capture every second and processes each
packet before reading the next. Packets the host cannot keep up with, or that arrive while the
capture restarts, are lost, and Scrutics does not count lost packets. The loss rate was not
measured in v0.7.

---

## 4. Device identity

- A device is identified by its MAC address when one is seen; its IP address is an observed
  attribute with a history of changes. An IP change does not create a new device (`DEVICE_MOVED`,
  MEDIUM), and a new MAC on a known IP creates a separate device (`MAC_CHANGED`, HIGH).
- Two devices can therefore share an IP address; both are listed (rows are keyed by device).
- Devices from Zeek or Suricata logs, which carry no MAC, are identified by IP address.
- A Modbus unit ID (a device behind a gateway) never creates a device.
- **Routed traffic:** packets from another subnet arrive with the router's MAC address, so hosts
  behind a router are recorded against the router's MAC. Scrutics does not infer routers.

---

## 5. What Scrutics observes (evidence)

Every observation is stored as an evidence record (type, value, weight, source, confidence,
detail). Evidence explains decisions; no single record sets the class.

| Evidence | Source | Weight |
|---|---|---|
| Port signature | each port of a packet the device sends that matches the signature table (section 6) | 3 to 20 by signature |
| Validated protocol | the Modbus TCP parser (the only protocol parser in v0.7) | 20 |
| Vendor (OUI) | MAC prefix lookup; weight by vendor class: OT 30, IT 15, neutral 10, other 5 | 5 to 30 |
| DHCP host name, vendor class, client FQDN | DHCPv4 options 12, 60, 81 | 5 each |
| DHCP vendor-class match | option 60 matched to a known vendor | 10 |
| DHCP OS fingerprint | DHCPv4 option 55 matched to a known fingerprint | two OS-hint records, 10 each |
| mDNS / WS-Discovery | mDNS names (port 5353), WS-Discovery presence (port 3702) | 15 per distinct name |
| OS hint from TTL | initial TTL 64 ("Linux/Unix-like") or 128 ("Windows-like"): 5; 255 ("network device"): 15 | 5 or 15 |
| Family hint | a user file `~/.scrutics/curated_oui.yaml` (none bundled) | 5 |

DNS names come only from DHCP option 81; DNS traffic is not parsed. Each kind of evidence keeps
the first 64 distinct values per device (section 9).

---

## 6. Classification

**Port signatures** (`scrutics/classifier/signatures.py`): 33 OT ports (Modbus TCP 502, S7comm /
IEC 61850 MMS / ICCP 102, EtherNet/IP 44818 and 2222, DNP3 20000, IEC 60870-5-104 2404, BACnet/IP
47808, PROFINET RT, EtherCAT, OPC UA discovery, HART-IP, FINS, CODESYS, and others), 7
infrastructure ports (DNS, DHCP, NTP, SNMP, syslog), 21 IT ports and 2 discovery ports. Apart from
Modbus TCP, protocols are identified by port number only: a device listening on 102 is "S7comm /
IEC 61850 MMS / ICCP" whatever it actually speaks.

**Listening ports.** A device is credited with a listening port only from packets it sends itself,
on the signature's own transport. When both ports of a packet are service ports and nothing else
shows which side serves, the lower port is taken. Unanswered connection attempts create no device.

**Decision.** `classify_asset` applies the first matching rule:

1. a user rule matches by listening port or MAC: the rule's class (OT or IT) and role;
2. device-level infrastructure evidence: Infrastructure. No such evidence exists in v0.7, so this
   rule never applies and no device is classified Infrastructure;
3. serves a validated OT protocol (Modbus TCP): OT, decision confidence HIGH;
4. listens on an OT signature port: OT, MEDIUM;
5. sends validated OT protocol requests: OT, MEDIUM, role "OT client";
6. listens on an IT signature port: IT, MEDIUM;
7. otherwise: Unknown, LOW, role "Possible OT Client" when it contacted OT ports, else
   "Unclassified".

Vendor, DHCP, OS hints, host names, discovery, behaviour and infrastructure-service ports never
vote; they appear in the reason. The reason and any conflicting signals are stored with the
device. The vendor note "OT-associated vendor; no OT service observed in this capture" flags an OT
vendor with no observed OT service; it changes nothing.

---

## 7. Confidence

Every screen shows one confidence: the headless table (`CONF%`), the TUI tables and detail view,
the topology page (node size, isolated list, tooltip, CSV export, chat summary) and the AI
assistant's asset results and `min_confidence` filter.

**What it is:** the sum of the weights of the device's evidence records, capped at 100
(`classification_confidence_pct`, the `classification_confidence` column of `assets.csv`).

**What it is not:** a probability that the class is right. It measures how much evidence exists,
including evidence that never votes on the class:

- an OT-vendor MAC alone gives 30 on a device that may be classified Unknown;
- each distinct mDNS name adds 15, so a device announcing seven names reaches 100;
- port evidence is recorded for both ports of each packet a device sends, so a client polling port
  502 gains the Modbus port's 20 as well.

The decision confidence (HIGH, MEDIUM, LOW, from section 6) is the separate statement of how the
class was decided. `assets.csv` also keeps `confidence_pct`, an older multi-factor score computed
only while the behavioural baseline runs (0 with `--no-baseline`); no screen shows it.

---

## 8. Anomalies

**Learned baseline (per IP address).** For each device address Scrutics observes for the baseline
window (`--baseline`, 60 s of capture time by default), then locks the baseline and reports:

| Type | When | Severity |
|---|---|---|
| `NEW_PEER` | a peer not seen during the window | MEDIUM |
| `DIRECTIONALITY_CHANGE` | a device that mostly responded starts initiating (at most once per 300 s) | HIGH |
| `INTERVAL_ANOMALY` | a packet interval more than 4 standard deviations from the learned mean (at most once per 60 s) | LOW |

The interval is the time between consecutive packets an address sends, to any peer: one rhythm per
address, not per conversation, learned once in the baseline window and not updated afterwards. A
new client that starts talking to a device therefore changes the device's rhythm, and the device
raises `INTERVAL_ANOMALY` about once a minute for as long as that client stays, although its polling
of each peer is unchanged.

**User-rule constraints** (`BEHAVIORAL_VIOLATION`, HIGH): `never_initiates`, `allowed_peers`,
`allowed_ports`, `alert_on_new_port` (`NEW_PORT`) and `max_new_peers_per_hour`
(`PEER_RATE_EXCEEDED`), with cooldowns. A device that only contacts a port receives the
constraints of a user rule for that port unless the rule's `mac_prefix` excludes it, so constraint
rules should set `mac_prefix` (README example). What several conflicting rules should mean is not
defined; one rule applies at a time.

**Identity:** `MAC_CHANGED` (HIGH) and `DEVICE_MOVED` (MEDIUM). **Suricata:** `SURICATA_ALERT`,
severity from the alert (1 HIGH, 2 MEDIUM, 3 LOW).

**`--no-baseline`** skips the learned baseline only. Rule constraints, identity alerts and
Suricata alerts are still raised.

---

## 9. Output

Each run writes a session folder `output/scrutics_YYYYMMDD_HHMMSS/`:

| File | Written | Contents |
|---|---|---|
| `events.csv`, `anomalies.csv` | appended as each record happens, never rewritten | every event and anomaly |
| `assets.csv` | every 15 s and at the end | one row per device, with both confidence columns, protocol display, vendor note and per-device limit counts |
| `evidence.json` | every 15 s and at the end | evidence records, keyed by IP address |
| `connections.csv` | every 15 s and at the end | every connection between devices |
| `topology.json`, `topology.html` | every 15 s and at the end | the 2,000 busiest connections |
| `manifest.json` | every 15 s and at the end | counts observed, exported and dropped, write errors, `export_complete` |

The snapshot files are rewritten in place at each checkpoint; only `manifest.json` is replaced
atomically. A process killed while a snapshot file is being written can leave that file
incomplete; `events.csv` and `anomalies.csv` keep everything appended before it.

`evidence.json` is keyed by IP address, so when two devices share an address only one device's
evidence is written; the manifest counts the others and marks the export incomplete. A write
failure is counted and reported at the end of the run (and at headless checkpoints), not when it
happens.

**Per-device limits.** Each device keeps the most recent 256 IP changes, the first 64 distinct
values of each evidence kind, the first 64 DNS names and the first 4,096 peers (and first-contact
times). What is not kept is counted in `assets.csv` and the run summary. The number of devices,
and the connections between them, are not limited.

**SIEM sinks** forward anomalies only (not inventory), as syslog (JSON, CEF, LEEF or plain, over
UDP or TCP) or to Splunk HEC. Delivery is best effort through a queue of 1,000: when the queue is
full or a sink fails, the anomaly is not delivered and the loss is not counted. These integrations
have not been validated against production SIEMs.

---

## 10. Interfaces

**CLI** (`python3 -m scrutics` or `scrutics`):

| Command | Purpose |
|---|---|
| (no options) | TUI |
| `--live IFACE` / `--file PATH` | capture source |
| `--duration S` | live capture length, whole seconds, 0 = until Ctrl+C (default 60) |
| `--baseline S` | baseline window, whole seconds, 1 or more (default 60) |
| `--no-baseline` | skip the learned baseline (section 8) |
| `--headless`, `--output DIR`, `--version` | console mode, output folder, version |
| `doctor` | dependency, interface, configuration, output-folder and OUI checks |
| `ai [QUESTION]` (alias `ask`) | AI assistant; `--session`, `--provider`, `--model`, `--diagnose`, `--reconfigure`, `--disable`, `--reset` |
| `list-models PROVIDER` | models available to your key |
| `oui status`, `oui validate FILE`, `oui update`, `oui import FILE` | vendor database |

**TUI:** `1` start, `2` file options, `3` panels, `R` reload rules, `P` pause, `A` AI assistant,
`Q` quit; it can also load a saved session (read-only). The asset table's Anomalies column counts
anomalies per IP address: during a capture among the newest 100 kept on screen, for a loaded session
every row of `anomalies.csv`. The TUI redraws its asset table every
0.5 s, work that headless mode does not do; how much this costs on large inventories was not
measured for this release.

**Rules and configuration:** `~/.scrutics/scrutics.yaml` if it exists, otherwise
`scrutics/config/custom_rules.yaml`. The file is polled every 2.5 s; `R` in the TUI and SIGHUP
reload at once; an invalid edit keeps the rules in use. Built-in rules are in
`scrutics/config/builtin_rules.yaml`. User rules can assert OT or IT only.

---

## 11. Topology page

`topology.html` draws devices with connections as a force-directed graph (drag, zoom; labels hide
when zoomed out), lists devices with no drawn connection in a side panel, and exports Assets,
Connections and Summary sheets to `.xlsx` in the browser. Node size follows confidence. The layout
starts each group as a radial tree around its most connected device and packs groups in rows; once
it settles, devices in a group of up to 30 devices and 60 links swap places while that lowers the
number of crossing connections and connections over a device (larger groups keep the force layout),
devices linked only to a hub are spread evenly around it, and the view is fitted so that every
device and label is in view. Addresses and ids do not decide the layout. Connections in both
directions between two devices are two mirror-image arcs. Labels are placed so they touch no other
label, device, label line, off-screen badge or page overlay, farther out with a thin line to the
device when needed; a protocol label that does not fit clear of other connections is not shown.
After settling, groups are packed closely by their actual size so that the fitted view is as large
as the canvas allows.
It shows the 2,000 busiest connections.

The page's chat (section 12) is optional and sends data only after you enter a key.

---

## 12. AI assistant

Optional; needs the `requests` package (`pip install -e ".[ai]"`). Providers: Gemini, OpenAI,
Anthropic, and Ollama (local or on your network). Default models: `gemini-3.8-flash`,
`gpt-6-luna` (with `reasoning_effort: "none"`), `claude-haiku-5-5` (with thinking disabled),
`qwen3.5:4b`.

**What it can see.** The assistant (`scrutics ai`, TUI) reads a saved session through five tools:
statistics, asset list (filter by type and minimum confidence; at most 100 results), one asset
by IP address, connections (at most 100) and anomalies. It makes at most 5 tool rounds per
question. It reads every row of the session files, and says which files or rows it could not
read. An asset looked up by IP address is the first device with that address, and its evidence
comes from `evidence.json`, which is keyed by IP address, so for devices that shared an address
the evidence may belong to the other device.

**What it sends.** Your question and the session data the assistant looks up go to the provider
you configured. The assistant only reads; it changes nothing.

**Follow-up questions.** Each question carries the earlier exchanges as text: at most the 5 most
recent and 8,000 characters of question and answer text (CLI and TUI alike). The newest exchange
is always sent; an answer that alone exceeds the cap keeps its start and end around
`[middle of this answer omitted]`. Older exchanges that no longer fit are dropped whole, oldest
first. The TUI keeps the conversation, on screen and as context, across closing and reopening the
assistant, and clears it on a session switch; nothing is kept after Scrutics exits. Answers,
questions and errors are shown as plain text (no Markdown rendering), wrapped to the panel.

**Keys.** Sent only to their own provider, in a request header (Gemini in `x-goog-api-key`).
Removed from every message Scrutics prints or raises, including DEBUG logging. Setup stores keys
in `~/.scrutics/ai_keys.sh` (mode 0600) with one marked loader line in `~/.bashrc` (Linux, macOS,
WSL), or as a per-user variable (Windows `.bat`). `--provider` uses that provider's own key from
its environment variable. Residual limits: Python's `http.client` debug output, if you turn it on,
prints headers including the key; `list-models --key KEY` puts the key on the command line.

**Models and requests.** Model lists come from the provider (OpenAI limited to `gpt-6-luna` and
`gpt-6-sol`); a fallback list is labelled with its 2026-10-16 check date. Temperature is sent only
to models documented to accept it. Output limits: Gemini 8192 tokens with a low thinking level on
`gemini-3.8-flash`, Anthropic 4096, none sent to OpenAI or Ollama; setup writes no `max_tokens`, and
an `ai.yaml` holding exactly 1024 (written by earlier setups) gets the default. The model is told
the answer length that fits its limit. An answer cut off at the limit is shown with a notice saying
so (CLI, TUI, topology chat); one cut off before any text is reported; other empty answers (Gemini
safety or malformed calls, Anthropic refusals) are not.

**Retries.** HTTP 429, 502, 503, 529 and connections that could not be opened: up to 4 attempts,
at most 30 s per wait and 60 s in total, honouring `Retry-After` within those limits. Read
timeouts, errors after the request was sent, HTTP 500, 504, 408 and other 4xx are not retried.

**Topology chat.** Runs in the browser and sees only a summary of the page: asset counts by type,
address, vendor, protocol and confidence for up to 20 OT devices, IT devices by address only (a
count above 10), unknown devices as a count, and connections only when there are 15 or fewer. It is
given no roles and no vendors of IT or unknown devices. The key stays in page memory.

---

## 13. Vendor database

The bundled database (`scrutics/classifier/ics_oui.txt`) holds about 4,900 IEEE assignments (MA-L,
MA-M, MA-S and IAB, retrieved 2026-10-10) of the industrial, network-infrastructure and IT vendors
Scrutics recognises; MACs of other vendors show Unknown. A vendor name is the holder of the MAC
assignment, not necessarily the maker of the device. A vendor's class (OT, IT, neutral) comes from
matching its name, by whole words, to a reviewed list of known vendors.

`scrutics oui update` downloads the IEEE MA-L listing (`oui.txt`) into `~/.scrutics/oui.txt`, and
`oui import` installs a file you provide; an installed database replaces the bundled one for every
lookup (they are not merged), so after an MA-L-only update the bundled MA-M and MA-S entries are no
longer used. `oui status` and `doctor` report the active database and its age.

---

## 14. Platform, resources and testing

- **Python** 3.10 or later is required; this release was tested on 3.10.12 and 3.12.3, not on
  3.11.
  **Scapy** 2.5 to below 3 is allowed; the suite was run on 2.7.0 and 2.8.0. Live capture needs
  Linux or WSL2.
- **Memory** grows with the number of devices and connections (measured on this release's code
  with invented devices, Scapy 2.7.0, process RSS): about 9 KB per device that talks to one other host with the baseline on (about 880
  MB per 100,000 invented devices), about 1 KB more per further host it talks to (19 KB with ten),
  and about 7 KB per device with `--no-baseline`.
- **Tests:** the suite (1,779 tests) passes on Scapy 2.7.0 and 2.8.0; one browser test is
  skipped when Playwright is not installed.
- **Simulation lab** (`docker-compose.yml`, `sim/`): two Modbus TCP servers, EtherNet/IP and
  BACnet stubs (listeners only, no CIP or BACnet traffic) and a traffic generator that opens TCP
  connections and sends two-byte UDP datagrams to them (no Modbus requests), on a Docker bridge.
  It exercises vendor lookup and port classification, not the Modbus parser, and is not a model of
  a real plant.

---

## 15. Known gaps (v0.7)

- Live capture loses packets it cannot keep up with, and the loss is not counted; the loss rate
  was not measured in v0.7 (section 3).
- Hosts behind a router are recorded against the router's MAC (section 4).
- Confidence measures the amount of evidence, not certainty (section 7).
- Protocols other than Modbus TCP are identified by port only; Zeek and Suricata application-layer
  records are used as port observations (sections 3, 6).
- No Infrastructure classification (section 6).
- No IPv6, Linux cooked (SLL/SLL2) or raw-IP captures (section 3).
- A port rule's constraints reach the devices that contact the port (section 8).
- Polling intervals are measured per address across all its peers, so a new client makes a device
  raise `INTERVAL_ANOMALY` about once a minute while it lasts (section 8).
- `evidence.json` and the assistant's single-asset lookup are keyed by IP address (sections 9, 12).
- Write failures are reported at the end of the run, not when they happen (section 9).
- SIEM delivery is best effort and losses are not counted (section 9).
- Topology groups of more than 30 devices or 60 links keep the force layout and can show crossing
  connections; the topology chat sees only a summary (sections 11, 12).
- Empty AI answers other than the token-limit case are not reported; `list-models --key` takes the
  key on the command line (section 12).
- pcapng undescribed-interface packets: behaviour differs between Scapy 2.7 and 2.8 (section 3).

The CHANGELOG lists each gap with the release's changes.
