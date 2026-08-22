# Scrutics

**Passive OT/ICS Network Asset Discovery**

Scrutics discovers and classifies assets on operational technology networks by observing traffic passively — no packets transmitted, no active scanning, no risk to running processes. It identifies PLCs, RTUs, HMIs, and field devices by MAC vendor and ICS protocol, builds a behavioral baseline per device, and exports results as CSV or forwards anomaly events to a SIEM in real time.

Built for small OT teams, brownfield facilities, and security practitioners who need network visibility without the cost, complexity, or active-scanning risk of enterprise platforms.

> **First public release — v0.4.0.** Core functionality is stable. Configuration format and internal APIs may change before v1.0. Bug reports and deployment feedback are actively sought.

---

![Scrutics TUI](docs/screenshots/Scrutics_TUI.png)
*Asset inventory, event log, and anomaly feed during live capture against a simulated OT network (Schneider, Siemens, Rockwell, BACnet)*

---

## Who is this for

OT engineers, IT/security staff tasked with OT visibility, and security researchers who need lightweight passive asset discovery without deploying a full monitoring stack.

**You should be comfortable with basic Linux command-line usage and network interfaces.** Scrutics does not require deep Linux expertise, but you will need to identify the right network interface, run commands with sudo, and read CSV output.

---

## Why passive-only

Active scanning — nmap, ping sweeps, discovery packets — can crash legacy PLCs and freeze HMIs on OT networks. Scrutics operates exclusively in read-only mode: it observes traffic that already exists on the wire and classifies what it sees.

No probing. No injected packets. No risk.

Passive-only operation is enforced at runtime by patching Scapy's transmit functions before any capture begins. Any accidental transmit attempt raises a `PermissionError` and is logged.

---

## Why not Zeek, Malcolm, or Grassmarlin

| | Scrutics | Zeek | Malcolm | Grassmarlin |
|---|---|---|---|---|
| Installation | `pip install` or ZIP download | Requires scripting knowledge | Full Docker stack | Windows-only installer |
| Runs on Raspberry Pi | ✓ | Possible but complex | No | No |
| OT-specific out of the box | ✓ | Requires ICS scripts | ✓ via Zeek | ✓ |
| Reads Zeek / Suricata output | ✓ | — | — | — |
| SIEM output (real time) | ✓ | Needs pipeline | Via OpenSearch | No |
| Active development | ✓ | ✓ | ✓ | Archived |

Scrutics is not trying to replace Zeek or Malcolm for large environments. The target is a facility that has no existing OT visibility tooling and needs to answer "what is on my network and is it behaving normally" without deploying a full security stack.

---

## Feature status

| Feature | Status |
|---------|--------|
| Passive live capture | ✅ Stable |
| PCAP / PCAPNG file analysis | ✅ Stable |
| Behavioral baseline and anomaly detection | ✅ Stable |
| CSV output (events, anomalies, assets) | ✅ Stable |
| Behavioral rule constraints | 🟡 Actively evolving |
| SIEM sinks (syslog, Splunk HEC) | 🟡 Untested on production SIEMs |
| Zeek / Suricata log parsing | 🟡 Synthetic-tested only |
| Custom rules format | 🟡 May change before v1.0 |
| Internal Python APIs | 🔴 Not stable |

---

## Requirements

- Python 3.10 or newer
- Linux (including WSL2 on Windows)
- Root or `CAP_NET_RAW` for live capture (file analysis does not require root)
- Dependencies: `scapy`, `textual`, `pyyaml`

Raspberry Pi 4 or newer is recommended for continuous live deployment.

---

## Installation

**Option 1 — Download ZIP (easiest)**

1. Go to the [Releases page](https://github.com/AhmedQazafy/Scrutics/releases)
2. Download the latest `Source code (zip)` and extract it
3. Open a terminal inside the folder

```bash
pip install -r requirements.txt --break-system-packages
```

**Option 2 — Git clone**

```bash
git clone https://github.com/AhmedQazafy/Scrutics.git
cd Scrutics
pip install -r requirements.txt --break-system-packages
```

**Option 3 — Editable install (adds the `scrutics` command)**

```bash
pip install -e . --break-system-packages
scrutics --version
```

**Verify everything is working**

```bash
python3 -m scrutics doctor
```

![Scrutics doctor](docs/screenshots/Scrutics_Doctor.png)

Doctor checks all dependencies, finds your network interfaces, and confirms your config is loading correctly. If it says `✓ Everything looks good.` you are ready to run.

---

## Quick start

**Launch the TUI (recommended for first use)**

```bash
sudo python3 -m scrutics
```

**Headless live capture**

```bash
sudo python3 -m scrutics --live eth0 --headless
```

**Analyze a PCAP file**

```bash
python3 -m scrutics --file capture.pcap --headless
```

**Fast inventory from a large PCAP (skip anomaly detection)**

```bash
python3 -m scrutics --file big.pcap --headless --no-baseline
```

![Scrutics headless mode](docs/screenshots/Scrutics_Headless.png)
*Headless live capture | periodic asset snapshots with confidence scores climbing as the baseline locks, then a clean save on Ctrl+C*

---

## Deployment

### Finding the right interface

Scrutics must run on the interface that carries OT network traffic — typically a SPAN or mirror port from your OT managed switch.

```bash
# List available interfaces
python3 -m scrutics doctor

# Verify traffic is present before running Scrutics
sudo tcpdump -i <interface> -c 10
```

If tcpdump shows no packets, the interface is wrong or the SPAN port is not configured.

### Windows users

Live capture requires Linux or WSL2. Two practical paths:

**WSL2** — install WSL2, clone Scrutics inside the WSL filesystem (`~/Scrutics`, not `/mnt/c/...`), and run from there.

**Offline PCAP** — capture traffic using Wireshark, tcpdump, or an existing network appliance, then hand Scrutics the PCAP file. File analysis works on any machine with Python installed and needs no root or Linux.

### Stopping a live capture correctly

Always run live captures in the foreground:

```bash
sudo python3 -m scrutics --live eth0 --duration 0 --headless
# Ctrl+C saves assets.csv and exits cleanly
```

Do **not** use `&` (background). Ctrl+C on a backgrounded process goes to the shell, not to Scrutics — `assets.csv` will not be saved. To stop a background process: `kill -TERM <pid>`

### Example GIF
![Scrutics headless mode](docs/screenshots/Scrutics_Headless_test.gif)
*Using Doctor then Headless live test then a save on Ctrl+C*

### Raspberry Pi

```bash
sudo apt install python3-pip
git clone https://github.com/AhmedQazafy/Scrutics.git
cd Scrutics
pip3 install -r requirements.txt --break-system-packages
sudo python3 -m scrutics --live eth0 --duration 0 --headless
```

---

## Command reference

| Option | Default | Description |
|--------|---------|-------------|
| `--live INTERFACE` | — | Network interface for live passive capture |
| `--file FILEPATH` | — | File to analyze (.pcap, .pcapng, .log, .json) |
| `--duration SECONDS` | `60` | Capture duration. `0` = run until Ctrl+C |
| `--baseline SECONDS` | `60` | Observation window before anomaly detection activates |
| `--output DIR` | `./output` | Directory to save session folders |
| `--headless` | off | Disable TUI, print to console |
| `--no-baseline` | off | Skip anomaly detection — inventory only |
| `doctor` | — | Print diagnostic information |

**TUI shortcuts:** `1` Start · `2` File Options · `3` Toggle Panels · `R` Reload Rules · `P` Pause · `Q` Quit · `←→` Switch Panels · `Enter` Scroll Mode

---

## Output files

All output is saved to `output/scrutics_TIMESTAMP/`.

| File | When written | Contents |
|------|-------------|----------|
| `assets.csv` | On session end | IP, MAC, vendor, protocols, role, confidence, anomaly count |
| `events.csv` | Continuously | Classification events as they happen |
| `anomalies.csv` | Continuously | Behavioral anomalies — never lost to a crash |

---

## Configuration

Edit `scrutics/config/custom_rules.yaml` to add custom classification rules and SIEM output sinks. Changes are detected automatically while Scrutics is running. Press `R` in the TUI for an immediate reload.

The built-in ICS rules are in `scrutics/config/builtin_rules.yaml` — do not edit this file.

### Custom rules

```yaml
rules:
  # Classification only
  - name: "OSIsoft PI Historian"
    port: 5461
    classify_as: "PI Historian"
    role: "Data Historian"
    is_ot: true

  # With behavioral constraints
  - name: "Modbus PLC Fleet"
    port: 502
    classify_as: "Modbus TCP"
    role: "PLC / RTU"
    is_ot: true
    never_initiates: true        # alert if PLC initiates any connection
    allowed_peers:
      - "192.168.1.100"          # SCADA server
    max_new_peers_per_hour: 2
```

**Classification fields:** `name`, `port`, `mac_prefix`, `protocol`, `classify_as`, `role`, `is_ot`, `confidence`

**Behavioral constraints:** `never_initiates`, `allowed_peers`, `allowed_ports`, `alert_on_new_port`, `max_new_peers_per_hour`

### Inventory scope

```yaml
inventory:
  include_public_ips: false
  cidrs: []
```

### SIEM output

```yaml
output:
  sinks:
    - type: syslog
      host: 192.168.1.50
      port: 514
      protocol: udp
      format: json        # json | cef | leef | plain

    - type: splunk_hec
      url: https://splunk.example.com:8088
      token: your-hec-token
      verify_ssl: true
```

---

## Analyzing existing captures

| Input | Command |
|-------|---------|
| PCAP / PCAPNG | `scrutics --file capture.pcap` |
| Zeek conn.log | `scrutics --file conn.log` |
| Suricata EVE JSON | `scrutics --file eve.json` |

Format is detected automatically. Use `--no-baseline` for files over ~100MB.

---

## Troubleshooting

Run `scrutics doctor` first — it identifies most issues immediately.

| Symptom | Fix |
|---------|-----|
| No packets after 30s | Wrong interface — check `doctor` interface list |
| Permission denied | `sudo python3 -m scrutics` |
| assets.csv not saved | Used `&` background — use foreground + Ctrl+C |
| Rules not reloading | YAML syntax error — check `doctor` config line |
| TUI won't open | `pip install textual --break-system-packages` |

---

## Known limitations

- **Large PCAPs are slow** — use `--no-baseline` for files over 100MB
- **No MAC in Zeek/Suricata logs** — OUI vendor matching unavailable; confidence scores are lower
- **No IPv6 support**
- **WSL2 file performance** — keep Scrutics on the Linux filesystem, not `/mnt/c/...`
- **Passive enforcement caveat** — code that captures a Scapy send reference before `enforce_passive()` is called can bypass the patch; does not affect normal use

---

## Why v0.x

Scrutics stays in the 0.x series while validating its architecture through real-world deployments. Core capture and classification is stable. Configuration format and internal APIs may change before v1.0.

---

## Roadmap

Future priorities will be driven by real-world deployments and user feedback.

- Validate against the [4SICS 2015 public ICS dataset](https://www.netresec.com/?page=PCAP4SICS) and publish accuracy results
- Generate network topology maps showing device relationships and communication 
  patterns taht are exportable as interactive HTML, Gephi-compatible CSV, or embedded 
  in session output for visual analysis in tools engineers already use (details undecided yet)
- Refine behavioral detection based on feedback from real OT environments
- Validate Wazuh and Splunk SIEM integrations against production deployments
- Improve Windows and offline PCAP deployment workflows
- Expand SIEM format support based on what users actually request
- Explore standalone executable for environments where Python installation is impractical

---

## Project structure

```
Scrutics/
├── scrutics/
│   ├── baseline/       — behavioral baseline engine
│   ├── capture/        — packet capture and flow processing
│   ├── classifier/     — OUI lookup and protocol classification
│   ├── config/         — YAML rules (builtin_rules.yaml, custom_rules.yaml)
│   ├── db/             — asset inventory and rolling CSV writer
│   ├── diagnostics.py  — health checks (scrutics doctor)
│   ├── integrations/   — SIEM sink manager (syslog, Splunk HEC)
│   ├── parsers/        — Zeek, Suricata, PCAP parsers
│   ├── signals.py      — file-watch reload and SIGHUP handler
│   ├── ui/             — Textual TUI
│   └── passive.py      — passive enforcement layer
├── sim/                — Docker OT simulation (Modbus, EtherNet/IP, BACnet)
├── tests/              — 94 unit tests
└── pyproject.toml
```

---

> **Note:** This project was developed with a degree of AI assistance. All design decisions, testing, validation, and code changes are the author's own work. Feel free to reach out privately with any concerns.

## License

MIT
