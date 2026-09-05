"""
Passive capture engine. NEVER transmits packets.
All Scapy imports are lazy. Passive enforcement applied before capture.
"""

import time
import datetime
import threading
from collections import deque

from scrutics.db.inventory import AssetInventory
from scrutics.baseline.baselineengine import BaselineEngine
from scrutics.baseline.scorer import oui_score, protocol_score, confidence_pct, confidence_from_evidence
from scrutics.classifier.protocol import classify_by_ports, classification_evidence_from_ports
from scrutics.classifier.signatures import (
    get_signature, get_all_service_ports, get_ot_ports,
    get_it_ports, get_infrastructure_ports, get_discovery_ports
)


class CaptureEngine:
    def __init__(self, inventory: AssetInventory, progress_callback=None, baseline_window: int = 60):
        self.inventory = inventory
        self.progress_callback = progress_callback
        self._packet_count = 0
        self._oui_db = None
        self.baseline = BaselineEngine(observation_window=baseline_window)
        self.event_log: deque = deque(maxlen=500)
        self._logged_protocols: dict = {}   # ip -> frozenset of protocols last logged
        self._logged_dst_ports: dict = {}   # ip -> set of dst ports already logged
        self.writer      = None   # RollingWriter — attached by caller before capture
        self.sink_manager = None  # SinkManager   — attached by caller before capture
        self.no_baseline  = False  # skip anomaly detection (e.g. large PCAP files)
        self.topology_edges: dict = {}
        self._stop_event = threading.Event()
        self._get_oui_db()         # preload at startup — avoids silent delay on first packet

    def _log(self, message: str, style: str = "dim white"):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        entry = (ts, message, style)
        self.event_log.append(entry)
        if self.writer:
            self.writer.write_event(ts, message)

    def _get_oui_db(self) -> dict:
        if self._oui_db is None:
            from scrutics.classifier.oui import load_oui_db
            self._oui_db = load_oui_db()
        return self._oui_db

    def get_event_buffer(self) -> list:
        """
        Deprecated compatibility shim.

        Events are now persisted immediately by RollingWriter. This returns
        only the current in-memory display buffer.
        """
        return list(self.event_log)

    def _process_packet(self, pkt):
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.dns import DNS, DNSQR
        from scapy.packet import Raw

        src_mac = src_ip = dst_ip = src_port = dst_port = proto = None
        now_ts = float(getattr(pkt, "time", time.time()))
        ttl = None

        if Ether in pkt:
            src_mac = pkt[Ether].src

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ttl = pkt[IP].ttl

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = "TCP"
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = "UDP"
        if ARP in pkt:
            src_ip  = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc

        if not src_ip or not src_mac:
            return
        if not self.inventory.is_asset_ip(src_ip):
            return
        if src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        # ── Phase 4: Extract TTL for OS hints ───────────────────────────────
        if ttl is not None:
            self._process_ttl(src_ip, ttl, now_ts)

        # ── Phase 4: mDNS / WS-Discovery detection ──────────────────────────
        if proto == "UDP" and dst_port in (5353, 3702):
            self._process_discovery_packet(src_ip, dst_ip, dst_port, pkt, now_ts)

        self._process_flow_data(src_ip=src_ip, src_mac=src_mac,
                                dst_ip=dst_ip, src_port=src_port,
                                dst_port=dst_port, proto=proto, ts=now_ts,
                                trust_dst_port=False)

    def _process_ttl(self, ip: str, ttl: int, ts: float):
        """Extract TTL as OS hint evidence."""
        asset = self.inventory.get(ip)
        if not asset:
            return

        # Infer initial TTL (common values)
        if ttl <= 64:
            inferred_initial = 64
            os_hint = "Linux/Unix-like"
            confidence = "LOW"
        elif ttl <= 128:
            inferred_initial = 128
            os_hint = "Windows-like"
            confidence = "LOW"
        elif ttl <= 255:
            inferred_initial = 255
            os_hint = "Network device (Cisco/Solaris)"
            confidence = "TENTATIVE"
        else:
            return

        # Add as evidence only once
        existing = any(
            e.type == "os_hint" and e.value == os_hint
            for e in asset.evidence
        )
        if not existing:
            asset.add_os_hint(
                f"{os_hint} (observed TTL: {ttl}, inferred initial: {inferred_initial})",
                confidence=confidence
            )
            self._log(f"{ip} -> OS hint: {os_hint} (TTL: {ttl})", "dim white")

    def _process_discovery_packet(self, src_ip, dst_ip, dst_port, pkt, ts):
        """
        Parse mDNS/WS-Discovery announcements for device identification.
        Passive only — we never send discovery requests.
        """
        from scapy.layers.dns import DNS
        from scapy.packet import Raw

        asset = self.inventory.get(src_ip)
        if not asset:
            return

        service_name = None
        service_type = None

        # mDNS (port 5353)
        if dst_port == 5353 and DNS in pkt:
            dns = pkt[DNS]
            if dns.qr == 0:  # Query
                # We're observing queries — evidence of client activity
                if dns.qd:
                    qname = dns.qd.qname.decode() if hasattr(dns.qd.qname, 'decode') else str(dns.qd.qname)
                    service_name = qname
                    service_type = "mDNS query"
            elif dns.qr == 1 and dns.ancount > 0:  # Answer
                for i in range(dns.ancount):
                    try:
                        ans = dns.an[i]
                        if hasattr(ans, 'rrname'):
                            name = ans.rrname.decode() if hasattr(ans.rrname, 'decode') else str(ans.rrname)
                            if name.endswith('.local.'):
                                service_name = name
                                service_type = "mDNS announcement"
                                break
                    except Exception:
                        continue

        # WS-Discovery (port 3702)
        elif dst_port == 3702:
            # WS-Discovery uses SOAP/XML — we can detect it but parsing is complex
            # For now, just note that WS-Discovery was observed
            service_name = "WS-Discovery"
            service_type = "WS-Discovery observed"

        if service_name:
            # Add discovery evidence
            existing = any(
                e.type == "discovery" and e.value == service_name
                for e in asset.evidence
            )
            if not existing:
                asset.add_evidence(
                    evidence_type="discovery",
                    value=service_name,
                    weight=15,
                    source="mDNS" if dst_port == 5353 else "WS-Discovery",
                    confidence="HIGH",
                    detail=f"Device announced via {service_type}: {service_name}"
                )
                self._log(f"{src_ip} -> Discovery: {service_name} ({service_type})", "green")

    def _process_flow_data(self, src_ip, src_mac, dst_ip, dst_port, proto, ts,
                           src_port=None, alert=None, trust_dst_port=True):
        if not self.inventory.is_asset_ip(src_ip):
            return
        if not self.inventory.is_asset_ip(dst_ip):
            dst_ip = None

        from scrutics.classifier.oui import lookup_vendor, is_ot_vendor
        from scrutics.classifier.protocol import classify_by_ports, known_service_ports
        from scrutics.classifier.signatures import get_signature

        self.inventory.update(ip=src_ip, mac=src_mac, dst_ip=dst_ip, dst_port=dst_port)
        service_ports = known_service_ports()
        self._record_topology_edge(src_ip, dst_ip, src_port, dst_port, proto, service_ports, ts)

        # ── Phase 4: Add port signature evidence ────────────────────────────
        for port in (src_port, dst_port):
            if port and port > 0:
                sig = get_signature(port, proto)
                if sig:
                    asset = self.inventory.get(src_ip)
                    if asset:
                        # Add port evidence
                        existing = any(
                            e.type == "port" and e.value == str(port)
                            for e in asset.evidence
                        )
                        if not existing:
                            asset.add_evidence(
                                evidence_type="port",
                                value=str(port),
                                weight=sig.weight,
                                source="traffic",
                                confidence=sig.confidence,
                                detail=f"Observed {sig.name} on port {port} ({sig.category})"
                            )
                            if sig.category == "OT":
                                self._log(f"{src_ip} -> OT port: {port} ({sig.name})", "cyan")

        if src_port in service_ports:
            self.inventory.credit_listener_port(src_ip, src_port)

        if dst_ip and dst_port and (trust_dst_port or dst_port in service_ports):
            self.inventory.credit_listener_port(dst_ip, dst_port)
            dst_asset = self.inventory.get(dst_ip)
            if dst_asset and dst_asset.ports_seen:
                self._classify_and_score(dst_asset)
                from scrutics.classifier.protocol import ICS_PORTS
                if dst_port in ICS_PORTS:
                    seen = self._logged_dst_ports.setdefault(dst_ip, set())
                    if dst_port not in seen:
                        seen.add(dst_port)
                        self._log(f"{dst_ip} <- port {dst_port} ({proto or '?'}) from {src_ip}", "cyan")

        asset = self.inventory.get(src_ip)
        if asset:
            if asset.vendor == "Unknown" and src_mac:
                vendor = lookup_vendor(src_mac, self._get_oui_db())
                asset.vendor = vendor
                asset.is_ot_vendor = is_ot_vendor(vendor)
                if asset.is_ot_vendor:
                    self._log(f"{src_ip} -> OUI match: {vendor}", "yellow")
                    # Add vendor evidence
                    asset.add_evidence(
                        evidence_type="vendor",
                        value=vendor,
                        weight=30,
                        source="OUI",
                        confidence="HIGH",
                        detail=f"MAC OUI matches OT vendor {vendor}"
                    )
                elif vendor != "Unknown":
                    asset.add_evidence(
                        evidence_type="vendor",
                        value=vendor,
                        weight=15,
                        source="OUI",
                        confidence="MEDIUM",
                        detail=f"MAC OUI: {vendor}"
                    )

            # Classify asset based on ports it listens on OR contacts
            if asset.ports_seen or asset.contacted_ports:
                self._classify_and_score(asset)

                # Add protocol evidence from classification
                if asset.protocols:
                    for proto_name in asset.protocols:
                        if proto_name != "Unknown":
                            existing = any(
                                e.type == "protocol" and e.value == proto_name
                                for e in asset.evidence
                            )
                            if not existing:
                                asset.add_evidence(
                                    evidence_type="protocol",
                                    value=proto_name,
                                    weight=20,
                                    source="traffic",
                                    confidence="HIGH",
                                    detail=f"Observed {proto_name} protocol"
                                )

            self._check_behavioral_constraints(asset, dst_ip, dst_port, ts)

            if not self.no_baseline:
                anomaly = self.baseline.observe(
                    ip=src_ip, timestamp=ts,
                    initiates=asset.initiates,
                    peers=set(asset.peer_ips),
                )
                asset.behavioral_score     = self.baseline.get_behavioral_score(src_ip)
                asset.directionality_score = self.baseline.get_directionality_score(src_ip)
                asset.baseline_status      = self.baseline.get_status(src_ip)
                self._recompute_confidence(asset)

                if anomaly:
                    sev = anomaly.get("severity", "MEDIUM")
                    style = "bold red" if sev == "HIGH" else "yellow"
                    self._log(f"! {src_ip} [{anomaly['type']}] {anomaly['detail']}", style)
                    if self.writer:
                        self.writer.write_anomaly(anomaly)
                    if self.sink_manager:
                        self.sink_manager.emit_anomaly(anomaly)

        if alert:
            sev_map = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
            sev = sev_map.get(alert.get("severity", 3), "MEDIUM")
            alert_entry = {
                "ip": src_ip, "timestamp": ts, "type": "SURICATA_ALERT",
                "detail": f"{alert.get('signature','?')} [{alert.get('category','')}]",
                "severity": sev,
            }
            self.baseline.anomaly_log.append(alert_entry)
            self._log(f"! SURICATA {src_ip} -- {alert.get('signature','?')}",
                      "bold red" if sev == "HIGH" else "yellow")
            if self.writer:
                self.writer.write_anomaly(alert_entry)
            if self.sink_manager:
                self.sink_manager.emit_anomaly(alert_entry)

        self._packet_count += 1
        if self.progress_callback:
            self.progress_callback(self._packet_count)

    def _classify_and_score(self, asset):
        from scrutics.classifier.protocol import classify_by_ports

        # Classify based solely on ports the asset is LISTENING on
        result = classify_by_ports(asset.ports_seen, mac=asset.mac)

        # If the asset has no listening ports, it cannot be classified as OT/IT by itself.
        # It might be a client that only talks to OT devices.
        if not asset.ports_seen:
            # Override classification: treat as unknown with special role
            asset.is_ot = None
            asset.role = "Possible OT Client"
            asset.confidence = "LOW"
            # We'll cap confidence_pct later in _recompute_confidence
            # but we also clear the protocol_score because no listening ports
            asset.protocol_score = 0
            # Keep the behavioral/directional scores as-is (they reflect client behavior)
            # Then skip the rest of the normal classification logic.
            # ── NEW: Apply constraints from contacted ports ─────────────────
            self._apply_constraints_from_contacted_ports(asset)
            return

        # Normal path for assets with listening ports
        asset.protocols = result["protocols"]
        asset.role = result["role"]
        asset.is_ot = result["is_ot"]
        asset.confidence = result["confidence"]

        if result.get("behavioral_constraints"):
            asset.behavioral_constraints = result["behavioral_constraints"]

        # Recompute OUI and protocol scores normally
        asset.oui_score = oui_score(asset.is_ot_vendor)
        asset.protocol_score = protocol_score(
            matched_ics=result["is_ot"] is True,
            matched_it=result["is_ot"] is False,
        )
        # Confidence will be recomputed in _recompute_confidence
        # No need to call it here; it's called after this method returns.

    def _determine_domain(self, asset) -> str:
        """Determine domain/industry from evidence."""
        # Check for utility/SCADA evidence
        utility_evidence = any(
            "DNP3" in str(e.detail) or "IEC 60870" in str(e.detail) or "ICCP" in str(e.detail)
            for e in asset.evidence
        )
        if utility_evidence:
            return "Utility"

        # Check for building automation
        building_evidence = any(
            "BACnet" in str(e.detail) or "Niagara" in str(e.detail) or "Metasys" in str(e.detail)
            for e in asset.evidence
        )
        if building_evidence:
            return "Building_Automation"

        # Check for general OT/industrial
        if asset.classification_type == "OT":
            return "Industrial"

        # Check for enterprise IT
        if asset.classification_type == "IT":
            return "Enterprise"

        return "Unknown"

    def _determine_role(self, asset) -> str:
        """Determine asset role from evidence."""
        # Check evidence for specific roles
        if any("Modbus" in str(e.detail) or "S7comm" in str(e.detail) or "FINS" in str(e.detail) for e in asset.evidence):
            return "PLC"

        if any("DNP3" in str(e.detail) or "IEC 60870" in str(e.detail) for e in asset.evidence):
            return "RTU"

        if any("OPC-UA" in str(e.detail) for e in asset.evidence):
            return "OPC-UA_Server"

        if any("PROFINET" in str(e.detail) or "EtherCAT" in str(e.detail) for e in asset.evidence):
            return "Industrial_Ethernet_Device"

        if any("BACnet" in str(e.detail) or "Niagara" in str(e.detail) for e in asset.evidence):
            return "Building_Controller"

        if any("HTTP" in str(e.detail) or "HTTPS" in str(e.detail) for e in asset.evidence):
            return "Web_Service"

        if any("SSH" in str(e.detail) or "RDP" in str(e.detail) for e in asset.evidence):
            return "Remote_Access_Host"

        if any("SNMP" in str(e.detail) for e in asset.evidence):
            return "Network_Device"

        if any("DNS" in str(e.detail) or "DHCP" in str(e.detail) for e in asset.evidence):
            return "Infrastructure_Service"

        if asset.classification_type == "OT" and not asset.role:
            return "OT_Device"

        if asset.classification_type == "IT" and not asset.role:
            return "IT_Device"

        return "Unknown"

    def _record_topology_edge(self, src_ip, dst_ip, src_port, dst_port, proto, service_ports, ts):
        if not src_ip or not dst_ip:
            return
        if not self.inventory.is_asset_ip(src_ip) or not self.inventory.is_asset_ip(dst_ip):
            return

        key = (src_ip, dst_ip)
        edge = self.topology_edges.setdefault(key, {
            "protocols": set(),
            "count": 0,
            "first_seen": ts,
            "last_seen": ts,
            "src_port": src_port,
            "dst_port": dst_port,
        })
        edge["count"] += 1
        edge["last_seen"] = ts
        if edge["first_seen"] is None:
            edge["first_seen"] = ts

        protocol = self._topology_protocol_label(src_port, dst_port, proto, service_ports)
        if protocol:
            edge["protocols"].add(protocol)

    def _topology_protocol_label(self, src_port, dst_port, proto, service_ports):
        from scrutics.classifier.protocol import classify_by_ports

        for port in (dst_port, src_port):
            if port in service_ports:
                result = classify_by_ports({port})
                protocols = [p for p in result.get("protocols", []) if p and p != "Unknown"]
                if protocols:
                    return ", ".join(protocols)
                return str(port)
        return proto or ""

    def _check_behavioral_constraints(self, asset, dst_ip, dst_port, ts):
        """
        Check rule-defined behavioral constraints against observed traffic.
        Fires BEHAVIORAL_VIOLATION anomalies — always HIGH severity.
        Independent of baseline window: fires from the first packet.
        """
        c = asset.behavioral_constraints
        if not c:
            return

        def _allowed(vtype, cooldown=60):
            last = asset._constraint_anomaly_ts.get(vtype)
            if last is not None and (ts - last) < cooldown:
                return False
            asset._constraint_anomaly_ts[vtype] = ts
            return True

        def _emit(vtype, detail):
            anomaly = {
                "ip": asset.ip, "timestamp": ts,
                "type": "BEHAVIORAL_VIOLATION",
                "severity": "HIGH",
                "detail": f"[{vtype}] {detail}",
            }
            self.baseline.anomaly_log.append(anomaly)
            self._log(f"! VIOLATION {asset.ip} [{vtype}] {detail}", "bold red")
            if self.writer:
                self.writer.write_anomaly(anomaly)
            if self.sink_manager:
                self.sink_manager.emit_anomaly(anomaly)

        # never_initiates — device should only respond, never initiate
        if c.get("never_initiates") and asset.initiates:
            if _allowed("NEVER_INITIATES"):
                _emit("NEVER_INITIATES",
                      f"device initiated connection to {dst_ip}:{dst_port}")

        # allowed_peers — device may only communicate with listed IPs
        allowed_peers = c.get("allowed_peers", [])
        if allowed_peers and dst_ip and dst_ip not in allowed_peers:
            key = f"PEER_{dst_ip}"
            if _allowed(key, cooldown=300):
                _emit("DISALLOWED_PEER",
                      f"communicated with {dst_ip} (not in allowed_peers)")

        # allowed_ports — device should only be seen on listed listener ports
        allowed_ports = c.get("allowed_ports", [])
        if allowed_ports and dst_port and dst_port not in allowed_ports:
            key = f"PORT_{dst_port}"
            if _allowed(key, cooldown=300):
                _emit("DISALLOWED_PORT",
                      f"traffic on port {dst_port} (not in allowed_ports)")

        # alert_on_new_port — alert whenever device appears on a port not seen before
        if c.get("alert_on_new_port") and dst_port:
            known = asset._constraint_anomaly_ts.get("_known_ports", set())
            if dst_port not in known:
                known.add(dst_port)
                asset._constraint_anomaly_ts["_known_ports"] = known
                if len(known) > 1:   # skip the very first port — it's expected
                    _emit("NEW_PORT",
                          f"device active on new port {dst_port}")

        # max_new_peers_per_hour — rate limit new peer discovery
        max_peers = c.get("max_new_peers_per_hour")
        if max_peers and dst_ip:
            if dst_ip not in asset.peer_first_seen:
                asset.peer_first_seen[dst_ip] = ts
            cutoff = ts - 3600
            recent_new = sum(1 for t in asset.peer_first_seen.values() if t >= cutoff)
            if recent_new > max_peers:
                if _allowed("PEER_RATE", cooldown=300):
                    _emit("PEER_RATE_EXCEEDED",
                          f"{recent_new} new peers in last hour (limit: {max_peers})")

    def _recompute_confidence(self, asset):
        if not asset.ports_seen and asset.role == "Possible OT Client":
            asset.confidence_pct = min(
                confidence_pct(
                    oui_s=asset.oui_score,
                    protocol_s=asset.protocol_score,
                    behavioral_s=asset.behavioral_score,
                    directional_s=asset.directionality_score,
                ),
                40
            )
            # Also set classification_confidence_pct to the same value
            asset.classification_confidence_pct = asset.confidence_pct
            return

        asset.confidence_pct = confidence_pct(
            oui_s=asset.oui_score,
            protocol_s=asset.protocol_score,
            behavioral_s=asset.behavioral_score,
            directional_s=asset.directionality_score,
        )
        asset.classification_confidence_pct = asset.confidence_pct  # Always set
        
    def request_stop(self):
        """Request that a live capture stop at the next capture interval."""
        self._stop_event.set()

    def start_live(self, interface: str, timeout: int = 60, packet_count: int = 0):
        from scrutics.passive import enforce_passive, verify_passive
        enforce_passive()
        violations = verify_passive()
        if violations:
            raise RuntimeError(f"Passive enforcement compromised: {violations}")
        from scapy.all import sniff

        self._stop_event.clear()
        self._log(f"Passive capture started on {interface}", "cyan")

        deadline = time.monotonic() + timeout if timeout > 0 else None
        captured = 0
        while not self._stop_event.is_set():
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                capture_timeout = min(1.0, remaining)
            else:
                capture_timeout = 1.0

            before = self._packet_count
            sniff(iface=interface, prn=self._process_packet, store=False,
                  count=max(0, packet_count - captured) if packet_count else 0,
                  timeout=capture_timeout, promisc=True)
            captured += self._packet_count - before
            if packet_count and captured >= packet_count:
                break

        self._log("Capture complete", "dim white")

    def start_pcap(self, filepath: str):
        from scrutics.passive import enforce_passive
        enforce_passive()
        from scapy.all import PcapReader
        self._log(f"Streaming PCAP: {filepath}", "cyan")
        count = 0
        with PcapReader(filepath) as packets:
            for pkt in packets:
                self._process_packet(pkt)
                count += 1
        self._log(f"Processed {count} packets", "dim white")

    def start_zeek(self, filepath: str):
        from scrutics.parsers.zeek import extract_flows_from_zeek
        flows = extract_flows_from_zeek(filepath)
        self._log(f"Loaded {len(flows)} flows from Zeek log", "cyan")
        for flow in flows:
            self._process_flow(flow)

    def start_suricata(self, filepath: str):
        from scrutics.parsers.suricata import extract_flows_from_eve
        flows = extract_flows_from_eve(filepath)
        alert_count = sum(1 for f in flows if "alert" in f)
        self._log(f"Loaded {len(flows)} events ({alert_count} alerts) from EVE", "cyan")
        for flow in flows:
            self._process_flow(flow)

    def start_file(self, filepath: str):
        from scrutics.parsers.detector import detect_file_type
        ftype = detect_file_type(filepath)
        self._log(f"File type: {ftype}", "dim white")
        if ftype in ("pcap", "pcapng"):
            self.start_pcap(filepath)
        elif ftype == "zeek":
            self.start_zeek(filepath)
        elif ftype == "suricata":
            self.start_suricata(filepath)
        else:
            self._log(f"Unsupported format: {filepath}", "bold red")
            raise ValueError(f"Cannot parse: {filepath}")

    def _process_flow(self, flow: dict):
        self._process_flow_data(
            src_ip=flow.get("src_ip"), src_mac=flow.get("src_mac"),
            dst_ip=flow.get("dst_ip"), dst_port=flow.get("dst_port"),
            proto=flow.get("proto", "TCP"), ts=flow.get("timestamp", time.time()),
            alert=flow.get("alert"),
        )

    def _apply_constraints_from_contacted_ports(self, asset):
        """
        Apply behavioral constraints from rules that match the asset's contacted ports.
        Uses merge semantics to preserve constraints from multiple matching rules.
        """
        from scrutics.classifier.protocol import load_user_rules, load_builtin_rules, match_rule
        rules = load_user_rules() + load_builtin_rules()
    
        behavioral_fields = {
            "never_initiates",
            "allowed_peers",
            "allowed_ports",
            "alert_on_new_port",
            "max_new_peers_per_hour",
        }
    
        def _extract_constraints(rule):
            return {k: rule[k] for k in behavioral_fields if k in rule}
    
        # First try MAC match
        if asset.mac:
            rule = match_rule(rules, mac=asset.mac)
            if rule:
                constraints = _extract_constraints(rule)
                if constraints:
                    asset.behavioral_constraints.update(constraints)
                    return
    
        # Then try each contacted port
        for port in asset.contacted_ports:
            rule = match_rule(rules, port=port, mac=asset.mac)
            if rule:
                constraints = _extract_constraints(rule)
                if constraints:
                    asset.behavioral_constraints.update(constraints)
                    return