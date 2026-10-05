"""
Passive capture engine. NEVER transmits packets.
All Scapy imports are lazy. Passive enforcement applied before capture.
"""

import math
import time
import datetime
import threading
from collections import deque

from scrutics.db.inventory import AssetInventory
from scrutics.capture.ingest_stats import IngestStats
from scrutics.capture.cooldown import Cooldowns
from scrutics.baseline.baselineengine import BaselineEngine
from scrutics.baseline.scorer import oui_score, protocol_score, confidence_pct, confidence_from_evidence
from scrutics.classifier.protocol import classify_by_ports, classification_evidence_from_ports
from scrutics.classifier.asset_classifier import classify_asset, RULE_SENDS_VALIDATED_OT_REQUESTS
from scrutics.classifier.signatures import (
    get_signature, get_all_service_ports, get_ot_ports,
    get_it_ports, get_infrastructure_ports, get_discovery_ports
)


def _usable_timestamp(ts) -> bool:
    """A real, finite timestamp that maps to a calendar date (rejects NaN, inf, out-of-range)."""
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts):
        return False
    try:
        datetime.datetime.fromtimestamp(ts)
    except (OverflowError, ValueError, OSError):
        return False
    return True


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
        self._mac_to_ip: dict[str, str] = {}
        self._mac_anomaly_ts: dict[str, float] = {}
        self._mac_cooldowns = Cooldowns(self._mac_anomaly_ts)   # keys age out, see Cooldowns
        self._pending_dhcp: dict[str, dict] = {}
        self._MAX_PENDING_DHCP = 1000
        self._stop_event = threading.Event()
        # Rejected input and contained per-item errors; one event log entry per new kind
        self.ingest_stats = IngestStats(log=lambda message: self._log(message, "yellow"))
        self._ingest_index = 0     # packets handed to _ingest_packet in this engine's lifetime
        self._current_item = ("live", 0)   # (path, packet index or line number) being processed
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

    def _ingest_packet(self, pkt, path: str = "live"):
        """
        Process one captured packet; an unexpected error skips only that packet.

        This is the live capture callback, so Scapy never sees the exception and keeps its
        socket. KeyboardInterrupt and SystemExit are not caught.
        """
        self._ingest_index += 1
        self._current_item = (path, self._ingest_index)
        try:
            self._process_packet(pkt)
        except Exception as exc:
            self.ingest_stats.contain(exc, path, self._ingest_index)

    def _ingest_flow(self, flow: dict, path: str, line_no: int):
        """Process one log record; an unexpected error skips only that record."""
        self._current_item = (path, line_no)
        try:
            self._process_flow(flow)
        except Exception as exc:
            self.ingest_stats.contain(exc, path, line_no)

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
        if not _usable_timestamp(now_ts):
            self.ingest_stats.reject("timestamp out of range", *self._current_item)
            return

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

        # Passive DHCPv4 identification enrichment BEFORE asset-IP validation gate
        if proto == "UDP" and (src_port in (67, 68) or dst_port in (67, 68)):
            self._process_dhcp_packet(pkt, now_ts)

        if not src_ip or not src_mac:
            return
        if not self.inventory.is_asset_ip(src_ip):
            return
        if src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        # Extract TTL for OS fingerprinting hints
        if ttl is not None:
            self._process_ttl(src_ip, ttl, now_ts)

        # mDNS (5353) and WS-Discovery (3702) — passive device discovery protocols
        if proto == "UDP" and dst_port in (5353, 3702):
            self._process_discovery_packet(src_ip, dst_ip, dst_port, pkt, now_ts)

        # Modbus TCP payload (port 502), parsed once the source asset is resolved
        modbus_payload = None
        if proto == "TCP" and (src_port == 502 or dst_port == 502) and Raw in pkt:
            modbus_payload = pkt[Raw].load

        self._process_flow_data(src_ip=src_ip, src_mac=src_mac,
                                dst_ip=dst_ip, src_port=src_port,
                                dst_port=dst_port, proto=proto, ts=now_ts,
                                trust_dst_port=False, modbus_payload=modbus_payload)

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
        if not asset.has_evidence("os_hint", os_hint):
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
                # Each question record is guarded like the answers below: a record that is not
                # a question or whose name is not valid UTF-8 is skipped
                for question in dns.qd or []:
                    try:
                        qname = question.qname
                        qname = qname.decode() if hasattr(qname, 'decode') else str(qname)
                    except Exception:
                        continue
                    service_name = qname
                    service_type = "mDNS query"
                    break
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
            if not asset.has_evidence("discovery", service_name):
                asset.add_evidence(
                    evidence_type="discovery",
                    value=service_name,
                    weight=15,
                    source="mDNS" if dst_port == 5353 else "WS-Discovery",
                    confidence="HIGH",
                    detail=f"Device announced via {service_type}: {service_name}"
                )
                self._log(f"{src_ip} -> Discovery: {service_name} ({service_type})", "green")

    def _process_dhcp_packet(self, pkt, ts: float):
        """
        Passive DHCPv4 identification enrichment (UDP 67/68).
        Extracts BOOTP chaddr as client MAC, parses options 12, 55, 60, 81.
        Enriches existing asset or retains in bounded in-memory buffer until asset is created.
        Never creates assets by itself; never directly determines classification_type.
        """
        try:
            from scapy.layers.dhcp import BOOTP, DHCP
        except ImportError:
            return

        bootp = None
        if BOOTP in pkt:
            bootp = pkt[BOOTP]
        elif hasattr(pkt, "haslayer") and pkt.haslayer("Raw"):
            try:
                bootp = BOOTP(bytes(pkt["Raw"].load))
            except Exception:
                bootp = None
        if not bootp:
            return

        chaddr = getattr(bootp, "chaddr", None)
        if not chaddr:
            return

        client_mac = None
        if isinstance(chaddr, (bytes, bytearray)):
            if len(chaddr) >= 6:
                client_mac = ":".join(f"{b:02x}" for b in chaddr[:6])
        elif isinstance(chaddr, str):
            client_mac = chaddr.strip()

        norm_mac = self.inventory._normalize_mac(client_mac)
        if not norm_mac:
            return

        dhcp = None
        if DHCP in pkt:
            dhcp = pkt[DHCP]
        elif bootp and hasattr(bootp, "haslayer") and bootp.haslayer(DHCP):
            dhcp = bootp[DHCP]

        raw_options = getattr(dhcp, "options", []) if dhcp else []
        if not raw_options:
            return

        from scrutics.classifier.dhcp_fingerprints import parse_option_81

        enrichment = {}
        for item in raw_options:
            if not isinstance(item, tuple) or len(item) < 2:
                continue
            opt_key, opt_val = item[0], item[1]

            # Option 12: Host Name
            if opt_key in ("hostname", 12):
                try:
                    if isinstance(opt_val, (bytes, bytearray)):
                        h = opt_val.decode("utf-8", errors="ignore")
                    else:
                        h = str(opt_val)
                    clean_h = h.replace("\x00", "").strip()
                    if clean_h:
                        enrichment["hostname"] = clean_h
                except Exception:
                    pass

            # Option 55: Parameter Request List
            elif opt_key in ("param_req_list", 55):
                try:
                    prl = []
                    if isinstance(opt_val, (bytes, bytearray)):
                        prl = [int(b) for b in opt_val]
                    elif isinstance(opt_val, (list, tuple)):
                        prl = [int(x) for x in opt_val]
                    if prl:
                        enrichment["param_req_list"] = prl
                except Exception:
                    pass

            # Option 60: Vendor Class Identifier
            elif opt_key in ("vendor_class_id", 60):
                try:
                    if isinstance(opt_val, (bytes, bytearray)):
                        v = opt_val.decode("utf-8", errors="ignore")
                    else:
                        v = str(opt_val)
                    clean_v = v.replace("\x00", "").strip()
                    if clean_v:
                        enrichment["vendor_class_id"] = clean_v
                except Exception:
                    pass

            # Option 81: Client FQDN
            elif opt_key in ("client_FQDN", 81):
                try:
                    clean_fqdn = parse_option_81(opt_val)
                    if clean_fqdn:
                        enrichment["fqdn"] = clean_fqdn
                except Exception:
                    pass

        if not enrichment:
            return

        # Attempt to enrich resolved Asset by client MAC
        asset = self.inventory.get_by_mac(norm_mac)
        if asset:
            self._apply_dhcp_enrichment(asset, enrichment)
        else:
            # Buffer pending enrichment for when Asset is subsequently created/resolved
            if len(self._pending_dhcp) >= self._MAX_PENDING_DHCP and norm_mac not in self._pending_dhcp:
                oldest = next(iter(self._pending_dhcp))
                del self._pending_dhcp[oldest]
            if norm_mac in self._pending_dhcp:
                self._pending_dhcp[norm_mac].update(enrichment)
            else:
                self._pending_dhcp[norm_mac] = enrichment

    def _apply_dhcp_enrichment(self, asset, enrichment: dict):
        """
        Apply parsed DHCP enrichment data to an existing Asset.
        Does not modify OUI vendor fields or directly alter classification_type.
        """
        if not asset or not enrichment:
            return

        # Option 12: Host Name
        if "hostname" in enrichment:
            host = enrichment["hostname"]
            asset.hostname = host
            asset.add_evidence(
                evidence_type="hostname",
                value=host,
                weight=5,
                source="DHCP",
                confidence="LOW",
                detail=f"DHCP Option 12 Host Name: {host}"
            )
            self._log(f"{asset.ip} -> DHCP Host Name: {host}", "dim white")

        # Option 55: Parameter Request List
        if "param_req_list" in enrichment:
            from scrutics.classifier.dhcp_fingerprints import lookup_dhcp_fingerprint
            os_match = lookup_dhcp_fingerprint(enrichment["param_req_list"])
            if os_match:
                asset.add_evidence(
                    evidence_type="os_hint",
                    value=os_match,
                    weight=10,
                    source="DHCP",
                    confidence="MEDIUM",
                    detail=f"DHCP Option 55 fingerprint match: {os_match}"
                )
                asset.add_os_hint(f"DHCP fingerprint: {os_match}", confidence="MEDIUM")
                self._log(f"{asset.ip} -> DHCP OS fingerprint: {os_match}", "dim white")

        # Option 60: Vendor Class Identifier
        if "vendor_class_id" in enrichment:
            vci = enrichment["vendor_class_id"]
            # Raw Option 60 evidence
            asset.add_evidence(
                evidence_type="vendor",
                value=vci,
                weight=5,
                source="DHCP",
                confidence="LOW",
                detail=f"DHCP Option 60 Vendor Class Identifier: {vci}"
            )
            from scrutics.classifier.dhcp_fingerprints import classify_option60
            rec = classify_option60(vci)
            if rec:
                asset.add_evidence(
                    evidence_type="vendor",
                    value=rec,
                    weight=10,
                    source="DHCP",
                    confidence="MEDIUM",
                    detail=f"DHCP Option 60 recognized pattern: {rec}"
                )
                self._log(f"{asset.ip} -> DHCP Option 60: {rec}", "dim white")

        # Option 81: Client FQDN
        if "fqdn" in enrichment:
            fqdn = enrichment["fqdn"]
            asset.add_evidence(
                evidence_type="dns",
                value=fqdn,
                weight=5,
                source="DHCP",
                confidence="LOW",
                detail=f"DHCP Option 81 Client FQDN: {fqdn}"
            )
            asset.add_dns_name(fqdn)
            self._log(f"{asset.ip} -> DHCP FQDN: {fqdn}", "dim white")

        # DHCP evidence never changes the class; refresh the explanation that lists it
        classify_asset(asset)

    def _check_pending_dhcp(self, asset):
        """If asset has pending DHCP enrichment, apply it and remove from buffer."""
        if not asset or not asset.mac:
            return
        norm = self.inventory._normalize_mac(asset.mac)
        if norm and norm in self._pending_dhcp:
            enrichment = self._pending_dhcp.pop(norm)
            self._apply_dhcp_enrichment(asset, enrichment)

    def _process_modbus_payload(self, payload_bytes: bytes, src_ip: str, src_port: int, dst_port: int, ts: float):
        """
        Parse Modbus TCP payload and add validated protocol evidence.
        
        Handles multiple complete ADUs within a single payload. Each validated
        Modbus observation adds protocol evidence with higher confidence than
        port-based identification alone.
        
        Args:
            payload_bytes: Raw TCP payload bytes
            src_ip: Source IP address
            src_port: TCP source port
            dst_port: TCP destination port
            ts: Packet timestamp
        """
        from scrutics.parsers.modbus import parse_modbus_payload, get_exception_name
        
        # Get the asset for this IP
        asset = self.inventory.get(src_ip)
        if not asset:
            return
        
        # Parse the payload
        observations = parse_modbus_payload(payload_bytes, src_port, dst_port)
        
        # Add evidence for each validated observation
        for obs in observations:
            # Build detailed description
            func_name = self._get_modbus_function_name(obs.function_code)
            exception_name = get_exception_name(obs.exception_code) if obs.is_exception else None
            # Undefined exception codes keep their raw value so distinct codes stay distinct
            summary_exception_name = exception_name
            if exception_name == "Unknown":
                summary_exception_name = f"Unknown (0x{obs.exception_code:02X})"
            
            # Every valid observation updates the per-protocol summary
            asset.record_protocol_observation(
                "Modbus TCP",
                sends_request=(obs.direction == "to_server"),
                function_code=obs.function_code,
                exception_name=summary_exception_name,
            )
            
            if obs.is_exception:
                detail = f"Modbus TCP Exception: {func_name}, ExceptionCode=0x{obs.exception_code:02X} ({exception_name}), TransID=0x{obs.transaction_id:04X}, UnitID=0x{obs.unit_id:02X}, direction={obs.direction}"
            else:
                detail = f"Modbus TCP: {func_name}, TransID=0x{obs.transaction_id:04X}, UnitID=0x{obs.unit_id:02X}, direction={obs.direction}"
                
                # Add address/quantity for function codes 03 and 04
                if obs.starting_address is not None and obs.quantity is not None:
                    detail += f", StartAddr=0x{obs.starting_address:04X}, Quantity={obs.quantity}"
            
            # Check for existing protocol evidence (avoid duplicates)
            if not asset.has_evidence_from("protocol", "Modbus TCP", "modbus_parser"):
                # Add validated protocol evidence
                # Uses same weight as port-based (20) but with HIGH confidence and modbus_parser source
                asset.add_evidence(
                    evidence_type="protocol",
                    value="Modbus TCP",
                    weight=20,
                    source="modbus_parser",
                    confidence="HIGH",
                    detail=detail
                )
                self._log(f"{src_ip} -> Modbus TCP validated: {func_name}", "cyan")
    
    def _get_modbus_function_name(self, func_code: int) -> str:
        """
        Get human-readable name for Modbus function code.
        
        Args:
            func_code: Modbus function code (0x01-0xFF)
            
        Returns:
            Human-readable function name
        """
        # Check if this is an exception (high bit set)
        if func_code & 0x80:
            base_code = func_code & 0x7F
            base_name = self._get_modbus_function_name(base_code)
            return f"Exception {base_name}"
        
        # Map function codes to names
        func_names = {
            0x01: "Function 0x01 (Read Coils)",
            0x02: "Function 0x02 (Read Discrete Inputs)",
            0x03: "Function 0x03 (Read Holding Registers)",
            0x04: "Function 0x04 (Read Input Registers)",
            0x05: "Function 0x05 (Write Single Coil)",
            0x06: "Function 0x06 (Write Single Register)",
            0x0F: "Function 0x0F (Write Multiple Coils)",
            0x10: "Function 0x10 (Write Multiple Registers)",
        }
        
        return func_names.get(func_code, f"Function 0x{func_code:02X}")

    def _process_flow_data(self, src_ip, src_mac, dst_ip, dst_port, proto, ts,
                           src_port=None, alert=None, trust_dst_port=True,
                           modbus_payload=None):
        if not self.inventory.is_asset_ip(src_ip):
            return
        if not self.inventory.is_asset_ip(dst_ip):
            dst_ip = None

        from scrutics.classifier.oui import (
            lookup_vendor, is_ot_vendor, classify_vendor, lookup_oui_metadata,
            VENDOR_CLASS_OT, VENDOR_CLASS_IT, VENDOR_CLASS_NEUTRAL, VENDOR_CLASS_UNKNOWN,
        )
        from scrutics.classifier.protocol import classify_by_ports, known_service_ports
        from scrutics.classifier.signatures import get_signature

        # ── Check for MAC change / device mobility anomalies ──
        if src_mac and src_mac.strip().lower() != "unknown":
            norm_mac = src_mac.strip().lower()
            existing_asset = self.inventory.get(src_ip)
            if existing_asset and existing_asset.mac and existing_asset.mac.strip().lower() != "unknown":
                old_mac = existing_asset.mac.strip().lower()
                if old_mac != norm_mac:
                    key = f"MAC_CHANGED_{src_ip}_{norm_mac}"
                    if self._mac_cooldowns.allow(key, ts, 300):
                        anomaly = {
                            "ip": src_ip,
                            "timestamp": ts,
                            "type": "MAC_CHANGED",
                            "severity": "HIGH",
                            "detail": f"Device MAC changed from {existing_asset.mac} to {src_mac}",
                        }
                        self.baseline.anomaly_log.append(anomaly)
                        self._log(f"! {src_ip} [MAC_CHANGED] {anomaly['detail']}", "bold red")
                        if self.writer:
                            self.writer.write_anomaly(anomaly)
                        if self.sink_manager:
                            self.sink_manager.emit_anomaly(anomaly)

            # Check if this MAC was previously associated with another IP (DEVICE_MOVED)
            existing_by_mac = self.inventory.get_by_mac(norm_mac)
            prior_ip = existing_by_mac.ip if (existing_by_mac and existing_by_mac.ip) else self._mac_to_ip.get(norm_mac)
            if prior_ip and prior_ip != src_ip:
                key = f"DEVICE_MOVED_{norm_mac}_{src_ip}"
                if self._mac_cooldowns.allow(key, ts, 300):
                    anomaly = {
                        "ip": src_ip,
                        "timestamp": ts,
                        "type": "DEVICE_MOVED",
                        "severity": "MEDIUM",
                        "detail": f"Device with MAC {src_mac} moved from {prior_ip} to {src_ip}",
                    }
                    self.baseline.anomaly_log.append(anomaly)
                    self._log(f"! {src_ip} [DEVICE_MOVED] {anomaly['detail']}", "yellow")
                    if self.writer:
                        self.writer.write_anomaly(anomaly)
                    if self.sink_manager:
                        self.sink_manager.emit_anomaly(anomaly)

            self._mac_to_ip[norm_mac] = src_ip

        # Resolve asset identity via AssetInventory.get_or_create (called by inventory.update)
        asset = self.inventory.update(ip=src_ip, mac=src_mac, dst_ip=dst_ip, dst_port=dst_port, timestamp=ts)
        if asset:
            self._check_pending_dhcp(asset)
        # Runs after asset resolution so the first packet from a new device keeps its observation
        if asset and modbus_payload is not None:
            self._process_modbus_payload(modbus_payload, src_ip, src_port, dst_port, ts)
        service_ports = known_service_ports()

        # Add evidence for each port matched against the signature database
        for port in (src_port, dst_port):
            if port and port > 0:
                sig = get_signature(port, proto)
                if sig and asset:
                    # Add port evidence
                    if not asset.has_evidence("port", str(port)):
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

        if src_port in service_ports and self._credits_listener(src_port, src_port, dst_port, proto):
            self.inventory.credit_listener_port(src_ip, src_port, timestamp=ts)

        if (dst_ip and dst_port and (trust_dst_port or dst_port in service_ports)
                and self._credits_listener(dst_port, src_port, dst_port, proto)):
            self.inventory.credit_listener_port(dst_ip, dst_port, timestamp=ts)
            dst_asset = self.inventory.get(dst_ip)
            if dst_asset and dst_asset.ports_seen:
                self._classify_and_score(dst_asset)
                classify_asset(dst_asset)
                from scrutics.classifier.protocol import ICS_PORTS
                if dst_port in ICS_PORTS:
                    seen = self._logged_dst_ports.setdefault(dst_ip, set())
                    if dst_port not in seen:
                        seen.add(dst_port)
                        self._log(f"{dst_ip} <- port {dst_port} ({proto or '?'}) from {src_ip}", "cyan")
        if asset is None:
            asset = self.inventory.get(src_ip)

        # Resolve destination Asset for topology edge creation.
        # An edge is only created when BOTH endpoints are resolved Assets at capture time.
        # If dst_ip was credited as a listener port or already known, it is resolved.
        # Unresolved destinations produce no topology edge — this is deliberate.
        # topology_edges is an asset relationship aggregate, not a record of
        # every unresolved communication observation.
        dst_asset = self.inventory.get(dst_ip) if dst_ip else None
        if dst_asset:
            self._check_pending_dhcp(dst_asset)
        self._record_topology_edge(
            src_asset=asset, dst_asset=dst_asset,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            proto=proto, service_ports=service_ports, ts=ts,
        )
        if asset:
            if asset.vendor == "Unknown" and src_mac:
                vendor = lookup_vendor(src_mac, self._get_oui_db())
                asset.vendor = vendor
                asset.vendor_class = classify_vendor(vendor)
                asset.is_ot_vendor = (asset.vendor_class == VENDOR_CLASS_OT)
                if asset.vendor_class == VENDOR_CLASS_OT:
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
                elif asset.vendor_class == VENDOR_CLASS_IT:
                    asset.add_evidence(
                        evidence_type="vendor",
                        value=vendor,
                        weight=15,
                        source="OUI",
                        confidence="MEDIUM",
                        detail=f"MAC OUI matches IT/networking vendor {vendor}"
                    )
                elif asset.vendor_class == VENDOR_CLASS_NEUTRAL:
                    asset.add_evidence(
                        evidence_type="vendor",
                        value=vendor,
                        weight=10,
                        source="OUI",
                        confidence="MEDIUM",
                        detail=f"MAC OUI matches dual-use/infrastructure vendor {vendor}"
                    )
                elif vendor != "Unknown":
                    asset.add_evidence(
                        evidence_type="vendor",
                        value=vendor,
                        weight=5,
                        source="OUI",
                        confidence="LOW",
                        detail=f"MAC OUI: {vendor}"
                    )

            # Enrich with curated OUI metadata (device family hint)
            if src_mac and src_mac.strip().lower() != "unknown":
                meta = lookup_oui_metadata(src_mac)
                if meta and meta.get("device_family_hint"):
                    hint = meta["device_family_hint"]
                    asset.add_evidence(
                        evidence_type="os_hint",
                        value=hint,
                        weight=5,
                        source="OUI_metadata",
                        confidence="LOW",
                        detail=f"OUI device family hint: {hint}",
                    )

            # Port-based role, protocol names and legacy scores
            if asset.ports_seen or asset.contacted_ports:
                self._classify_and_score(asset)

            # Decide the classification from the asset's current state
            classify_asset(asset)

            self._check_behavioral_constraints(asset, dst_ip, dst_port, ts)

            if not self.no_baseline:
                anomaly = self.baseline.observe(
                    ip=src_ip, timestamp=ts,
                    initiates=asset.initiates,
                    peers=set(asset.peers_not_given_to(self.baseline.device(src_ip))),
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

    def _credits_listener(self, port, src_port, dst_port, proto):
        """
        Whether a packet shows that `port` is a service offered by its endpoint.

        The DHCP client port 68 is never a service (RFC 2131 section 4.1). When the
        source and destination ports are equal, either peer could be the server, so
        the port is credited only if its signature votes OT or IT; then both
        endpoints are credited.
        """
        if port == 68:
            return False
        if src_port == dst_port:
            sig = get_signature(port, proto)
            return sig is not None and sig.category in ("OT", "IT")
        return True

    def _classify_and_score(self, asset):
        from scrutics.classifier.protocol import classify_by_ports

        # Classify based solely on ports the asset is LISTENING on
        result = classify_by_ports(asset.ports_seen, mac=asset.mac)

        # If the asset has no listening ports, it cannot be classified as OT/IT by itself.
        # It might be a client that only talks to OT devices.
        if not asset.ports_seen:
            # No listening ports; the classifier sets the role.
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

    def _record_topology_edge(self, src_asset, dst_asset, src_ip, dst_ip,
                               src_port, dst_port, proto, service_ports, ts):
        """
        Record a topology edge between two resolved Assets.

        INVARIANT: Both src_asset and dst_asset must be resolved Asset objects.
        An edge is only created when BOTH endpoints are resolved Assets at
        capture time. topology_edges is an asset relationship aggregate, not
        a record of every unresolved communication observation. Unresolved
        destinations produce no topology edge — this is deliberate and must
        not be "fixed" later by retrospective IP→Asset reconstruction.

        Edge key uses Asset.primary_key for persistent identity that survives
        IP changes. source_ip/destination_ip are stored as metadata representing
        the most-recently-observed IPs for this aggregate edge — NOT identity keys.
        Asset.ip_history is the authoritative historical IP-assignment timeline.
        """
        # Both endpoints must be resolved Assets — no exceptions.
        if not src_asset or not dst_asset:
            return

        src_pk = src_asset.primary_key
        dst_pk = dst_asset.primary_key

        # Self-loops are not meaningful topology edges.
        if src_pk == dst_pk:
            return

        key = (src_pk, dst_pk)
        edge = self.topology_edges.setdefault(key, {
            "protocols": set(),
            "count": 0,
            "first_seen": ts,
            "last_seen": ts,
            "src_port": src_port,
            "dst_port": dst_port,
            # Edge metadata: most-recently-observed IPs for this aggregate edge.
            # These are NOT identity keys. Asset.ip_history is authoritative
            # for historical IP assignments.
            "source_ip": src_ip,
            "destination_ip": dst_ip,
        })
        edge["count"] += 1
        edge["last_seen"] = ts
        if edge["first_seen"] is None:
            edge["first_seen"] = ts
        # Update IP metadata to reflect the most recent observation.
        edge["source_ip"] = src_ip
        edge["destination_ip"] = dst_ip

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
            return asset.constraint_alert_allowed(vtype, ts, cooldown)

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
            asset.record_peer_first_seen(dst_ip, ts)
            recent_new = asset.peers_first_seen_since(ts - 3600)
            if recent_new > max_peers:
                if _allowed("PEER_RATE", cooldown=300):
                    _emit("PEER_RATE_EXCEEDED",
                          f"{recent_new} new peers in last hour (limit: {max_peers})")

    def _recompute_confidence(self, asset):
        # Cap for clients: no listening service, has contacted services, and is not
        # decided by validated OT requests it sends
        if (not asset.ports_seen and asset.contacted_ports
                and asset.classification_rule != RULE_SENDS_VALIDATED_OT_REQUESTS):
            asset.confidence_pct = min(
                confidence_pct(
                    oui_s=asset.oui_score,
                    protocol_s=asset.protocol_score,
                    behavioral_s=asset.behavioral_score,
                    directional_s=asset.directionality_score,
                ),
                40
            )
            return

        asset.confidence_pct = confidence_pct(
            oui_s=asset.oui_score,
            protocol_s=asset.protocol_score,
            behavioral_s=asset.behavioral_score,
            directional_s=asset.directionality_score,
        )
        
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
            sniff(iface=interface, prn=self._ingest_packet, store=False,
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
        self._stop_event.clear()
        self._log(f"Streaming PCAP: {filepath}", "cyan")
        count = 0
        with PcapReader(filepath) as packets:
            for pkt in packets:
                if self._stop_event.is_set():
                    break
                self._ingest_packet(pkt, "pcap")
                count += 1
        self._log(f"Processed {count} packets", "dim white")

    def start_zeek(self, filepath: str):
        from scrutics.parsers.zeek import iter_zeek_flows
        self._stop_event.clear()
        flows = list(iter_zeek_flows(filepath, self.ingest_stats))
        self._log(f"Loaded {len(flows)} flows from Zeek log", "cyan")
        for line_no, flow in flows:
            if self._stop_event.is_set():
                break
            self._ingest_flow(flow, "zeek", line_no)

    def start_suricata(self, filepath: str):
        from scrutics.parsers.suricata import iter_eve_flows
        self._stop_event.clear()
        flows = list(iter_eve_flows(filepath, self.ingest_stats))
        alert_count = sum(1 for _, f in flows if "alert" in f)
        self._log(f"Loaded {len(flows)} events ({alert_count} alerts) from EVE", "cyan")
        for line_no, flow in flows:
            if self._stop_event.is_set():
                break
            self._ingest_flow(flow, "suricata", line_no)

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
        ts = flow.get("timestamp", time.time())
        if not _usable_timestamp(ts):
            self.ingest_stats.reject("timestamp out of range", *self._current_item)
            return
        self._process_flow_data(
            src_ip=flow.get("src_ip"), src_mac=flow.get("src_mac"),
            dst_ip=flow.get("dst_ip"), dst_port=flow.get("dst_port"),
            proto=flow.get("proto", "TCP"), ts=ts,
            alert=flow.get("alert"),
        )

    def _apply_constraints_from_contacted_ports(self, asset):
        """
        Apply behavioral constraints from the rule that matches the asset's MAC or, failing that,
        from one rule matching a contacted port.

        Each contacted port matches the first rule match_rule returns for it. Of the ports whose
        rule sets constraints, the highest is used, so the result does not depend on the order
        ports were contacted. The constraints are merged into those already on the asset.
        """
        from scrutics.classifier.protocol import active_rules, match_rule
        rules = active_rules()
    
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
    
        # Then the contacted ports. Only a port named by a rule can match a rule of its own; any
        # other port matches the first applicable rule without a port key, which also shadows
        # every later port rule. Rules after that one can never match, so the scan stops there.
        first_rule_by_port = {}
        portless_rule = None
        for rule in rules:
            if "port" not in rule:
                if match_rule([rule], mac=asset.mac):
                    portless_rule = rule
                    break
                continue
            port = rule["port"]
            try:
                hash(port)
            except TypeError:
                continue                    # an unhashable port never equals a contacted port
            if port not in first_rule_by_port and match_rule([rule], port=port, mac=asset.mac):
                first_rule_by_port[port] = rule

        if portless_rule is not None and _extract_constraints(portless_rule):
            # Only reachable when the asset has no MAC (with a MAC the step above returns this
            # rule): any contacted port can resolve to it, so ports are looked up one by one
            for port in sorted(asset.contacted_ports, reverse=True):
                rule = match_rule(rules, port=port, mac=asset.mac)
                if rule:
                    constraints = _extract_constraints(rule)
                    if constraints:
                        asset.behavioral_constraints.update(constraints)
                        return
            return

        for port in sorted((p for p in first_rule_by_port if p in asset.contacted_ports), reverse=True):
            constraints = _extract_constraints(first_rule_by_port[port])
            if constraints:
                asset.behavioral_constraints.update(constraints)
                return