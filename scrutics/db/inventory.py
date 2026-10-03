"""In-memory asset inventory with multi-factor confidence scoring."""

from dataclasses import dataclass, field, InitVar
from typing import Optional, Any, Union
import bisect
import csv
import datetime
import ipaddress
import time

# Evidence weights (moved here for central definition)
EVIDENCE_WEIGHT_OT_VENDOR = 30
EVIDENCE_WEIGHT_OT_LISTEN_PORT = 10
EVIDENCE_WEIGHT_OT_CONTACT_PORT = 3
EVIDENCE_WEIGHT_OT_PROTOCOL = 20
EVIDENCE_WEIGHT_BEHAVIOR_INITIATES = 5
EVIDENCE_WEIGHT_OS_HINT = 5
EVIDENCE_WEIGHT_DISCOVERY = 15
EVIDENCE_WEIGHT_IT_PORT = 5

# Separator for classification conflict notes in a single CSV cell
CONFLICT_SEPARATOR = "; "

# Retention limits per asset. A value beyond its limit is not kept; the asset counts the refused
# additions instead, so truncation is visible in exports and summaries.
MAX_IP_HISTORY = 256                  # IP episodes, the most recent ones
MAX_EVIDENCE_VALUES_PER_TYPE = 64     # distinct values per evidence type, the first ones seen
MAX_DNS_NAMES = 64                    # the first names seen
MAX_PEERS = 4096                      # peer IPs and peer first-seen times, the first ones seen


def split_conflicts(text: str | None) -> list:
    """Parse a CSV conflicts cell back into the list of conflict notes."""
    if not text:
        return []
    return [note for note in text.split(CONFLICT_SEPARATOR) if note]


def is_inventory_ip(
    ip: str | None,
    *,
    include_public_ips: bool = False,
    cidrs: list[ipaddress.IPv4Network] | None = None,
) -> bool:
    """
    Return True for device IPs that should appear in inventory.

    Broadcast, multicast, unspecified, and subnet-broadcast-looking .255
    addresses are traffic targets, not assets.
    """
    # Only dotted-quad text is an address here; ipaddress would also accept packed bytes and ints
    if not ip or not isinstance(ip, str):
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    if addr.is_unspecified or addr.is_multicast:
        return False
    if addr.is_loopback or addr.is_reserved:
        return False
    if ip == "255.255.255.255":
        return False
    if ip.rsplit(".", 1)[-1] == "255":
        return False
    if cidrs:
        return any(addr in network for network in cidrs)
    if not include_public_ips and not (addr.is_private or addr.is_link_local):
        return False
    return True


@dataclass
class Evidence:
    """Structured evidence for asset classification."""
    type: str          # "vendor" | "protocol" | "port" | "behavior" | "os_hint"
    value: str         # "Siemens" | "S7comm" | "502" | "initiates"
    weight: int        # 0-100 contribution to confidence
    source: str        # "OUI" | "traffic" | "baseline" | "config"
    confidence: str    # "HIGH" | "MEDIUM" | "LOW" | "TENTATIVE"
    detail: str = ""   # Optional explanation

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "value": self.value,
            "weight": self.weight,
            "source": self.source,
            "confidence": self.confidence,
            "detail": self.detail,
        }


@dataclass
class ProtocolObservationSummary:
    """Accumulated validated observations of one protocol on one asset."""
    sends_requests: bool = False       # asset sent at least one request to a server
    answers_as_server: bool = False    # asset sent at least one response as a server
    function_codes: dict = field(default_factory=dict)  # function code as observed -> count
    exceptions: dict = field(default_factory=dict)      # exception name -> count
    observation_count: int = 0


@dataclass
class Asset:
    ip: str
    mac: str
    vendor: str = "Unknown"
    vendor_class: str = "UNKNOWN"
    is_ot_vendor: bool = False
    hostname: str = ""
    protocols: list = field(default_factory=list)
    ports_seen: set = field(default_factory=set)
    contacted_ports: set = field(default_factory=set)
    role: str = "Unclassified"
    is_ot: InitVar[Optional[Union[bool, str]]] = None
    confidence: str = "LOW"
    oui_score: int = 0
    protocol_score: int = 0
    behavioral_score: int = 0
    directionality_score: int = 0
    confidence_pct: int = 0
    baseline_status: str = "no_data"
    packet_count: int = 0
    peer_ips: set = field(default_factory=set)
    initiates: bool = False
    first_seen: str = ""
    last_seen: str = ""
    last_seen_epoch: float = 0.0
    behavioral_constraints: dict = field(default_factory=dict)
    peer_first_seen: dict = field(default_factory=dict)   # peer_ip -> epoch float
    _constraint_anomaly_ts: dict = field(default_factory=dict)  # type -> epoch float

    # New v0.5.0 fields
    evidence: list = field(default_factory=list)           # List[Evidence]
    os_hints: list = field(default_factory=list)           # List[str] - tentative OS hints
    dns_names: list = field(default_factory=list)          # List[str] - DNS names if observed
    observed_services: list = field(default_factory=list)  # List[dict] - {port, protocol, last_seen}
    classification_type: str = "Unknown"                   # "OT" | "IT" | "Infrastructure" | "Unknown"
    classification_confidence_pct: int = 0                 # Overall confidence based on evidence
    domain: str = "Unknown"                                # "Industrial" | "Building_Automation" | "Utility" | "Enterprise" | "Unknown"
    ip_history: list = field(default_factory=list)         # List[dict] - chronological IP episodes: [{"ip": str, "first_seen": float, "last_seen": float}]
    # protocol name -> ProtocolObservationSummary; in-memory only, not part of repr or equality
    protocol_summaries: dict = field(default_factory=dict, repr=False, compare=False)
    # Explanation of the current classification decision; in-memory only, not part of repr or equality
    classification_rule: str = field(default="", repr=False, compare=False)
    classification_reason: str = field(default="", repr=False, compare=False)
    classification_conflicts: list = field(default_factory=list, repr=False, compare=False)
    # Additions refused because a retention limit was reached, over the asset's recorded lifetime.
    # Truncation metadata only: never evidence and never classification input.
    ip_history_dropped: int = field(default=0, repr=False, compare=False)
    evidence_overflow: dict = field(default_factory=dict, repr=False, compare=False)  # type -> count
    dns_names_overflow: int = field(default=0, repr=False, compare=False)
    # Every refused peer addition is counted, repeats included: it is not a count of distinct peers
    peer_additions_rejected: int = field(default=0, repr=False, compare=False)
    peer_first_seen_overflow: int = field(default=0, repr=False, compare=False)
    # Derived from peer_ips, in-memory only: the peers in order of first addition, rebuilt (with a
    # new epoch) whenever peer_ips was replaced or changed outside add_peer; and, per baseline IP,
    # (device baseline, epoch, log position) marking how much of the log that baseline was given
    _peer_log: list = field(default_factory=list, init=False, repr=False, compare=False)
    _peer_log_source: Any = field(default=None, init=False, repr=False, compare=False)
    _peer_log_epoch: int = field(default=0, init=False, repr=False, compare=False)
    _baseline_peer_cursors: dict = field(default_factory=dict, init=False, repr=False, compare=False)
    # Derived from evidence, in-memory only (see _synced_evidence_index): lookup keys, vendor
    # values, the number of distinct values per type and the weight total of the records indexed
    # so far. Records whose key cannot be hashed are kept in a list that every lookup also scans.
    _ev_source: Any = field(default=None, init=False, repr=False, compare=False)
    _ev_indexed: int = field(default=0, init=False, repr=False, compare=False)
    _ev_keys: set = field(default_factory=set, init=False, repr=False, compare=False)
    _ev_type_values: set = field(default_factory=set, init=False, repr=False, compare=False)
    _ev_unhashable: list = field(default_factory=list, init=False, repr=False, compare=False)
    _ev_vendor_values: set = field(default_factory=set, init=False, repr=False, compare=False)
    _ev_type_counts: dict = field(default_factory=dict, init=False, repr=False, compare=False)
    _ev_weighted: int = field(default=0, init=False, repr=False, compare=False)
    _ev_weight_total: int = field(default=0, init=False, repr=False, compare=False)
    _ev_weights_exact: bool = field(default=True, init=False, repr=False, compare=False)
    # Derived from dns_names, in-memory only: the names indexed so far
    _dns_source: Any = field(default=None, init=False, repr=False, compare=False)
    _dns_indexed: int = field(default=0, init=False, repr=False, compare=False)
    _dns_set: set = field(default_factory=set, init=False, repr=False, compare=False)
    _dns_unhashable: list = field(default_factory=list, init=False, repr=False, compare=False)
    # Derived from peer_first_seen, in-memory only: its first-seen times in ascending order,
    # rebuilt whenever the dict was replaced or changed outside record_peer_first_seen
    _first_seen_source: Any = field(default=None, init=False, repr=False, compare=False)
    _first_seen_times: list = field(default_factory=list, init=False, repr=False, compare=False)

    def __post_init__(self, is_ot: Optional[Union[bool, str]] = None):
        # Sync vendor_class and is_ot_vendor
        if self.vendor_class != "UNKNOWN" and not self.is_ot_vendor:
            self.is_ot_vendor = (self.vendor_class == "OT")
        elif self.is_ot_vendor and self.vendor_class == "UNKNOWN":
            self.vendor_class = "OT"
        elif self.vendor != "Unknown" and self.vendor_class == "UNKNOWN":
            try:
                from scrutics.classifier.oui import classify_vendor
                self.vendor_class = classify_vendor(self.vendor)
                self.is_ot_vendor = (self.vendor_class == "OT")
            except Exception:
                pass

        # If is_ot was supplied on creation, use it to initialize classification_type
        if is_ot is not None and self.classification_type == "Unknown":
            if is_ot is True or is_ot == "OT":
                self.classification_type = "OT"
            elif is_ot is False or is_ot == "IT":
                self.classification_type = "IT"
            elif isinstance(is_ot, str):
                self.classification_type = is_ot

    @property
    def is_ot(self) -> Optional[bool]:
        """Backward-compatible / derived representation of canonical classification_type."""
        if self.classification_type == "OT":
            return True
        elif self.classification_type in ("IT", "Infrastructure"):
            return False
        return None

    @is_ot.setter
    def is_ot(self, val: Any) -> None:
        """Setting is_ot updates canonical classification_type for backward compatibility."""
        if val is True or val == "OT":
            self.classification_type = "OT"
        elif val is False or val == "IT":
            self.classification_type = "IT"
        elif val is None or val == "Unknown":
            self.classification_type = "Unknown"
        else:
            self.classification_type = str(val)

    def add_evidence(self, evidence_type: str, value: str, weight: int,
                     source: str, confidence: str = "MEDIUM", detail: str = "") -> bool:
        """
        Add evidence, deduplicating by type+value+source. Returns whether a record was stored.

        Each type keeps at most MAX_EVIDENCE_VALUES_PER_TYPE distinct values, the first ones seen.
        A record for a value already kept is stored whatever its source; a new value beyond the
        limit is not stored and is counted in evidence_overflow.
        """
        if self.has_evidence_from(evidence_type, value, source):
            return False
        if self._evidence_type_full(evidence_type) and not self.has_evidence(evidence_type, value):
            self.evidence_overflow[evidence_type] = self.evidence_overflow.get(evidence_type, 0) + 1
            return False

        # Create new evidence
        ev = Evidence(
            type=evidence_type,
            value=value,
            weight=weight,
            source=source,
            confidence=confidence,
            detail=detail
        )
        self.evidence.append(ev)

        # Recalculate classification confidence based on evidence weights
        total_weight = self._evidence_weight_total()
        max_possible = 100
        self.classification_confidence_pct = min(total_weight, max_possible)
        return True

    def load_evidence(self, ev: Evidence) -> bool:
        """
        Append a record read from a saved session as it was saved: duplicates are kept and
        confidence is not recomputed. A new value beyond its type's limit is not kept and is
        counted in evidence_overflow. Returns whether the record was kept.
        """
        if self._evidence_type_full(ev.type) and not self.has_evidence(ev.type, ev.value):
            self.evidence_overflow[ev.type] = self.evidence_overflow.get(ev.type, 0) + 1
            return False
        self.evidence.append(ev)
        return True

    def _evidence_type_full(self, evidence_type) -> bool:
        """Whether the type already has MAX_EVIDENCE_VALUES_PER_TYPE distinct values."""
        self._synced_evidence_index()
        try:
            return self._ev_type_counts.get(evidence_type, 0) >= MAX_EVIDENCE_VALUES_PER_TYPE
        except TypeError:
            return False                    # an unhashable type has no count: no code adds one

    def _synced_evidence_index(self) -> None:
        """
        Bring the evidence lookups up to date with the evidence list.

        Records are only ever appended, by add_evidence, load_evidence or directly, so
        only the records added since the last call are indexed. A replaced or shorter list is
        indexed again from the start. A record changed in place is not noticed.
        """
        evidence = self.evidence
        if self._ev_source is not evidence or len(evidence) < max(self._ev_indexed, self._ev_weighted):
            self._ev_source = evidence
            self._ev_indexed = self._ev_weighted = self._ev_weight_total = 0
            self._ev_weights_exact = True
            self._ev_keys, self._ev_type_values, self._ev_vendor_values = set(), set(), set()
            self._ev_unhashable, self._ev_type_counts = [], {}
        for ev in evidence[self._ev_indexed:]:
            try:
                pair = (ev.type, ev.value)
                if pair not in self._ev_type_values:
                    self._ev_type_values.add(pair)
                    self._ev_type_counts[ev.type] = self._ev_type_counts.get(ev.type, 0) + 1
                self._ev_keys.add((ev.type, ev.value, ev.source))
            except TypeError:
                self._count_unhashable_value(ev)
                self._ev_unhashable.append(ev)
            if ev.type == "vendor" and ev.value and ev.value != "Unknown":
                self._ev_vendor_values.add(str(ev.value))
            self._ev_indexed += 1

    def _count_unhashable_value(self, ev) -> None:
        """Count the value of a record whose key cannot be hashed, unless it is already counted."""
        try:
            hash(ev.type)
        except TypeError:
            return
        try:
            if (ev.type, ev.value) in self._ev_type_values:
                return
        except TypeError:
            pass
        if any(e.type == ev.type and e.value == ev.value for e in self._ev_unhashable):
            return
        self._ev_type_counts[ev.type] = self._ev_type_counts.get(ev.type, 0) + 1

    def _evidence_weight_total(self):
        """
        Sum of all evidence weights. Kept as a running total while every weight is an int;
        any other weight (as a hand-edited session file may hold) falls back to summing the
        list, so the result and any error are those of sum().
        """
        self._synced_evidence_index()
        if self._ev_weights_exact:
            for ev in self.evidence[self._ev_weighted:]:
                if type(ev.weight) not in (int, bool):
                    self._ev_weights_exact = False
                    break
                self._ev_weight_total += ev.weight
                self._ev_weighted += 1
        if not self._ev_weights_exact:
            return sum(e.weight for e in self.evidence)
        return self._ev_weight_total

    def has_evidence(self, evidence_type: str, value) -> bool:
        """Whether any evidence record has this type and value, from any source."""
        self._synced_evidence_index()
        try:
            if (evidence_type, value) in self._ev_type_values:
                return True
        except TypeError:
            return any(e.type == evidence_type and e.value == value for e in self.evidence)
        return any(e.type == evidence_type and e.value == value for e in self._ev_unhashable)

    def has_evidence_from(self, evidence_type: str, value, source: str) -> bool:
        """Whether an evidence record has this type, value and source."""
        self._synced_evidence_index()
        try:
            if (evidence_type, value, source) in self._ev_keys:
                return True
        except TypeError:
            return any(e.type == evidence_type and e.value == value and e.source == source
                       for e in self.evidence)
        return any(e.type == evidence_type and e.value == value and e.source == source
                   for e in self._ev_unhashable)

    def vendor_evidence_values(self) -> set:
        """Text of every vendor evidence value other than empty or "Unknown"."""
        self._synced_evidence_index()
        return self._ev_vendor_values

    def _synced_first_seen_times(self) -> list:
        """First-seen times of all peers, ascending, rebuilt if peer_first_seen changed directly."""
        if (self._first_seen_source is not self.peer_first_seen
                or len(self._first_seen_times) != len(self.peer_first_seen)):
            self._first_seen_times = sorted(self.peer_first_seen.values())
            self._first_seen_source = self.peer_first_seen
        return self._first_seen_times

    def record_peer_first_seen(self, ip: str, timestamp: float) -> None:
        """
        Record when a peer was first contacted; later contacts keep the first time. The first
        MAX_PEERS peers are kept; every later call for a peer not kept is counted in
        peer_first_seen_overflow, repeats included.
        """
        times = self._synced_first_seen_times()
        if ip not in self.peer_first_seen:
            if len(self.peer_first_seen) >= MAX_PEERS:
                self.peer_first_seen_overflow += 1
                return
            self.peer_first_seen[ip] = timestamp
            bisect.insort(times, timestamp)

    def peers_first_seen_since(self, cutoff: float) -> int:
        """Number of peers first contacted at or after cutoff."""
        times = self._synced_first_seen_times()
        return len(times) - bisect.bisect_left(times, cutoff)

    def add_dns_name(self, name: str) -> None:
        """
        Record a DNS name for this asset once, keeping the order names were first seen. Names
        beyond MAX_DNS_NAMES are not kept and are counted in dns_names_overflow.
        """
        names = self.dns_names
        if self._dns_source is not names or len(names) < self._dns_indexed:
            self._dns_source, self._dns_indexed = names, 0
            self._dns_set, self._dns_unhashable = set(), []
        for known in names[self._dns_indexed:]:
            try:
                self._dns_set.add(known)
            except TypeError:
                self._dns_unhashable.append(known)
            self._dns_indexed += 1
        try:
            present = name in self._dns_set or any(known == name for known in self._dns_unhashable)
        except TypeError:
            present = name in names
        if not present:
            if len(names) >= MAX_DNS_NAMES:
                self.dns_names_overflow += 1
            else:
                names.append(name)

    def _synced_peer_log(self) -> list:
        """The peer log, rebuilt from peer_ips if that set was replaced or changed directly."""
        if self._peer_log_source is not self.peer_ips or len(self._peer_log) != len(self.peer_ips):
            self._peer_log = list(self.peer_ips)
            self._peer_log_source = self.peer_ips
            self._peer_log_epoch += 1
        return self._peer_log

    def add_peer(self, ip: str) -> None:
        """
        Record a peer IP this asset communicated with. The first MAX_PEERS peers are kept; every
        later call for a peer not kept is counted in peer_additions_rejected, repeats included.
        """
        log = self._synced_peer_log()
        if ip not in self.peer_ips:
            if len(self.peer_ips) >= MAX_PEERS:
                self.peer_additions_rejected += 1
                return
            self.peer_ips.add(ip)
            log.append(ip)

    def peers_not_given_to(self, baseline) -> list:
        """
        Peers not yet passed to `baseline` (the device baseline of one IP), now marked as passed.

        A baseline is keyed by IP while the asset is keyed by MAC, so each baseline IP the asset
        has used keeps its own position: peers learned at another IP still reach this baseline
        when the asset returns. A baseline object not seen before, or a rebuilt log, gets every
        peer; passing a peer the baseline already has changes nothing.
        """
        log = self._synced_peer_log()
        start = 0
        cursor = self._baseline_peer_cursors.get(baseline.ip)
        if cursor is not None and cursor[0] is baseline and cursor[1] == self._peer_log_epoch:
            start = cursor[2]
        self._baseline_peer_cursors[baseline.ip] = (baseline, self._peer_log_epoch, len(log))
        return log[start:]

    def record_protocol_observation(self, protocol: str, *, sends_request: bool,
                                    function_code: int, exception_name: str | None = None):
        """
        Accumulate one validated protocol observation into the per-protocol summary.
        Does not add evidence and does not change classification or confidence.
        """
        summary = self.protocol_summaries.get(protocol)
        if summary is None:
            summary = ProtocolObservationSummary()
            self.protocol_summaries[protocol] = summary
        if sends_request:
            summary.sends_requests = True
        else:
            summary.answers_as_server = True
        summary.function_codes[function_code] = summary.function_codes.get(function_code, 0) + 1
        if exception_name is not None:
            summary.exceptions[exception_name] = summary.exceptions.get(exception_name, 0) + 1
        summary.observation_count += 1

    def add_os_hint(self, hint: str, confidence: str = "LOW"):
        """Add a tentative OS hint, deduplicated by value."""
        # Check if this exact hint already exists in evidence
        if self.has_evidence("os_hint", hint):
            return
        # If not, add it; the hint is listed only when its evidence record was stored
        if self.add_evidence(
            evidence_type="os_hint",
            value=hint,
            weight=5 if confidence == "LOW" else 10 if confidence == "MEDIUM" else 15,
            source="traffic",
            confidence=confidence,
            detail="Tentative OS hint from passive observation"
        ):
            self.os_hints.append(hint)

    def add_service(self, port: int, protocol: str, last_seen: str):
        """Record an observed service."""
        # Check if service already exists
        for svc in self.observed_services:
            if svc.get("port") == port and svc.get("protocol") == protocol:
                svc["last_seen"] = last_seen
                return
        self.observed_services.append({
            "port": port,
            "protocol": protocol,
            "last_seen": last_seen
        })

    def is_stale(self, now_epoch: float | None = None, timeout: float = 30.0) -> bool:
        """Check if asset has not sent traffic in > timeout seconds (online/offline liveness)."""
        if not self.last_seen_epoch:
            return False
        current = time.time() if now_epoch is None else now_epoch
        return (current - self.last_seen_epoch) > timeout

    @property
    def primary_key(self) -> str:
        """
        Primary identity key for the asset.

        Invariant note:
        MAC is the best passive signal available, not a guaranteed hardware identity --
        spoofable, and Tier 2's own MAC_CHANGED detection exists precisely because it can lie.
        If MAC is unavailable or Unknown, falls back to IP.
        """
        if self.mac and self.mac.strip() and self.mac.strip().lower() != "unknown":
            return self.mac.strip().lower()
        return self.ip

    def record_ip(self, ip: str, timestamp: float) -> None:
        """
        Record chronological IP-assignment episodes.

        ip_history represents chronological assignment episodes, not a deduplicated
        set of unique IPs. If the device was at A, moved to B, and returned to A,
        this produces [A, B, A] in order.
        - If ip matches the most recent episode's IP, updates last_seen.
        - If ip differs from the most recent episode, appends a new episode.
        Never collapses or deduplicates episodes. Only the most recent MAX_IP_HISTORY episodes
        are kept; older ones are dropped and counted in ip_history_dropped.
        """
        if not ip:
            return
        if self.ip_history and self.ip_history[-1].get("ip") == ip:
            self.ip_history[-1]["last_seen"] = timestamp
        else:
            self.ip_history.append({
                "ip": ip,
                "first_seen": timestamp,
                "last_seen": timestamp,
            })
            if len(self.ip_history) > MAX_IP_HISTORY:
                self._drop_oldest_ip_episodes()
        self.ip = ip
        self.last_seen_epoch = timestamp
        try:
            self.last_seen = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass


    def _drop_oldest_ip_episodes(self) -> None:
        """
        Drop the episodes beyond MAX_IP_HISTORY, oldest first. An IP with no episode left also
        loses its baseline cursor; if the asset returns to it, that baseline is given every peer
        again, which changes nothing for the peers it already has.
        """
        excess = len(self.ip_history) - MAX_IP_HISTORY
        dropped = self.ip_history[:excess]
        del self.ip_history[:excess]
        self.ip_history_dropped += excess
        remaining = {episode.get("ip") for episode in self.ip_history}
        for episode in dropped:
            if episode.get("ip") not in remaining:
                self._baseline_peer_cursors.pop(episode.get("ip"), None)

    def to_dict(self) -> dict:
        proto_str = ", ".join(self.protocols) if self.protocols else "Unknown"
        type_str = self.classification_type if self.classification_type != "Unknown" else (
            "OT" if self.is_ot is True else "IT" if self.is_ot is False else "Unknown"
        )

        # Evidence summary for CSV (only first 5 for brevity)
        evidence_summary = "; ".join(
            f"{e.type}:{e.value}({e.weight})" for e in self.evidence[:5]
        )

        left = {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "vendor_class": self.vendor_class,
            "protocol": proto_str,
            "role": self.role,
            "confidence_pct": self.confidence_pct,
            "type": type_str,
            "classification_type": self.classification_type,
            "classification_confidence": self.classification_confidence_pct,
            "evidence_summary": evidence_summary,
            "domain": self.domain,
            "os_hints": "|".join(self.os_hints) if self.os_hints else "",
            "dns_names": "|".join(self.dns_names) if self.dns_names else "",
            "hostname": self.hostname,
        }
        right = {
            "oui_score": self.oui_score,
            "protocol_score": self.protocol_score,
            "behavioral_score": self.behavioral_score,
            "directionality_score": self.directionality_score,
            "baseline_status": self.baseline_status,
            "packet_count": self.packet_count,
            "peer_count": len(self.peer_ips),
            "ports_seen": "|".join(str(p) for p in sorted(self.ports_seen)),
            "contacted_ports": "|".join(str(p) for p in sorted(self.contacted_ports)),
            "initiates": self.initiates,
            "is_ot_vendor": self.is_ot_vendor,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            # Classification basis, appended so existing columns keep their order
            "classification_rule": self.classification_rule,
            "classification_reason": self.classification_reason,
            "classification_conflicts": CONFLICT_SEPARATOR.join(self.classification_conflicts),
            "classification_decision_confidence": self.confidence,
        }
        return {**left, **right}


class AssetInventory:
    def __init__(self, inventory_config: dict | None = None):
        # Current-IP lookup table: ip -> Asset (represents the device CURRENTLY active at this IP)
        self._assets: dict[str, Asset] = {}
        # Primary physical identity index: normalized_mac -> Asset
        self._by_mac: dict[str, Asset] = {}
        if inventory_config is None:
            try:
                from scrutics.config.loader import load_inventory_config
                inventory_config = load_inventory_config()
            except Exception:
                inventory_config = {}
        self._include_public_ips = bool(inventory_config.get("include_public_ips", False))
        self._cidrs = []
        for cidr in inventory_config.get("cidrs", []) or []:
            self._cidrs.append(ipaddress.ip_network(str(cidr), strict=False))

    def is_asset_ip(self, ip: str | None) -> bool:
        return is_inventory_ip(
            ip,
            include_public_ips=self._include_public_ips,
            cidrs=self._cidrs,
        )

    def update(
        self,
        ip: str,
        mac: str = None,
        dst_ip: str = None,
        dst_port: int = None,
        timestamp: float | None = None,
    ) -> Optional[Asset]:
        """
        Update inventory from observed traffic flow.
        Resolves asset identity via get_or_create(), tracks packet count, peer IPs,
        and contacted ports.
        """
        if not self.is_asset_ip(ip):
            return None
        if timestamp is None:
            timestamp = time.time()
        asset = self.get_or_create(ip=ip, mac=mac, timestamp=timestamp)
        if not asset:
            return None
        asset.packet_count += 1

        # Track peers and initiates
        if self.is_asset_ip(dst_ip):
            asset.add_peer(dst_ip)
            asset.initiates = True
            asset.add_evidence(
                evidence_type="behavior",
                value="initiates_connections",
                weight=5,
                source="traffic",
                confidence="MEDIUM",
                detail=f"Initiates connections to {dst_ip}"
            )

        # Track contacted ports
        if dst_port:
            asset.contacted_ports.add(dst_port)

        return asset

    def credit_listener_port(self, ip: str, port: int, timestamp: float | None = None):
        """Credit a listening port to an asset, creating it if not already known."""
        if not self.is_asset_ip(ip) or not port:
            return
        asset = self.get_or_create(ip=ip, mac=None, timestamp=timestamp)
        if asset:
            asset.ports_seen.add(port)

    @staticmethod
    def _normalize_mac(mac: str | None) -> str | None:
        """
        Normalize a MAC address to lowercase colon-separated format.
        Follows existing convention in engine.py (strip + lower) and handles
        hyphenated Windows-style MACs by converting '-' to ':'.
        Returns None if mac is empty, None, 'unknown', or broadcast/zero.
        """
        if not mac:
            return None
        s = mac.strip().lower().replace("-", ":")
        if not s or s == "unknown" or s in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return None
        return s

    def get_or_create(
        self,
        ip: str,
        mac: str | None = None,
        timestamp: float | None = None,
    ) -> Optional[Asset]:
        """
        Resolve or create an Asset according to Tier 2 MAC-based device identity rules.

        Identity invariants:
        1. MAC is the primary physical identity key when known.
           There must never be two simultaneously active _by_mac entries for the same normalized MAC.
        2. The IP index (self._assets) represents the CURRENT device active at that IP.
           When an asset moves from IP A to IP B, self._assets[A] is removed so lookups for A
           do not falsely return the moved asset.
        3. Historical IP assignments live exclusively in Asset.ip_history as chronological episodes.
           A device moving A -> B -> A accumulates [A, B, A] in order; episodes are never collapsed.
        4. When a new MAC claims an IP previously occupied by a different known MAC (MAC_CHANGED),
           a separate Asset is created. Old and new assets are NEVER merged. The old Asset remains
           in _by_mac and can naturally become stale based on its last_seen timestamp.
        5. When MAC is unknown/empty, fallback to pure IP-based identity semantics.
        """
        if not self.is_asset_ip(ip):
            return None

        if timestamp is None:
            timestamp = time.time()
        now_str = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

        norm_mac = self._normalize_mac(mac)
        existing_at_ip = self._assets.get(ip)

        # ── Rule 1: Known MAC already exists in _by_mac ───────────────────────
        # Same physical asset re-observed. It may be at the same IP or a new IP.
        if norm_mac and norm_mac in self._by_mac:
            asset = self._by_mac[norm_mac]
            old_ip = asset.ip

            # If the device moved to a new IP, update current-IP index:
            # remove old IP key so an innocent lookup of old IP does not return this device.
            if old_ip and old_ip != ip:
                if self._assets.get(old_ip) is asset:
                    del self._assets[old_ip]

            # If another device was previously recorded at this new IP in _assets,
            # evict its current-IP pointer (that device is no longer at this IP).
            if existing_at_ip and existing_at_ip is not asset:
                pass

            self._assets[ip] = asset
            asset.record_ip(ip, timestamp)
            if mac and asset.mac != mac and mac != "Unknown":
                asset.mac = mac
            return asset

        # ── Rule 2: Known MAC is new, but IP currently belongs to a DIFFERENT known MAC ──
        # Device replacement / MAC_CHANGED scenario.
        # DO NOT merge. Create a separate Asset for the new MAC.
        # The old asset is removed from the current-IP index, but preserved in _by_mac
        # where its historical state remains intact and it naturally becomes stale.
        if norm_mac and existing_at_ip:
            old_asset_mac = self._normalize_mac(existing_at_ip.mac)
            if old_asset_mac and old_asset_mac != norm_mac:
                # Evict old asset from current-IP index
                del self._assets[ip]

                # Create brand-new Asset for the new physical device
                new_asset = Asset(
                    ip=ip,
                    mac=mac or "Unknown",
                    first_seen=now_str,
                    last_seen=now_str,
                    last_seen_epoch=timestamp,
                )
                new_asset.record_ip(ip, timestamp)
                self._by_mac[norm_mac] = new_asset
                self._assets[ip] = new_asset
                return new_asset

        # ── Rule 3: MAC is unknown / empty / "Unknown" ────────────────────────
        # Pure IP-based fallback. Preserves existing IP-based semantics.
        if not norm_mac:
            if existing_at_ip:
                existing_at_ip.record_ip(ip, timestamp)
                return existing_at_ip
            else:
                asset = Asset(
                    ip=ip,
                    mac="Unknown",
                    first_seen=now_str,
                    last_seen=now_str,
                    last_seen_epoch=timestamp,
                )
                asset.record_ip(ip, timestamp)
                self._assets[ip] = asset
                return asset

        # ── Rule 4: Learning MAC for an existing MAC-less asset at IP ─────────
        if existing_at_ip and not self._normalize_mac(existing_at_ip.mac):
            existing_at_ip.mac = mac or "Unknown"
            self._by_mac[norm_mac] = existing_at_ip
            existing_at_ip.record_ip(ip, timestamp)
            return existing_at_ip

        # ── Rule 5: Brand-new IP + Brand-new MAC ──────────────────────────────
        new_asset = Asset(
            ip=ip,
            mac=mac or "Unknown",
            first_seen=now_str,
            last_seen=now_str,
            last_seen_epoch=timestamp,
        )
        new_asset.record_ip(ip, timestamp)
        self._by_mac[norm_mac] = new_asset
        self._assets[ip] = new_asset
        return new_asset

    def get_by_mac(self, mac: str | None) -> Optional[Asset]:
        """
        Lookup asset by MAC address in the primary physical identity index.
        """
        norm = self._normalize_mac(mac)
        if not norm:
            return None
        return self._by_mac.get(norm)

    def get_all(self) -> list:
        """
        Return all unique assets in inventory.
        Includes both active assets (indexed by current IP) and any historical assets
        (indexed by MAC) whose IP was reassigned to another device.
        """
        seen_ids = set()
        result = []
        for asset in self._by_mac.values():
            aid = id(asset)
            if aid not in seen_ids:
                seen_ids.add(aid)
                result.append(asset)
        for asset in self._assets.values():
            aid = id(asset)
            if aid not in seen_ids:
                seen_ids.add(aid)
                result.append(asset)
        return result

    def get(self, ip: str) -> Optional[Asset]:
        """
        Lookup current asset at IP.
        Represents the CURRENT device active at that IP.
        """
        return self._assets.get(ip)

    def count(self) -> int:
        """
        Return count of unique assets in inventory.
        """
        return len(self.get_all())

    def export_csv(self, path: str):
        assets = self.get_all()
        if not assets:
            return
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=assets[0].to_dict().keys())
            writer.writeheader()
            for asset in assets:
                writer.writerow(asset.to_dict())