"""
OS-hint events: one event per hint an asset gains, not one per packet.

A TTL hint ("Linux/Unix-like (observed TTL: 64, ...)") or a DHCP fingerprint hint is logged when the
asset stores it for the first time. Repeated packets with the same hint log nothing more; the
evidence de-duplication is unchanged. Frames are built with struct.pack and decoded by Scapy.
"""

import struct

import scapy.layers.dhcp  # noqa: F401  (registers the UDP 67/68 -> BOOTP binding)
import scapy.layers.inet  # noqa: F401  (registers the Ether -> IPv4 binding used to decode frames)
from scapy.layers.l2 import Ether

from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import MAX_EVIDENCE_VALUES_PER_TYPE, AssetInventory

MAC = "02:00:00:00:00:41"
IP = "10.0.0.41"
PEER = "10.0.0.1"


def _mac(text):
    return bytes(int(part, 16) for part in text.split(":"))


def _ipv4(src, dst, proto, payload, ttl):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, ttl, proto, 0,
                         bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return header + payload


def _frame(src_mac, src_ip, dst_ip, l4_proto, l4, ttl=64, dst_mac="02:00:00:00:00:fe"):
    raw = _mac(dst_mac) + _mac(src_mac) + b"\x08\x00" + _ipv4(src_ip, dst_ip, l4_proto, l4, ttl)
    return Ether(raw)


def _tcp(sport, dport, flags=0x18):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 8192, 0, 0)


def _dhcp_discover(client_mac, param_req_list):
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, 0x1234, 0, 0,
                        b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4,
                        _mac(client_mac) + b"\0" * 10, b"\0" * 64, b"\0" * 128)
    options = (b"\x63\x82\x53\x63" + b"\x35\x01\x01"
               + bytes([55, len(param_req_list)]) + bytes(param_req_list) + b"\xff")
    payload = bootp + options
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    return _frame(client_mac, "0.0.0.0", "255.255.255.255", 17, udp, dst_mac="ff:ff:ff:ff:ff:ff")


class _Sink:
    """Every event and anomaly, unbounded (the engine's in-memory event log keeps only 500)."""
    def __init__(self):
        self.events = []

    def write_event(self, ts, message):
        self.events.append(message)

    def write_anomaly(self, anomaly):
        pass


def _engine():
    engine = CaptureEngine(inventory=AssetInventory({}))
    engine.no_baseline = True
    engine.writer = _Sink()
    return engine


def _feed(engine, frames):
    for i, pkt in enumerate(frames):
        pkt.time = 1_700_000_000 + i * 0.01
        engine._ingest_packet(pkt, "pcap")


def _hint_events(engine, kind="OS hint"):
    return [m for m in engine.writer.events if f"-> {kind}:" in m]


def test_one_thousand_packets_from_one_host_log_one_os_hint_event():
    engine = _engine()
    _feed(engine, [_frame(MAC, IP, PEER, 6, _tcp(40000, 502)) for _ in range(1000)])
    assert _hint_events(engine) == [f"{IP} -> OS hint: Linux/Unix-like (TTL: 64)"]
    asset = engine.inventory.get(IP)
    assert asset.os_hints == ["Linux/Unix-like (observed TTL: 64, inferred initial: 64)"]
    assert [e.value for e in asset.evidence if e.type == "os_hint"] == asset.os_hints
    assert engine.ingest_stats.contained_total == 0


def test_a_changed_ttl_is_a_new_hint_and_logs_once():
    engine = _engine()
    frames = [_frame(MAC, IP, PEER, 6, _tcp(40000, 502), ttl=64 if i % 2 else 63) for i in range(400)]
    _feed(engine, frames)
    assert sorted(_hint_events(engine)) == [f"{IP} -> OS hint: Linux/Unix-like (TTL: 63)",
                                            f"{IP} -> OS hint: Linux/Unix-like (TTL: 64)"]
    assert len(engine.inventory.get(IP).os_hints) == 2


def test_hints_refused_at_the_per_device_limit_log_nothing():
    engine = _engine()
    ttls = [64] + list(range(1, MAX_EVIDENCE_VALUES_PER_TYPE + 1)) + list(range(100, 121))
    _feed(engine, [_frame(MAC, IP, PEER, 6, _tcp(40000, 502), ttl=t) for t in ttls])
    asset = engine.inventory.get(IP)
    assert len(asset.os_hints) == MAX_EVIDENCE_VALUES_PER_TYPE
    assert len(_hint_events(engine)) == MAX_EVIDENCE_VALUES_PER_TYPE
    assert asset.evidence_overflow["os_hint"] == 21


def test_repeated_dhcp_fingerprint_logs_one_event():
    engine = _engine()
    _feed(engine, [_frame(MAC, IP, PEER, 6, _tcp(40000, 502))])        # the asset exists
    _feed(engine, [_dhcp_discover(MAC, [1, 3, 6, 15]) for _ in range(50)])
    assert _hint_events(engine, "DHCP OS fingerprint") == [
        f"{IP} -> DHCP OS fingerprint: Generic Industrial RTOS / Controller"]
    asset = engine.inventory.get(IP)
    assert "DHCP fingerprint: Generic Industrial RTOS / Controller" in asset.os_hints
    assert engine.ingest_stats.contained_total == 0


def test_add_os_hint_reports_whether_the_hint_is_new():
    engine = _engine()
    _feed(engine, [_frame(MAC, IP, PEER, 6, _tcp(40000, 502))])
    asset = engine.inventory.get(IP)
    assert asset.add_os_hint("Windows-like (observed TTL: 128, inferred initial: 128)") is True
    assert asset.add_os_hint("Windows-like (observed TTL: 128, inferred initial: 128)") is False
