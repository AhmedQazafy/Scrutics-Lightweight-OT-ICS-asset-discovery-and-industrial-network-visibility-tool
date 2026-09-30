"""
A listening port means the device offers that service.

Packets whose source and destination ports are equal credit no listener unless the
port's signature votes OT or IT; then both endpoints are credited. The DHCP client
port 68 is never credited.
"""

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from scrutics.db.inventory import AssetInventory
from scrutics.capture.engine import CaptureEngine


def _engine():
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)
    engine.no_baseline = True
    return inv, engine


def _udp(src_mac, src_ip, dst_ip, sport, dport, payload=b"\x00" * 8):
    return (
        Ether(src=src_mac, dst="02:00:00:00:00:ff")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / Raw(load=payload)
    )


def _ports(inv, ip):
    asset = inv.get(ip)
    return set(asset.ports_seen) if asset else None


def test_ntp_symmetric_exchange_credits_no_listener():
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:46", "10.0.0.46", "10.0.0.47", 123, 123))
    engine._process_packet(_udp("02:00:00:00:00:47", "10.0.0.47", "10.0.0.46", 123, 123))
    assert _ports(inv, "10.0.0.46") == set()
    assert _ports(inv, "10.0.0.47") == set()


def test_ntp_server_reply_to_ephemeral_port_credits_the_server():
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:48", "10.0.0.48", "10.0.0.5", 123, 50000))
    assert _ports(inv, "10.0.0.48") == {123}


def test_dhcp_client_port_68_is_never_credited():
    inv, engine = _engine()
    # Client renewing to the server, then the server replying to the client
    engine._process_packet(_udp("02:00:00:00:00:49", "10.0.0.49", "10.0.0.1", 68, 67, b"\x01" + b"\x00" * 239))
    engine._process_packet(_udp("02:00:00:00:00:01", "10.0.0.1", "10.0.0.49", 67, 68, b"\x02" + b"\x00" * 239))
    assert 68 not in _ports(inv, "10.0.0.49")
    assert 68 not in _ports(inv, "10.0.0.1")
    assert _ports(inv, "10.0.0.1") == {67}


def test_bacnet_symmetric_exchange_credits_both_endpoints():
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:52", "10.0.0.52", "10.0.0.53", 47808, 47808, b"\x81\x0b\x00\x0c"))
    engine._process_packet(_udp("02:00:00:00:00:53", "10.0.0.53", "10.0.0.52", 47808, 47808, b"\x81\x0a\x00\x0c"))
    assert _ports(inv, "10.0.0.52") == {47808}
    assert _ports(inv, "10.0.0.53") == {47808}


def test_mdns_symmetric_announcement_credits_no_listener():
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:54", "10.0.0.54", "224.0.0.251", 5353, 5353, b"\x00" * 12))
    assert _ports(inv, "10.0.0.54") == set()
