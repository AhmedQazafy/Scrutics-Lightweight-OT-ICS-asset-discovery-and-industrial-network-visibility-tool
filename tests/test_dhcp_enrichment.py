"""
Passive DHCP identification enrichment tests.

Verifies:
  - Options 12, 55, 60, 81 parsing and enrichment
  - chaddr client identity vs Ethernet src_mac
  - DHCP arriving before normal asset discovery
  - Pending-buffer flush on subsequent asset resolution
  - Bounded pending-buffer behavior
  - Option 55 fingerprint match and no-match
  - Option 60 raw, recognized, and unrecognized handling
  - Option 60 does not modify OUI vendor fields
  - Option 81 E=0 (ASCII) and E=1 (DNS wire-format)
  - Malformed Option 81 safety
  - Evidence deduplication across repeated DHCP packets
  - DHCP does not directly change classification_type
  - Malformed DHCP packets do not crash engine
"""

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP

from scrutics.db.inventory import AssetInventory, Asset
from scrutics.capture.engine import CaptureEngine
from scrutics.classifier.dhcp_fingerprints import (
    lookup_dhcp_fingerprint,
    classify_option60,
    parse_option_81,
)


def make_dhcp_pkt(chaddr_mac="00:11:22:33:44:55", ether_src="aa:bb:cc:dd:ee:ff", options=None):
    mac_bytes = bytes.fromhex(chaddr_mac.replace(":", "").replace("-", ""))
    chaddr_field = mac_bytes + b"\x00" * (16 - len(mac_bytes))
    opts = list(options or [])
    if not any(opt == "end" or (isinstance(opt, tuple) and opt[0] == "end") for opt in opts):
        opts.append("end")
    return (
        Ether(src=ether_src, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=chaddr_field)
        / DHCP(options=opts)
    )


class TestDHCPOptionParsing:
    """Option 12, 55, 60, 81 unit & integration tests."""

    def test_option_12_hostname_extracted_and_stripped(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")

        pkt = make_dhcp_pkt(
            chaddr_mac="00:11:22:33:44:55",
            options=[("hostname", b"plc-controller-01\x00\x00")]
        )
        engine._process_packet(pkt)

        assert asset.hostname == "plc-controller-01"
        ev = [e for e in asset.evidence if e.type == "hostname" and e.source == "DHCP"]
        assert len(ev) == 1
        assert ev[0].value == "plc-controller-01"
        assert ev[0].weight == 5
        assert ev[0].confidence == "LOW"

    def test_option_12_hostname_replacement(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")

        pkt1 = make_dhcp_pkt(chaddr_mac="00:11:22:33:44:55", options=[("hostname", b"old-host")])
        engine._process_packet(pkt1)
        assert asset.hostname == "old-host"

        pkt2 = make_dhcp_pkt(chaddr_mac="00:11:22:33:44:55", options=[("hostname", b"new-host")])
        engine._process_packet(pkt2)
        assert asset.hostname == "new-host"

    def test_option_55_fingerprint_match(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")

        prl = [1, 15, 3, 6, 44, 46, 47, 31, 33, 43]
        pkt = make_dhcp_pkt(chaddr_mac="00:11:22:33:44:55", options=[("param_req_list", prl)])
        engine._process_packet(pkt)

        ev = [e for e in asset.evidence if e.type == "os_hint" and e.source == "DHCP"]
        assert len(ev) == 1
        assert "Windows 7" in ev[0].value
        assert ev[0].weight == 10
        assert ev[0].confidence == "MEDIUM"
        assert any("Windows 7" in h for h in asset.os_hints)

    def test_option_55_fingerprint_no_match(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")

        prl = [99, 98, 97]
        pkt = make_dhcp_pkt(chaddr_mac="00:11:22:33:44:55", options=[("param_req_list", prl)])
        engine._process_packet(pkt)

        ev = [e for e in asset.evidence if e.source == "DHCP" and e.type == "os_hint"]
        assert len(ev) == 0

    def test_option_60_raw_and_recognized(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")

        pkt = make_dhcp_pkt(chaddr_mac="00:11:22:33:44:55", options=[("vendor_class_id", b"Schneider Electric")])
        engine._process_packet(pkt)

        dhcp_ev = [e for e in asset.evidence if e.source == "DHCP" and e.type == "vendor"]
        assert len(dhcp_ev) == 2

        raw_ev = [e for e in dhcp_ev if e.value == "Schneider Electric"]
        assert len(raw_ev) == 1
        assert raw_ev[0].weight == 5
        assert raw_ev[0].confidence == "LOW"

        rec_ev = [e for e in dhcp_ev if "Automation Device" in e.value]
        assert len(rec_ev) == 1
        assert rec_ev[0].weight == 10
        assert rec_ev[0].confidence == "MEDIUM"

    def test_option_60_unrecognized(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")

        pkt = make_dhcp_pkt(chaddr_mac="00:11:22:33:44:55", options=[("vendor_class_id", b"UnrecognizedCustomDevice")])
        engine._process_packet(pkt)

        dhcp_ev = [e for e in asset.evidence if e.source == "DHCP" and e.type == "vendor"]
        assert len(dhcp_ev) == 1
        assert dhcp_ev[0].value == "UnrecognizedCustomDevice"

    def test_option_60_does_not_modify_vendor_fields(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")
        asset.vendor = "Cisco Systems, Inc."
        asset.vendor_class = "IT"
        asset.is_ot_vendor = False

        pkt = make_dhcp_pkt(chaddr_mac="00:11:22:33:44:55", options=[("vendor_class_id", b"Schneider Electric")])
        engine._process_packet(pkt)

        # OUI fields must remain untouched
        assert asset.vendor == "Cisco Systems, Inc."
        assert asset.vendor_class == "IT"
        assert asset.is_ot_vendor is False

    def test_option_81_e_bit_clear_ascii(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")

        opt81_raw = bytes([0x00, 0x00, 0x00]) + b"sensor1.plant.local\x00"
        pkt = make_dhcp_pkt(chaddr_mac="00:11:22:33:44:55", options=[("client_FQDN", opt81_raw)])
        engine._process_packet(pkt)

        assert "sensor1.plant.local" in asset.dns_names
        assert asset.hostname != "sensor1.plant.local"
        ev = [e for e in asset.evidence if e.type == "dns" and e.source == "DHCP"]
        assert len(ev) == 1
        assert ev[0].value == "sensor1.plant.local"

    def test_option_81_e_bit_set_wire_format(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")

        wire_data = (
            bytes([0x04, 0x00, 0x00, 7])
            + b"sensor1"
            + bytes([5])
            + b"plant"
            + bytes([5])
            + b"local"
            + bytes([0])
        )
        pkt = make_dhcp_pkt(chaddr_mac="00:11:22:33:44:55", options=[("client_FQDN", wire_data)])
        engine._process_packet(pkt)

        assert "sensor1.plant.local" in asset.dns_names
        assert asset.hostname != "sensor1.plant.local"

    def test_option_81_malformed_ignored(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")

        malformed_wire = bytes([0x04, 0x00, 0x00, 50]) + b"short"
        pkt = make_dhcp_pkt(chaddr_mac="00:11:22:33:44:55", options=[("client_FQDN", malformed_wire)])
        engine._process_packet(pkt)

        assert len(asset.dns_names) == 0


class TestClientIdentityAndCHADDR:
    """Tests verifying BOOTP chaddr as client MAC, ignoring Ethernet src_mac."""

    def test_chaddr_used_not_ether_src_mac(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)

        relay_asset = inventory.get_or_create("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        client_asset = inventory.get_or_create("192.168.1.50", "00:11:22:33:44:55")

        # Packet originates physically from relay, but BOOTP chaddr is client
        pkt = make_dhcp_pkt(
            chaddr_mac="00:11:22:33:44:55",
            ether_src="aa:bb:cc:dd:ee:ff",
            options=[("hostname", b"client-plc")]
        )
        engine._process_packet(pkt)

        assert client_asset.hostname == "client-plc"
        assert relay_asset.hostname == ""
        assert len([e for e in relay_asset.evidence if e.source == "DHCP"]) == 0

    def test_chaddr_invalid_skipped(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)

        pkt_zero = make_dhcp_pkt(chaddr_mac="00:00:00:00:00:00", options=[("hostname", b"host0")])
        engine._process_packet(pkt_zero)
        assert len(engine._pending_dhcp) == 0

        pkt_bcast = make_dhcp_pkt(chaddr_mac="ff:ff:ff:ff:ff:ff", options=[("hostname", b"hostf")])
        engine._process_packet(pkt_bcast)
        assert len(engine._pending_dhcp) == 0


class TestPendingBuffer:
    """Tests for pending DHCP buffer when DHCP arrives before normal traffic."""

    def test_dhcp_arrives_before_asset_discovery(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)

        # Send DHCP packet before asset exists in inventory
        pkt = make_dhcp_pkt(
            chaddr_mac="00:11:22:33:44:55",
            options=[
                ("hostname", b"delayed-plc"),
                ("vendor_class_id", b"Schneider Electric")
            ]
        )
        engine._process_packet(pkt)

        # Assert NO asset was created by DHCP
        assert len(inventory.get_all()) == 0
        assert "00:11:22:33:44:55" in engine._pending_dhcp
        assert engine._pending_dhcp["00:11:22:33:44:55"]["hostname"] == "delayed-plc"

        # Now normal flow traffic arrives for that MAC
        engine._process_flow_data(
            src_ip="192.168.1.55",
            src_mac="00:11:22:33:44:55",
            dst_ip="192.168.1.1",
            dst_port=80,
            proto="TCP",
            ts=1000.0,
        )

        asset = inventory.get("192.168.1.55")
        assert asset is not None
        assert asset.hostname == "delayed-plc"
        assert any(e.source == "DHCP" and e.type == "hostname" for e in asset.evidence)
        assert any(e.source == "DHCP" and e.type == "vendor" for e in asset.evidence)
        # Pending buffer was flushed
        assert "00:11:22:33:44:55" not in engine._pending_dhcp

    def test_bounded_pending_buffer(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        engine._MAX_PENDING_DHCP = 10  # use small limit for test speed

        for i in range(15):
            mac = f"00:11:22:33:44:{i:02x}"
            pkt = make_dhcp_pkt(chaddr_mac=mac, options=[("hostname", f"host-{i}".encode())])
            engine._process_packet(pkt)

        assert len(engine._pending_dhcp) == 10
        # Earliest MACs (0..4) should have been evicted
        assert "00:11:22:33:44:00" not in engine._pending_dhcp
        assert "00:11:22:33:44:0e" in engine._pending_dhcp


class TestDeduplicationAndSafety:
    """Deduplication, classification immutability, and malformed packet robustness."""

    def test_repeated_dhcp_packets_deduplicated(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")

        pkt = make_dhcp_pkt(
            chaddr_mac="00:11:22:33:44:55",
            options=[
                ("hostname", b"plc01"),
                ("vendor_class_id", b"Schneider Electric")
            ]
        )
        engine._process_packet(pkt)
        engine._process_packet(pkt)
        engine._process_packet(pkt)

        # Hostname evidence should be present exactly once
        host_ev = [e for e in asset.evidence if e.type == "hostname" and e.source == "DHCP"]
        assert len(host_ev) == 1

        # Raw vendor evidence should be present exactly once
        v_ev = [e for e in asset.evidence if e.type == "vendor" and e.source == "DHCP" and e.value == "Schneider Electric"]
        assert len(v_ev) == 1

    def test_dhcp_does_not_change_classification_type(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        asset = inventory.get_or_create("192.168.1.10", "00:11:22:33:44:55")

        # Initial state: unclassified client
        assert asset.classification_type == "Unknown"
        assert asset.is_ot is None

        pkt = make_dhcp_pkt(
            chaddr_mac="00:11:22:33:44:55",
            options=[
                ("hostname", b"modicon-m340"),
                ("vendor_class_id", b"Schneider Electric"),
                ("param_req_list", [1, 3, 6, 12, 15, 28])
            ]
        )
        engine._process_packet(pkt)

        # DHCP evidence alone must NEVER change classification_type
        assert asset.classification_type == "Unknown"
        assert asset.is_ot is None

    def test_asset_to_dict_contains_hostname(self):
        asset = Asset(ip="10.0.0.1", mac="00:11:22:33:44:55")
        asset.hostname = "test-box"
        d = asset.to_dict()
        assert "hostname" in d
        assert d["hostname"] == "test-box"

    def test_malformed_dhcp_packets_safe(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)

        # Empty UDP 67/68 packet
        empty_udp = Ether()/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)
        engine._process_packet(empty_udp)

        # Garbage BOOTP payload
        from scapy.packet import Raw
        garbage = Ether()/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/Raw(load=b"\x00" * 300)
        engine._process_packet(garbage)
