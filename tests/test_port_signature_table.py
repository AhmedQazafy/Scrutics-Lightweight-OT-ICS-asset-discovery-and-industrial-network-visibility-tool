"""
The port signature table is the single source for port evidence and listening-service crediting.
"""

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP

from scrutics.classifier.signatures import ALL_SIGNATURES, get_signature, get_listener_ports
from scrutics.classifier.protocol import known_service_ports
from scrutics.db.inventory import AssetInventory
from scrutics.capture.engine import CaptureEngine


def test_dual_transport_signatures_match_tcp_and_udp():
    dual = [s for s in ALL_SIGNATURES if s.transport == "TCP/UDP"]
    assert dual
    for sig in dual:
        assert get_signature(sig.port, "TCP") is sig
        assert get_signature(sig.port, "UDP") is sig
    assert get_signature(44818, "TCP").name == "EtherNet/IP"
    assert get_signature(20000, "UDP").name == "DNP3"


def test_single_transport_signature_does_not_match_other_transport():
    assert get_signature(502, "TCP").name == "Modbus TCP"
    assert get_signature(502, "UDP") is None
    assert get_signature(47808, "TCP") is None


def test_pcworx_and_ge_srtp_are_ot_signatures():
    pcworx = get_signature(1962, "TCP")
    srtp = get_signature(18245, "TCP")
    for sig in (pcworx, srtp):
        assert sig.category == "OT"
        assert sig.evidence_type == "ot_port"
        assert (sig.weight, sig.confidence) == (14, "HIGH")
    assert pcworx.name == "PCWorx"
    assert srtp.name == "GE SRTP"


def test_listener_ports_are_every_signature_port_plus_rule_ports():
    signature_ports = {s.port for s in ALL_SIGNATURES}
    assert get_listener_ports() == signature_ports
    assert signature_ports <= known_service_ports()
    # FTP has no signature and is not a creditable listening service
    assert 21 not in known_service_ports()


def _engine():
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)
    engine.no_baseline = True
    return inv, engine


def test_snmp_and_smb_sources_are_credited_as_listeners():
    inv, engine = _engine()
    snmp = (
        Ether(src="02:00:00:00:00:31", dst="02:00:00:00:00:05")
        / IP(src="10.0.0.31", dst="10.0.0.5")
        / UDP(sport=161, dport=50000)
    )
    smb = (
        Ether(src="02:00:00:00:00:32", dst="02:00:00:00:00:05")
        / IP(src="10.0.0.32", dst="10.0.0.5")
        / TCP(sport=445, dport=50001, flags="SA")
    )
    engine._process_packet(snmp)
    engine._process_packet(smb)
    assert inv.get("10.0.0.31").ports_seen == {161}
    assert inv.get("10.0.0.32").ports_seen == {445}


def test_ethernet_ip_over_udp_produces_port_evidence():
    inv, engine = _engine()
    pkt = (
        Ether(src="02:00:00:00:00:33", dst="02:00:00:00:00:05")
        / IP(src="10.0.0.33", dst="10.0.0.5")
        / UDP(sport=44818, dport=50002)
    )
    engine._process_packet(pkt)
    asset = inv.get("10.0.0.33")
    assert 44818 in asset.ports_seen
    port_records = [e for e in asset.evidence if e.type == "port" and e.value == "44818"]
    assert len(port_records) == 1
    assert port_records[0].weight == 20


def test_proconos_and_pcworx_are_separate_ot_signatures():
    proconos = get_signature(20547, "TCP")
    pcworx = get_signature(1962, "TCP")
    assert proconos.name == "ProConOS"
    assert pcworx.name == "PCWorx"
    for sig in (proconos, pcworx):
        assert sig.category == "OT"
        assert (sig.weight, sig.confidence) == (14, "HIGH")


def _serves(mac, ip, sport, dport):
    return (
        Ether(src=mac, dst="02:00:00:00:00:05")
        / IP(src=ip, dst="10.0.0.5")
        / TCP(sport=sport, dport=dport, flags="SA")
    )


def test_proconos_port_evidence_is_labeled_proconos():
    inv, engine = _engine()
    engine._process_packet(_serves("02:00:00:00:00:34", "10.0.0.34", 20547, 50003))
    asset = inv.get("10.0.0.34")
    port_records = [e for e in asset.evidence if e.type == "port" and e.value == "20547"]
    assert [e.detail for e in port_records] == ["Observed ProConOS on port 20547 (OT)"]
    assert asset.classification_reason == "listens on OT port: ProConOS (20547)"


def test_device_serving_pcworx_and_proconos_lists_both_services():
    inv, engine = _engine()
    engine._process_packet(_serves("02:00:00:00:00:35", "10.0.0.35", 1962, 50004))
    engine._process_packet(_serves("02:00:00:00:00:35", "10.0.0.35", 20547, 50005))
    asset = inv.get("10.0.0.35")
    assert asset.classification_type == "OT"
    assert asset.classification_reason == (
        "listens on OT port: PCWorx (1962); also: listens on OT port: ProConOS (20547)"
    )
    assert asset.classification_conflicts == []
