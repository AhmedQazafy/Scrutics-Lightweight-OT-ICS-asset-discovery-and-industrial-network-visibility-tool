"""
Tests for vendor classification.

Verifies:
1. Vendor classification mapping (OT, IT, NEUTRAL, UNKNOWN).
2. Cisco is classified as IT, not OT.
3. Vendor classification is an evidence input, NOT the final asset classification.
4. Asset.vendor_class exposes vendor class alongside vendor.
5. Evidence generation produces vendor-class-appropriate evidence objects.
6. classification_type is the canonical overall asset classification.
7. is_ot is derived/compatibility representation of classification_type.
8. Backward compatibility for is_ot_vendor and existing consumers.
"""

import pytest
from scrutics.classifier.oui import (
    classify_vendor, is_ot_vendor,
    VENDOR_CLASS_OT, VENDOR_CLASS_IT, VENDOR_CLASS_NEUTRAL, VENDOR_CLASS_UNKNOWN,
)
from scrutics.db.inventory import Asset, AssetInventory
from scrutics.capture.engine import CaptureEngine


class TestVendorClassification:

    def test_vendor_class_ot_vendors(self):
        """Pure OT vendors must be classified as OT."""
        assert classify_vendor("Schneider Electric") == VENDOR_CLASS_OT
        assert classify_vendor("Rockwell Automation") == VENDOR_CLASS_OT
        assert classify_vendor("Siemens AG") == VENDOR_CLASS_OT
        assert classify_vendor("Phoenix Contact") == VENDOR_CLASS_OT
        assert classify_vendor("Beckhoff Automation") == VENDOR_CLASS_OT
        assert classify_vendor("Yokogawa Electric") == VENDOR_CLASS_OT
        assert classify_vendor("Omron Corporation") == VENDOR_CLASS_OT

    def test_vendor_class_it_vendors(self):
        """Pure IT and computing vendors must be classified as IT."""
        assert classify_vendor("Dell Inc.") == VENDOR_CLASS_IT
        assert classify_vendor("Hewlett Packard") == VENDOR_CLASS_IT
        assert classify_vendor("Apple, Inc.") == VENDOR_CLASS_IT
        assert classify_vendor("Intel Corporation") == VENDOR_CLASS_IT
        assert classify_vendor("VMware, Inc.") == VENDOR_CLASS_IT

    def test_vendor_class_cisco_is_it_not_ot(self):
        """
        Cisco must be classified as IT/networking, NOT OT.
        Cisco must no longer be classified as OT merely because of the old OT_VENDORS list.
        """
        assert classify_vendor("Cisco Systems, Inc.") == VENDOR_CLASS_IT
        assert classify_vendor("Cisco") == VENDOR_CLASS_IT
        # is_ot_vendor must return False for Cisco
        assert is_ot_vendor("Cisco Systems, Inc.") is False
        assert is_ot_vendor("Cisco") is False

    def test_vendor_class_neutral_vendors(self):
        """Neutral/dual-use industrial networking vendors must be classified as NEUTRAL."""
        assert classify_vendor("Belden") == VENDOR_CLASS_NEUTRAL
        assert classify_vendor("Hirschmann Automation") == VENDOR_CLASS_NEUTRAL
        assert classify_vendor("Lantronix") == VENDOR_CLASS_NEUTRAL
        assert classify_vendor("Digi International") == VENDOR_CLASS_NEUTRAL

    def test_vendor_class_unknown_vendors(self):
        """Unknown or unmapped vendors must be classified as UNKNOWN."""
        assert classify_vendor("Unknown") == VENDOR_CLASS_UNKNOWN
        assert classify_vendor("") == VENDOR_CLASS_UNKNOWN
        assert classify_vendor(None) == VENDOR_CLASS_UNKNOWN
        assert classify_vendor("Unrecognized Corp 12345") == VENDOR_CLASS_UNKNOWN


class TestAssetVendorIntegration:

    def test_asset_vendor_class_initialization(self):
        """Asset exposes vendor_class and syncs with vendor identity."""
        asset = Asset(ip="10.0.0.1", mac="00:11:22:33:44:55", vendor="Siemens AG")
        assert asset.vendor_class == VENDOR_CLASS_OT
        assert asset.is_ot_vendor is True

    def test_asset_vendor_class_cisco(self):
        """Asset with Cisco vendor has vendor_class=IT and is_ot_vendor=False."""
        asset = Asset(ip="10.0.0.1", mac="00:11:22:33:44:55", vendor="Cisco Systems, Inc.")
        assert asset.vendor_class == VENDOR_CLASS_IT
        assert asset.is_ot_vendor is False

    def test_asset_vendor_class_belden(self):
        """Asset with Belden vendor has vendor_class=NEUTRAL and is_ot_vendor=False."""
        asset = Asset(ip="10.0.0.1", mac="00:11:22:33:44:55", vendor="Belden")
        assert asset.vendor_class == VENDOR_CLASS_NEUTRAL
        assert asset.is_ot_vendor is False

    def test_asset_vendor_class_unknown(self):
        """Asset with Unknown vendor has vendor_class=UNKNOWN and is_ot_vendor=False."""
        asset = Asset(ip="10.0.0.1", mac="00:11:22:33:44:55", vendor="Unknown")
        assert asset.vendor_class == VENDOR_CLASS_UNKNOWN
        assert asset.is_ot_vendor is False


class TestClassificationSeparation:

    def test_ot_vendor_does_not_directly_assign_classification_type(self):
        """
        CRITICAL ARCHITECTURAL RULE:
        vendor_class = OT does NOT, by itself, directly assign classification_type = OT.
        Without listening ports or protocol evidence, the asset cannot be classified as OT.
        """
        inv = AssetInventory()
        engine = CaptureEngine(inventory=inv)
        engine.no_baseline = True

        # Send traffic from a Schneider MAC to an external IP, but with NO listening ports
        # (src_port 49152 is client ephemeral, not a service port)
        engine._process_flow_data(
            src_ip="10.0.0.10",
            src_mac="00:80:F4:11:22:33",  # 00-80-F4 is Schneider Electric in ics_oui.txt
            dst_ip="10.0.0.99",
            src_port=49152,
            dst_port=49153,
            proto="TCP",
            ts=1.0,
            trust_dst_port=False,
        )

        asset = inv.get("10.0.0.10")
        assert asset is not None
        assert "Schneider" in asset.vendor
        assert asset.vendor_class == VENDOR_CLASS_OT

        # The vendor is OT, but the asset itself MUST NOT be classified as OT
        # because vendor is only an evidence signal, not the final verdict!
        assert asset.classification_type == "Unknown"
        assert asset.is_ot is None

    def test_cisco_asset_classified_as_ot_when_running_ot_protocol(self):
        """
        A Cisco device (vendor_class=IT) can still be classified as OT
        when protocol/port evidence indicates OT operation (e.g. Modbus 502).
        Vendor classification does not force asset classification.
        """
        inv = AssetInventory()
        engine = CaptureEngine(inventory=inv)
        engine.no_baseline = True

        # Inject fake OUI DB mapping Cisco
        engine._oui_db = {"00000C": "Cisco Systems, Inc."}

        # Client connects to Cisco device on port 502 (Modbus TCP)
        # First see Cisco device listening on 502
        engine._process_flow_data(
            src_ip="10.0.0.20",
            src_mac="00:00:0C:11:22:33",
            dst_ip="10.0.0.1",
            src_port=502,
            dst_port=40000,
            proto="TCP",
            ts=1.0,
        )

        asset = inv.get("10.0.0.20")
        assert asset is not None
        assert asset.vendor_class == VENDOR_CLASS_IT
        # Port 502 gives OT classification despite Cisco vendor!
        assert asset.classification_type == "OT"
        assert asset.is_ot is True


class TestEvidenceIntegration:

    def test_vendor_evidence_generation_by_class(self):
        """Verify vendor evidence is generated with class-appropriate weights and details."""
        inv = AssetInventory()
        engine = CaptureEngine(inventory=inv)
        engine.no_baseline = True

        # OT vendor (Schneider)
        engine._process_flow_data(
            src_ip="10.0.0.1",
            src_mac="00:80:F4:00:00:01",
            dst_ip=None,
            src_port=None,
            dst_port=None,
            proto="TCP",
            ts=1.0,
        )
        asset_ot = inv.get("10.0.0.1")
        vendor_ev_ot = [e for e in asset_ot.evidence if e.type == "vendor"]
        assert len(vendor_ev_ot) == 1
        assert vendor_ev_ot[0].weight == 30
        assert vendor_ev_ot[0].confidence == "HIGH"
        assert "OT vendor" in vendor_ev_ot[0].detail

        # IT vendor (inject Cisco)
        engine._oui_db["00000C"] = "Cisco Systems, Inc."
        engine._process_flow_data(
            src_ip="10.0.0.2",
            src_mac="00:00:0C:00:00:02",
            dst_ip=None,
            src_port=None,
            dst_port=None,
            proto="TCP",
            ts=2.0,
        )
        asset_it = inv.get("10.0.0.2")
        vendor_ev_it = [e for e in asset_it.evidence if e.type == "vendor"]
        assert len(vendor_ev_it) == 1
        assert vendor_ev_it[0].weight == 15
        assert vendor_ev_it[0].confidence == "MEDIUM"
        assert "IT/networking vendor" in vendor_ev_it[0].detail

        # Neutral vendor (inject Belden)
        engine._oui_db["001122"] = "Belden"
        engine._process_flow_data(
            src_ip="10.0.0.3",
            src_mac="00:11:22:00:00:03",
            dst_ip=None,
            src_port=None,
            dst_port=None,
            proto="TCP",
            ts=3.0,
        )
        asset_neutral = inv.get("10.0.0.3")
        vendor_ev_neutral = [e for e in asset_neutral.evidence if e.type == "vendor"]
        assert len(vendor_ev_neutral) == 1
        assert vendor_ev_neutral[0].weight == 10
        assert vendor_ev_neutral[0].confidence == "MEDIUM"
        assert "dual-use" in vendor_ev_neutral[0].detail


class TestIsOtCompatibility:

    def test_is_ot_derived_from_classification_type(self):
        """is_ot correctly represents canonical classification_type."""
        asset = Asset(ip="10.0.0.1", mac="00:11:22:33:44:55")

        asset.classification_type = "OT"
        assert asset.is_ot is True

        asset.classification_type = "IT"
        assert asset.is_ot is False

        asset.classification_type = "Unknown"
        assert asset.is_ot is None

        asset.classification_type = "Infrastructure"
        assert asset.is_ot is False

    def test_setting_is_ot_updates_classification_type(self):
        """Setting is_ot updates canonical classification_type for backward compatibility."""
        asset = Asset(ip="10.0.0.1", mac="00:11:22:33:44:55")

        asset.is_ot = True
        assert asset.classification_type == "OT"

        asset.is_ot = False
        assert asset.classification_type == "IT"

        asset.is_ot = None
        assert asset.classification_type == "Unknown"

    def test_to_dict_includes_vendor_class_and_is_ot_vendor(self):
        """Asset.to_dict() exports vendor_class, is_ot_vendor, and classification_type."""
        asset = Asset(ip="10.0.0.1", mac="00:11:22:33:44:55", vendor="Cisco Systems, Inc.")
        d = asset.to_dict()
        assert d["vendor"] == "Cisco Systems, Inc."
        assert d["vendor_class"] == VENDOR_CLASS_IT
        assert d["is_ot_vendor"] is False
        assert d["classification_type"] == "Unknown"
        assert d["type"] == "Unknown"
