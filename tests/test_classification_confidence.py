"""
classification_confidence_pct and confidence_pct are separate fields.

classification_confidence_pct is the accumulated evidence weight capped at 100.
confidence_pct is the multi-factor score (OUI, protocol, behavioral, directionality)
computed by CaptureEngine._recompute_confidence(). Recomputing confidence_pct must
not overwrite classification_confidence_pct.
"""

from scrutics.db.inventory import AssetInventory
from scrutics.capture.engine import CaptureEngine


def _expected_classification_confidence(asset) -> int:
    return min(sum(e.weight for e in asset.evidence), 100)


def test_recompute_confidence_does_not_overwrite_classification_confidence():
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)
    assert engine.no_baseline is False  # baselining enabled, so _recompute_confidence() runs

    # Listener on Modbus TCP 502 answering a client
    engine._process_flow_data(
        src_ip="10.0.0.20", src_mac="02:00:00:00:00:20", dst_ip="10.0.0.5",
        src_port=502, dst_port=40000, proto="TCP", ts=1.0,
    )
    asset = inv.get("10.0.0.20")
    assert asset is not None
    assert asset.baseline_status != "no_data"
    assert asset.confidence_pct > 0

    assert asset.classification_confidence_pct == _expected_classification_confidence(asset)
    # In this scenario the two scores differ; equality would mean one overwrote the other
    assert asset.classification_confidence_pct != asset.confidence_pct

    # More listening services push the evidence weight sum past the cap
    for i, port in enumerate((102, 44818, 20000), start=1):
        engine._process_flow_data(
            src_ip="10.0.0.20", src_mac="02:00:00:00:00:20", dst_ip="10.0.0.5",
            src_port=port, dst_port=40000 + i, proto="TCP", ts=1.0 + i,
        )
    assert sum(e.weight for e in asset.evidence) > 100
    assert asset.classification_confidence_pct == _expected_classification_confidence(asset) == 100
