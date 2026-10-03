"""
Lookup structures kept on an Asset always equal a fresh recomputation from the collection they
are derived from, whichever way that collection was changed: through the Asset's methods,
directly (as a session load does), or by replacing it.
"""

import random

import pytest

from scrutics.baseline.baselineengine import BaselineEngine
from scrutics.db.inventory import Asset


def _check_peer_log(asset):
    log = asset._synced_peer_log()
    assert len(log) == len(set(log)) == len(asset.peer_ips)
    assert set(log) == asset.peer_ips


@pytest.mark.parametrize("seed", range(20))
def test_peer_log_matches_peer_ips_after_random_mutations(seed):
    rng = random.Random(seed)
    asset = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01", peer_ips={"10.0.9.1"} if seed % 2 else set())
    baselines = BaselineEngine()
    given = {}
    for _ in range(300):
        op = rng.random()
        peer = f"10.0.1.{rng.randint(1, 60)}"
        if op < 0.6:
            asset.add_peer(peer)
        elif op < 0.75:
            asset.peer_ips.add(peer)                      # changed directly, bypassing add_peer
        elif op < 0.8:
            asset.peer_ips = set(rng.sample(sorted(asset.peer_ips | {peer}), k=1))   # replaced
            given.clear()                                 # peers may be dropped; restart the union
        else:
            ip = f"10.0.0.{rng.randint(1, 3)}"
            given.setdefault(ip, set()).update(asset.peers_not_given_to(baselines.device(ip)))
            # Everything the asset has was given to this baseline at least once
            assert asset.peer_ips <= given[ip]
        _check_peer_log(asset)


def test_peer_log_does_not_change_equality_or_repr():
    first = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01")
    second = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01")
    first.add_peer("10.0.1.1")
    second.peer_ips.add("10.0.1.1")
    first.peers_not_given_to(BaselineEngine().device("10.0.0.1"))
    assert first == second
    assert repr(first) == repr(second)
    assert "_peer_log" not in repr(first) and "_baseline_peer_cursors" not in repr(first)


# ── Evidence lookups, weight total and DNS names ──────────────────────────────

from scrutics.db.inventory import Evidence

TYPES = ("vendor", "port", "os_hint", "discovery", "protocol")
VALUES = ("Siemens", "502", "Unknown", "", "Linux/Unix-like", 502, ["unhashable"], None)
SOURCES = ("OUI", "traffic", "DHCP", "modbus_parser")


def _check_evidence_index(asset):
    for t in TYPES:
        for v in VALUES:
            assert asset.has_evidence(t, v) == any(e.type == t and e.value == v for e in asset.evidence)
            for s in SOURCES:
                assert asset.has_evidence_from(t, v, s) == any(
                    e.type == t and e.value == v and e.source == s for e in asset.evidence)
    assert asset.vendor_evidence_values() == {
        str(e.value) for e in asset.evidence if e.type == "vendor" and e.value and e.value != "Unknown"}


def _random_record(rng, weight=None):
    return Evidence(type=rng.choice(TYPES), value=rng.choice(VALUES), weight=rng.randint(0, 30) if weight is None else weight,
                    source=rng.choice(SOURCES), confidence="LOW")


@pytest.mark.parametrize("seed", range(20))
def test_evidence_lookups_match_the_list_after_random_mutations(seed):
    rng = random.Random(seed)
    asset = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01",
                  evidence=[_random_record(rng) for _ in range(rng.randint(0, 3))])
    for _ in range(200):
        op = rng.random()
        if op < 0.5:
            record = _random_record(rng)
            count = len(asset.evidence)
            asset.add_evidence(record.type, record.value, record.weight, record.source)
            if len(asset.evidence) > count:                 # a duplicate leaves the value as it was
                assert asset.classification_confidence_pct == min(sum(e.weight for e in asset.evidence), 100)
        elif op < 0.6:
            asset.add_os_hint(rng.choice(("Linux/Unix-like", "Windows-like")), confidence="LOW")
        elif op < 0.85:
            asset.evidence.append(_random_record(rng))      # as a session load does
        elif op < 0.9:
            asset.evidence = [_random_record(rng) for _ in range(rng.randint(0, 4))]
        else:
            asset.evidence = asset.evidence[: rng.randint(0, len(asset.evidence))]
        _check_evidence_index(asset)


def _distinct_values_per_type(evidence):
    seen, counts = [], {}
    for e in evidence:
        try:
            hash(e.type)
        except TypeError:
            continue
        if not any(t == e.type and v == e.value for t, v in seen):
            seen.append((e.type, e.value))
            counts[e.type] = counts.get(e.type, 0) + 1
    return counts


@pytest.mark.parametrize("seed", range(10))
def test_evidence_value_counts_match_the_list_at_the_limit(seed):
    rng = random.Random(seed)
    asset = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01")
    for _ in range(600):
        op = rng.random()
        record = Evidence(type=rng.choice(("hostname", "dns")), value=rng.choice((f"v{rng.randint(0, 90)}", ["u"])),
                          weight=1, source=rng.choice(SOURCES), confidence="LOW")
        before = _distinct_values_per_type(asset.evidence)
        if op < 0.6:
            asset.add_evidence(record.type, record.value, record.weight, record.source)
        elif op < 0.8:
            asset.load_evidence(record)
        elif op < 0.95:
            asset.evidence.append(record)                   # changed directly
        else:
            asset.evidence = asset.evidence[: rng.randint(0, len(asset.evidence))]
        after = _distinct_values_per_type(asset.evidence)
        asset._synced_evidence_index()
        assert asset._ev_type_counts == after
        if op < 0.8:
            # Through the Asset's methods a type never gains a value past the limit
            for t, n in after.items():
                assert n <= max(64, before.get(t, 0))
        _check_evidence_index(asset)


def test_confidence_after_a_session_load_counts_the_loaded_records():
    asset = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01", classification_confidence_pct=7)
    asset.add_evidence("port", "502", 20, "traffic")
    for value in ("a", "b", "c"):
        asset.evidence.append(Evidence(type="discovery", value=value, weight=15, source="mDNS", confidence="HIGH"))
    asset.add_evidence("port", "102", 15, "traffic")
    assert asset.classification_confidence_pct == min(20 + 45 + 15, 100)


def test_fractional_weights_give_the_same_total_as_sum():
    asset = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01")
    asset.add_evidence("port", "502", 20, "traffic")
    for i in range(10):
        asset.evidence.append(Evidence(type="discovery", value=str(i), weight=0.1, source="mDNS", confidence="LOW"))
    asset.add_evidence("port", "102", 1, "traffic")
    assert asset.classification_confidence_pct == min(sum(e.weight for e in asset.evidence), 100)


def test_a_malformed_weight_fails_every_later_add_with_the_record_kept():
    asset = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01")
    asset.add_evidence("port", "502", 20, "traffic")
    asset.evidence.append(Evidence(type="discovery", value="x", weight="5", source="mDNS", confidence="LOW"))
    for count, port in ((3, "102"), (4, "20000")):
        with pytest.raises(TypeError):
            asset.add_evidence("port", port, 15, "traffic")
        assert len(asset.evidence) == count and asset.evidence[-1].value == port
    assert asset.has_evidence("port", "20000")
    with pytest.raises(TypeError):
        sum(e.weight for e in asset.evidence)


@pytest.mark.parametrize("seed", range(20))
def test_dns_names_stay_unique_and_ordered_after_random_mutations(seed):
    rng = random.Random(seed)
    asset = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01", dns_names=["a.example"] if seed % 2 else [])
    for _ in range(200):
        op = rng.random()
        name = rng.choice(("a.example", "b.example", "c.example", "d.example"))
        if op < 0.7:
            expected = asset.dns_names + ([] if name in asset.dns_names else [name])
            asset.add_dns_name(name)
            assert asset.dns_names == expected
        elif op < 0.85:
            asset.dns_names.append(name)                    # changed directly
        elif op < 0.95:
            asset.dns_names = asset.dns_names[: rng.randint(0, len(asset.dns_names))]
        else:
            asset.dns_names = [name]


def test_evidence_index_does_not_change_equality_or_repr():
    first = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01")
    second = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01")
    for asset in (first, second):
        asset.add_evidence("vendor", "Siemens", 30, "OUI")
        asset.add_dns_name("a.example")
    first.has_evidence("port", "502")
    first.vendor_evidence_values()
    assert first == second and repr(first) == repr(second)
    assert "_ev_" not in repr(first) and "_dns_" not in repr(first)


# ── Peer first-seen times ─────────────────────────────────────────────────────

@pytest.mark.parametrize("seed", range(20))
def test_recent_peer_count_matches_first_seen_times_after_random_mutations(seed):
    rng = random.Random(seed)
    asset = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01",
                  peer_first_seen={"10.0.9.1": 5.0} if seed % 2 else {})
    for _ in range(300):
        op = rng.random()
        peer = f"10.0.1.{rng.randint(1, 80)}"
        ts = rng.choice((0, 1.5, 100, 3600, 3700.25, 7300)) + rng.random() * 50
        if op < 0.6:
            first = asset.peer_first_seen.get(peer, ts)
            asset.record_peer_first_seen(peer, ts)
            assert asset.peer_first_seen[peer] == first     # a later contact keeps the first time
        elif op < 0.8:
            asset.peer_first_seen.setdefault(peer, ts)      # changed directly
        elif op < 0.9:
            asset.peer_first_seen = {p: t for p, t in asset.peer_first_seen.items() if rng.random() < 0.5}
        else:
            asset.peer_first_seen = {peer: ts}             # replaced
        times = asset._synced_first_seen_times()
        assert times == sorted(asset.peer_first_seen.values())
        for cutoff in (-1, 0, 50, 3600, ts - 3600, ts, 1e9):
            assert asset.peers_first_seen_since(cutoff) == sum(1 for t in asset.peer_first_seen.values() if t >= cutoff)


def test_first_seen_times_do_not_change_equality_or_repr():
    first = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01")
    second = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01")
    first.record_peer_first_seen("10.0.1.1", 10.0)
    second.peer_first_seen["10.0.1.1"] = 10.0
    first.peers_first_seen_since(0)
    assert first == second and repr(first) == repr(second)
    assert "_first_seen_times" not in repr(first) and "_first_seen_source" not in repr(first)
