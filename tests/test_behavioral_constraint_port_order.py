"""
Behavioral constraints taken from the rules that match an asset's contacted ports.

Each contacted port gets the first rule match_rule returns for it: a rule without a port key
matches any port (when its MAC prefix fits) and shadows later port rules; a rule with a
protocol never matches here. Of the ports whose rule sets constraints, the highest is used, whatever
order the ports were contacted in, and only that rule's constraints are added; constraints added
by earlier packets stay. Contacted OT ports in a classification reason are listed in ascending
order.
"""

import itertools
import random

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

import scrutics.classifier.protocol as protocol
from scrutics.capture.engine import CaptureEngine
from scrutics.classifier.asset_classifier import _SIGNATURE_BY_PORT, classify_asset
from scrutics.config.loader import match_rule
from scrutics.db.inventory import Asset, AssetInventory

MAC = "02:00:00:00:00:a1"
CONSTRAINT_KEYS = ("never_initiates", "allowed_peers", "allowed_ports", "alert_on_new_port", "max_new_peers_per_hour")


def _rule(name, **fields):
    return {"name": name, "classify_as": name, "role": name, "is_ot": True, **fields}


@pytest.fixture
def rules(monkeypatch):
    def use(user_rules, builtin_rules=()):
        monkeypatch.setattr(protocol, "_USER_RULES", list(user_rules))
        monkeypatch.setattr(protocol, "_BUILTIN_RULES", list(builtin_rules))
    return use


def _client(engine, ports, src_ip="10.0.0.70", mac=MAC):
    for i, port in enumerate(ports):
        pkt = Ether(src=mac, dst="02:00:00:00:00:fe") / IP(src=src_ip, dst="10.0.0.99") / TCP(sport=40000, dport=port, flags="PA")
        pkt.time = 1_700_000_000.0 + i
        engine._process_packet(pkt)
    return engine.inventory.get(src_ip)


def _engine():
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    return engine


CONFLICTING = [
    _rule("modbus", port=502, allowed_ports=[502]),
    _rule("dnp3", port=20000, allowed_ports=[20000]),
    _rule("s7", port=102, allowed_ports=[102]),
]


@pytest.mark.parametrize("order", list(itertools.permutations((502, 20000, 102))))
def test_highest_matching_port_writes_a_conflicting_key_last(order, rules):
    rules(CONFLICTING)
    asset = _client(_engine(), order)
    assert asset.behavioral_constraints["allowed_ports"] == [20000]


@pytest.mark.parametrize("order", [(102, 502), (502, 102)])
def test_highest_matching_port_wins_among_the_ports_contacted(order, rules):
    rules(CONFLICTING)
    asset = _client(_engine(), order + (80,))
    assert asset.behavioral_constraints["allowed_ports"] == [502]


@pytest.mark.parametrize("order", [(502, 20000), (20000, 502)])
def test_only_the_highest_matching_port_supplies_constraints(order, rules):
    rules([_rule("modbus", port=502, allowed_ports=[502]), _rule("dnp3", port=20000, never_initiates=True)])
    engine = _engine()
    asset = Asset(ip="10.0.0.70", mac=MAC, contacted_ports=set(order))
    engine._apply_constraints_from_contacted_ports(asset)
    assert asset.behavioral_constraints == {"never_initiates": True}


def test_constraints_added_by_earlier_packets_stay(rules):
    rules([_rule("modbus", port=502, allowed_ports=[502]), _rule("dnp3", port=20000, never_initiates=True)])
    asset = _client(_engine(), (502, 20000))
    assert asset.behavioral_constraints == {"allowed_ports": [502], "never_initiates": True}


def test_a_port_without_constraints_does_not_hide_a_lower_one(rules):
    rules([_rule("modbus", port=502, allowed_ports=[502]), _rule("dnp3", port=20000)])
    asset = Asset(ip="10.0.0.70", mac=MAC, contacted_ports={502, 20000})
    _engine()._apply_constraints_from_contacted_ports(asset)
    assert asset.behavioral_constraints == {"allowed_ports": [502]}


def test_a_rule_without_a_port_shadows_later_port_rules(rules):
    rules([_rule("lab", mac_prefix=MAC), _rule("modbus", port=502, allowed_ports=[502])])
    assert _client(_engine(), (502,)).behavioral_constraints == {}


def test_a_port_rule_before_the_rule_without_a_port_still_applies(rules):
    rules([_rule("modbus", port=502, allowed_ports=[502]), _rule("lab", mac_prefix=MAC),
           _rule("dnp3", port=20000, alert_on_new_port=True)])
    assert _client(_engine(), (502, 20000)).behavioral_constraints == {"allowed_ports": [502]}


def test_a_rule_with_a_protocol_never_supplies_constraints(rules):
    rules([_rule("enip", port=44818, protocol="TCP", never_initiates=True)])
    assert _client(_engine(), (44818,)).behavioral_constraints == {}


def test_constraints_follow_rules_replaced_between_packets(rules):
    engine = _engine()
    rules([])
    assert _client(engine, (502,)).behavioral_constraints == {}
    rules([_rule("modbus", port=502, allowed_ports=[502])])
    assert _client(engine, (502,)).behavioral_constraints == {"allowed_ports": [502]}


def _reference(asset, rule_list):
    """Constraints as match_rule gives them: the highest contacted port whose rule sets any."""
    constraints = dict(asset.behavioral_constraints)
    extract = lambda rule: {k: rule[k] for k in CONSTRAINT_KEYS if k in rule}
    if asset.mac:
        rule = match_rule(rule_list, mac=asset.mac)
        if rule and extract(rule):
            constraints.update(extract(rule))
            return constraints
    for port in sorted(asset.contacted_ports, reverse=True):
        rule = match_rule(rule_list, port=port, mac=asset.mac)
        if rule and extract(rule):
            constraints.update(extract(rule))
            return constraints
    return constraints


def _random_rules(rng):
    rule_list = []
    for i in range(rng.randint(0, 8)):
        fields = {}
        if rng.random() < 0.75:
            fields["port"] = rng.choice((502, 102, 20000, 44818, 80, 9999))
        if rng.random() < 0.3:
            fields["mac_prefix"] = rng.choice(("02:00:00", "00:80:F4"))
        if rng.random() < 0.15:
            fields["protocol"] = "TCP"
        for key, value in (("allowed_ports", [i]), ("never_initiates", bool(i % 2)), ("max_new_peers_per_hour", i + 1)):
            if rng.random() < 0.4:
                fields[key] = value
        rule_list.append(_rule(f"r{i}", **fields))
    return rule_list


@pytest.mark.parametrize("seed", range(40))
def test_constraints_equal_the_first_match_of_the_highest_port_with_constraints(seed, rules):
    rng = random.Random(seed)
    rule_list = _random_rules(rng)
    rules(rule_list)
    engine = _engine()
    for mac in ("02:00:00:00:00:01", "00:80:f4:00:00:01", "Unknown", ""):
        asset = Asset(ip="10.0.0.70", mac=mac)
        asset.contacted_ports = set(rng.sample((502, 102, 20000, 44818, 80, 9999, 1, 65000), k=rng.randint(0, 8)))
        asset.behavioral_constraints = {"allowed_peers": ["10.0.0.1"]} if rng.random() < 0.3 else {}
        expected = _reference(asset, rule_list)
        engine._apply_constraints_from_contacted_ports(asset)
        assert asset.behavioral_constraints == expected


@pytest.mark.parametrize("seed", range(10))
def test_contacted_ot_ports_are_listed_in_ascending_order(seed):
    rng = random.Random(seed)
    asset = Asset(ip="10.0.0.70", mac=MAC)
    asset.contacted_ports = set(rng.sample(range(1, 65536), k=200)) | set(rng.sample(sorted(_SIGNATURE_BY_PORT), k=10))
    classify_asset(asset)
    expected = sorted(p for p in asset.contacted_ports if getattr(_SIGNATURE_BY_PORT.get(p), "category", None) == "OT")
    listed = [p for p in expected if f"({p})" in asset.classification_reason]
    assert listed == expected
    positions = [asset.classification_reason.index(f"({p})") for p in expected]
    assert positions == sorted(positions)
