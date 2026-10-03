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
