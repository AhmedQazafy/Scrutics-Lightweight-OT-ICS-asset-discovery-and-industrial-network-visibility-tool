"""Tests that need Node.js skip without it, except where Node is required (CI, SCRUTICS_REQUIRE_NODE=1)."""

import pytest

from tests import node_runtime


@pytest.fixture
def no_node(monkeypatch):
    monkeypatch.setattr(node_runtime.shutil, "which", lambda name: None)
    for name in ("SCRUTICS_NODE", "CI", "SCRUTICS_REQUIRE_NODE"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_a_missing_node_skips_locally(no_node):
    with pytest.raises(pytest.skip.Exception):
        node_runtime.require_node()


def test_a_missing_node_fails_in_ci(no_node):
    no_node.setenv("CI", "true")
    with pytest.raises(pytest.fail.Exception, match="Node.js is required"):
        node_runtime.require_node()


def test_a_missing_node_fails_when_required_locally(no_node):
    no_node.setenv("SCRUTICS_REQUIRE_NODE", "1")
    with pytest.raises(pytest.fail.Exception, match="SCRUTICS_REQUIRE_NODE=1"):
        node_runtime.require_node()


def test_require_node_other_than_1_still_skips(no_node):
    no_node.setenv("SCRUTICS_REQUIRE_NODE", "0")
    with pytest.raises(pytest.skip.Exception):
        node_runtime.require_node()


def test_node_on_path_or_in_scrutics_node_is_returned(no_node):
    no_node.setenv("SCRUTICS_NODE", "/opt/node/bin/node")
    assert node_runtime.require_node() == "/opt/node/bin/node"
    no_node.setattr(node_runtime.shutil, "which", lambda name: "/usr/bin/node")
    assert node_runtime.require_node() == "/usr/bin/node"
