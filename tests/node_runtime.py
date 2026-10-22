"""
Node.js for the tests that run the topology page's scripts.

Where Node is required (CI is set, as on the CI runners that install Node, or
SCRUTICS_REQUIRE_NODE=1 locally) a missing Node fails the test instead of skipping it, so a run
cannot pass while these checks silently did not run.
"""

import os
import shutil

import pytest


def find_node():
    return shutil.which("node") or os.environ.get("SCRUTICS_NODE")


def node_required() -> bool:
    return bool(os.environ.get("CI")) or os.environ.get("SCRUTICS_REQUIRE_NODE") == "1"


def require_node(purpose: str = "check the topology page scripts") -> str:
    """The Node.js executable; skips the test without one, or fails it where Node is required."""
    node = find_node()
    if node is None:
        if node_required():
            pytest.fail(f"Node.js is required (CI or SCRUTICS_REQUIRE_NODE=1) to {purpose}")
        pytest.skip("Node.js not installed")
    return node
