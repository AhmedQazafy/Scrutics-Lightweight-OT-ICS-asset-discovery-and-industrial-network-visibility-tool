"""Every inline script in a generated topology page must parse as JavaScript."""

import os
import re
import shutil
import subprocess

import pytest

from scrutics.db.inventory import Asset
from scrutics.topology import HTML_TEMPLATE, build_graph_data, generate_topology_html

_SCRIPT_RE = re.compile(r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>", re.S | re.I)


def _node():
    node = shutil.which("node")
    if node is None:
        if os.environ.get("CI"):
            pytest.fail("Node.js is required in CI to check the topology page scripts")
        pytest.skip("Node.js not installed")
    return node


def _inline_scripts(page):
    scripts = []
    for match in _SCRIPT_RE.finditer(page):
        attrs = match.group("attrs").lower()
        if "src=" in attrs or "application/json" in attrs:
            continue
        scripts.append(match.group("body"))
    return scripts


class _Inventory:
    def __init__(self, assets):
        self._assets = assets

    def get_all(self):
        return list(self._assets)


def _sample_page():
    plc = Asset(ip="10.0.0.10", mac="00:0e:8c:00:00:10", protocols=["Modbus TCP"])
    hmi = Asset(ip="10.0.0.20", mac="00:0c:26:00:00:20")
    edges = {(hmi.primary_key, plc.primary_key): {"protocols": {"Modbus TCP"}, "count": 5}}
    return generate_topology_html(build_graph_data(_Inventory([plc, hmi]), edges))


def _check_parses(node, tmp_path, scripts):
    failures = []
    for i, body in enumerate(scripts):
        path = tmp_path / f"inline_{i}.js"
        path.write_text(body, encoding="utf-8")
        result = subprocess.run([node, "--check", str(path)], capture_output=True, text=True)
        if result.returncode != 0:
            errors = [line for line in result.stderr.splitlines() if "Error" in line]
            failures.append(f"script {i}: {errors or result.stderr.strip()}")
    return failures


def test_every_inline_script_parses(tmp_path):
    node = _node()
    scripts = _inline_scripts(_sample_page())
    assert len(scripts) >= 2, "expected the graph script and the assistant script"
    assert _check_parses(node, tmp_path, scripts) == []


def test_template_backslash_escapes_reach_the_page():
    page = _sample_page()
    assert r'lines.join("\n")' in page
    assert "\\" not in HTML_TEMPLATE.replace("\\n", "").replace("\\/", "")


def test_page_uses_configured_default_models():
    from scrutics.ai.config import (
        DEFAULT_ANTHROPIC_MODEL, DEFAULT_GEMINI_MODEL, DEFAULT_OPENAI_MODEL,
    )
    page = _sample_page()
    for model in (DEFAULT_OPENAI_MODEL, DEFAULT_ANTHROPIC_MODEL, DEFAULT_GEMINI_MODEL):
        assert model in page
    assert "gemini-2.0-flash" not in page
    assert "_MODEL_HTML__" not in page and "__AI_MODELS_JSON__" not in page
