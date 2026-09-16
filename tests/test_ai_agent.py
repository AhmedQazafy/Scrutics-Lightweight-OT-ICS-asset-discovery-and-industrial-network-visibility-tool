"""Tests for the semantic tool API and the agent tool-calling loop.

Covers SessionContext loading, the five read-only tool functions,
tool schema generation, and run_agent_loop() behavior including
tool execution, iteration cap, and plain-text short-circuit.
"""

import json
from typing import Any, Iterator
import pytest

from scrutics.ai.provider import LLMProvider
from scrutics.ai.tools import (
    SessionContext,
    get_statistics,
    get_assets,
    get_asset,
    get_connections,
    get_anomalies,
    get_tool_definitions,
)
from scrutics.ai.agent import (
    TOOL_REGISTRY,
    OT_SYSTEM_PROMPT,
    run_agent_loop,
)
from scrutics.topology import write_manifest


# ── Test Double / FakeLLMProvider ──────────────────────────────────────────────

class FakeLLMProvider(LLMProvider):
    """Scripted LLM test double that returns pre-configured responses in sequence."""

    def __init__(self, responses: list[str | dict[str, Any]]):
        self.responses = list(responses)
        self.call_history: list[dict[str, Any]] = []

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        stream: bool = False,
        timeout: float = 30.0,
    ) -> str | dict[str, Any] | Iterator[str]:
        self.call_history.append({"messages": messages, "tools": tools})
        if not self.responses:
            return "No more scripted responses."
        return self.responses.pop(0)


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def session_fixture(tmp_path):
    """Creates a realistic, complete session directory fixture."""
    session_dir = tmp_path / "scrutics_20260905_120000"
    session_dir.mkdir()

    # 1. assets.csv
    assets_csv = session_dir / "assets.csv"
    assets_content = (
        "ip,mac,vendor,protocol,role,confidence_pct,type\n"
        "192.168.100.10,00:80:f4:11:22:33,Schneider Electric,Modbus TCP,PLC,85,OT\n"
        "192.168.100.20,00:1b:1b:44:55:66,Siemens AG,S7comm,PLC,90,OT\n"
        "192.168.100.50,00:50:56:aa:bb:cc,VMware,HTTP,Workstation,40,IT\n"
        "192.168.100.99,00:00:00:00:00:00,Unknown,,Unclassified,10,Unknown\n"
    )
    assets_csv.write_text(assets_content, encoding="utf-8")

    # 2. evidence.json
    evidence_json = session_dir / "evidence.json"
    evidence_data = {
        "192.168.100.10": [
            {"type": "vendor", "value": "Schneider Electric", "weight": 30, "source": "OUI", "confidence": "HIGH"},
            {"type": "port", "value": "502", "weight": 20, "source": "traffic", "confidence": "HIGH"},
        ],
        "192.168.100.20": [
            {"type": "vendor", "value": "Siemens AG", "weight": 30, "source": "OUI", "confidence": "HIGH"},
            {"type": "protocol", "value": "S7comm", "weight": 40, "source": "traffic", "confidence": "HIGH"},
        ],
    }
    evidence_json.write_text(json.dumps(evidence_data), encoding="utf-8")

    # 3. connections.csv
    connections_csv = session_dir / "connections.csv"
    connections_content = (
        "source,destination,protocol,count\n"
        "192.168.100.50,192.168.100.10,Modbus TCP,45\n"
        "192.168.100.50,192.168.100.20,S7comm,12\n"
        "192.168.100.10,192.168.100.20,EtherNet/IP,5\n"
    )
    connections_csv.write_text(connections_content, encoding="utf-8")

    # 4. anomalies.csv
    anomalies_csv = session_dir / "anomalies.csv"
    anomalies_content = (
        "timestamp,ip,severity,type,detail\n"
        "2026-09-05T12:05:00,192.168.100.10,HIGH,NEW_PEER,Unexpected communication with 10.0.0.99\n"
        "2026-09-05T12:10:00,192.168.100.50,LOW,INTERVAL_ANOMALY,Polling interval jitter\n"
    )
    anomalies_csv.write_text(anomalies_content, encoding="utf-8")

    # 5. manifest.json
    write_manifest(str(session_dir))

    return str(session_dir)


# ── Semantic Tools Tests ───────────────────────────────────────────────────────

def test_get_statistics(session_fixture):
    """1. get_statistics returns correct counts against a fixture session directory."""
    ctx = SessionContext(session_fixture)
    stats = get_statistics(ctx)

    assert stats["asset_count"] == 4
    assert stats["ot_count"] == 2
    assert stats["it_count"] == 1
    assert stats["unknown_count"] == 1
    assert stats["connection_count"] == 3
    assert stats["anomaly_count"] == 2


def test_get_assets_filter_by_type(session_fixture):
    """2. get_assets filtering by asset_type works."""
    ctx = SessionContext(session_fixture)

    ot_assets = get_assets(ctx, asset_type="OT")
    assert len(ot_assets) == 2
    assert all(a["type"] == "OT" for a in ot_assets)

    it_assets = get_assets(ctx, asset_type="IT")
    assert len(it_assets) == 1
    assert it_assets[0]["ip"] == "192.168.100.50"


def test_get_assets_filter_by_confidence(session_fixture):
    """3. get_assets filtering by min_confidence works."""
    ctx = SessionContext(session_fixture)

    high_conf = get_assets(ctx, min_confidence=80)
    assert len(high_conf) == 2
    assert {a["ip"] for a in high_conf} == {"192.168.100.10", "192.168.100.20"}


def test_get_assets_truncation_flag(session_fixture):
    """4. get_assets truncation flag appears when max_results cap is exceeded."""
    ctx = SessionContext(session_fixture)

    # Use max_results=2 to trigger truncation with 4 total assets
    result = get_assets(ctx, max_results=2)
    assert isinstance(result, dict)
    assert result["truncated"] is True
    assert result["total_count"] == 4
    assert len(result["assets"]) == 2


def test_get_asset_known_ip(session_fixture):
    """5. get_asset returns full detail and evidence for a known IP."""
    ctx = SessionContext(session_fixture)
    asset = get_asset(ctx, "192.168.100.10")

    assert asset["ip"] == "192.168.100.10"
    assert asset["vendor"] == "Schneider Electric"
    assert "evidence" in asset
    assert len(asset["evidence"]) == 2
    assert asset["evidence"][0]["value"] == "Schneider Electric"


def test_get_asset_unknown_ip_returns_error_dict(session_fixture):
    """6. get_asset returns error dict (not raising) for an unknown IP."""
    ctx = SessionContext(session_fixture)
    result = get_asset(ctx, "192.168.100.254")

    assert isinstance(result, dict)
    assert "error" in result
    assert "192.168.100.254" in result["error"]


def test_get_connections_filtering(session_fixture):
    """7. get_connections filtering by ip and protocol both work."""
    ctx = SessionContext(session_fixture)

    # Filter by IP (source or destination)
    conns_ip = get_connections(ctx, ip="192.168.100.10")
    assert conns_ip["total_count"] == 2
    assert len(conns_ip["connections"]) == 2

    # Filter by protocol
    conns_proto = get_connections(ctx, protocol="Modbus TCP")
    assert conns_proto["total_count"] == 1
    assert conns_proto["connections"][0]["source"] == "192.168.100.50"
    assert conns_proto["connections"][0]["destination"] == "192.168.100.10"

    # Truncation check
    conns_trunc = get_connections(ctx, max_results=1)
    assert isinstance(conns_trunc, dict)
    assert conns_trunc["truncated"] is True
    assert len(conns_trunc["connections"]) == 1


def test_get_anomalies_filter_by_severity(session_fixture):
    """8. get_anomalies filtering by severity works."""
    ctx = SessionContext(session_fixture)

    high_anoms = get_anomalies(ctx, severity="HIGH")
    assert high_anoms["total_count"] == 1
    assert high_anoms["anomalies"][0]["ip"] == "192.168.100.10"
    assert high_anoms["anomalies"][0]["type"] == "NEW_PEER"

    all_anoms = get_anomalies(ctx)
    assert all_anoms["total_count"] == 2


def test_get_tool_definitions_schema():
    """9. get_tool_definitions produces valid OpenAI-style function calling schemas."""
    definitions = get_tool_definitions()
    assert len(definitions) == 5

    names = {d["function"]["name"] for d in definitions}
    expected_names = {"get_statistics", "get_assets", "get_asset", "get_connections", "get_anomalies"}
    assert names == expected_names

    for d in definitions:
        assert d["type"] == "function"
        fn = d["function"]
        assert "name" in fn
        assert "description" in fn
        assert "parameters" in fn
        assert fn["parameters"]["type"] == "object"


# ── Tool-Calling Agent Loop Tests ──────────────────────────────────────────────

def test_run_agent_loop_immediate_text(session_fixture):
    """10. run_agent_loop with immediate text response returns answer without tool execution."""
    ctx = SessionContext(session_fixture)
    provider = FakeLLMProvider(["There are 2 PLCs discovered on the network."])

    answer = run_agent_loop(provider, ctx, "How many PLCs are there?")
    assert answer == "There are 2 PLCs discovered on the network."
    assert len(provider.call_history) == 1


def test_run_agent_loop_with_tool_call(session_fixture):
    """11. run_agent_loop executes tool call and returns final answer on subsequent turn."""
    ctx = SessionContext(session_fixture)

    tool_call_response = {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "id": "call_123",
                "type": "function",
                "function": {
                    "name": "get_assets",
                    "arguments": json.dumps({"asset_type": "OT"}),
                },
            }
        ],
    }
    final_text_response = "I found 2 OT devices: 192.168.100.10 (Schneider) and 192.168.100.20 (Siemens)."

    provider = FakeLLMProvider([tool_call_response, final_text_response])
    answer = run_agent_loop(provider, ctx, "List the OT devices.")

    assert answer == final_text_response
    # Verify two turns were made
    assert len(provider.call_history) == 2
    # Verify second turn contained the tool result
    second_turn_messages = provider.call_history[1]["messages"]
    tool_msg = [m for m in second_turn_messages if m.get("role") == "tool"][0]
    assert tool_msg["tool_call_id"] == "call_123"
    assert tool_msg["name"] == "get_assets"
    parsed_tool_result = json.loads(tool_msg["content"])
    assert len(parsed_tool_result) == 2


def test_run_agent_loop_max_iterations_safety_cap(session_fixture):
    """12. run_agent_loop hits max_tool_iterations cap when model loops indefinitely."""
    ctx = SessionContext(session_fixture)

    looping_response = {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "id": "call_loop",
                "type": "function",
                "function": {
                    "name": "get_statistics",
                    "arguments": "{}",
                },
            }
        ],
    }
    # Script provider to always request get_statistics (more than 5 times)
    provider = FakeLLMProvider([looping_response] * 10)
    answer = run_agent_loop(provider, ctx, "Loop test", max_tool_iterations=3)

    assert "unable to reach a final answer within the maximum allowed tool iterations (3)" in answer
    assert len(provider.call_history) == 3
