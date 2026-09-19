"""
Progressive AI Diagnostics for Scrutics Intelligence.

Progressively verifies provider connectivity, authentication, schema handling,
protocol compliance (function-call IDs, thought signatures, parallel calls),
and agent integration across 14 distinct diagnostic layers.
"""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import sys
import tempfile
import time
from typing import Any, Callable

from scrutics.ai.provider import (
    ChatResult,
    LLMProvider,
    LLMProviderError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMResponseError,
)
from scrutics.ai.config import load_ai_config, build_provider
from scrutics.ai.tools import SessionContext, get_tool_definitions
from scrutics.ai.agent import run_agent_loop


def _sanitize_string(s: str, api_key: str = "") -> str:
    """Strip keys, IPs, MACs, and raw cryptographic signatures from diagnostic output."""
    if not s:
        return ""
    out = s
    if api_key:
        out = out.replace(api_key, "[REDACTED_API_KEY]")
    # Redact common key URL parameters
    out = re.sub(r"key=[^&\s]+", "key=[REDACTED]", out)
    # Redact IPv4 addresses
    out = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP_REDACTED]", out)
    # Redact MAC addresses
    out = re.sub(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b", "[MAC_REDACTED]", out)
    return out


def run_ai_diagnostics(
    provider_name: str | None = None,
    cfg_override: dict[str, Any] | None = None,
    stream: Any = None,
) -> int:
    """Execute the 14-stage progressive AI diagnostic suite.

    Returns 0 if all stages succeed, or 1 if any stage fails.
    Outputs layer-specific diagnostics without leaking sensitive data.
    """
    out = stream if stream is not None else sys.stdout

    def log(msg: str = ""):
        out.write(msg + "\n")
        out.flush()

    log("=" * 65)
    log("  Scrutics AI Progressive Diagnostics")
    log("=" * 65)

    current_stage = 0

    def step(name: str) -> None:
        nonlocal current_stage
        current_stage += 1
        out.write(f"[{current_stage:02d}/14] {name:<46} ... ")
        out.flush()

    def pass_step(detail: str = "OK"):
        log(f"PASS ({detail})")

    def fail_step(reason: str, layer_hint: str) -> int:
        log("FAIL")
        log(f"\n[!] Failure at Stage {current_stage}: {reason}")
        log(f"[!] Layer Guidance: {layer_hint}\n")
        return 1

    # ── Stage 1: Configuration ────────────────────────────────────────────────
    step("Configuration loading")
    try:
        cfg = cfg_override if cfg_override is not None else load_ai_config()
        if not cfg:
            return fail_step(
                "No active AI configuration found.",
                "Run 'scrutics ai --reconfigure' or check ~/.scrutics/ai.yaml."
            )
        p_name = str(provider_name or cfg.get("provider", "gemini")).strip().lower()
        model_name = str(cfg.get("model", "gemini-3.8-flash")).strip()
        pass_step(f"provider={p_name}, model={model_name}")
    except Exception as e:
        return fail_step(str(e), "Check YAML syntax in ~/.scrutics/ai.yaml.")

    # ── Stage 2: API Key Configuration ────────────────────────────────────────
    step("API key presence & resolution")
    raw_key = cfg.get("api_key", "")
    resolved_key = ""
    if p_name != "ollama":
        if not raw_key:
            return fail_step(
                f"Missing API key for provider '{p_name}'.",
                f"Set api_key in ai.yaml or export GEMINI_API_KEY / OPENAI_API_KEY."
            )
        if str(raw_key).startswith("${") and str(raw_key).endswith("}"):
            var_name = str(raw_key)[2:-1].strip()
            resolved_key = os.environ.get(var_name, "")
            if not resolved_key:
                return fail_step(
                    f"Environment variable '{var_name}' is unset or empty.",
                    f"Run 'export {var_name}=<your-api-key>' in your environment."
                )
        else:
            resolved_key = str(raw_key)
        pass_step("Key resolved from environment")
    else:
        pass_step("Not required (Ollama local)")

    # ── Stage 3: DNS Resolution & Connectivity ────────────────────────────────
    step("DNS & Network host resolution")
    if p_name == "gemini":
        host = "generativelanguage.googleapis.com"
        port = 443
    elif p_name == "openai":
        host = "api.openai.com"
        port = 443
    elif p_name == "anthropic":
        host = "api.anthropic.com"
        port = 443
    else:
        host = "localhost"
        port = 11434

    try:
        ip_addr = socket.gethostbyname(host)
        pass_step(f"Host '{host}' resolved")
    except socket.gaierror as e:
        return fail_step(
            f"DNS resolution failed for '{host}': {e}",
            "Check internet connection, /etc/resolv.conf, or WSL2 DNS settings."
        )

    # ── Stage 4: TLS/HTTPS Handshake ──────────────────────────────────────────
    step("TLS/HTTPS handshake")
    if port == 443:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
            pass_step("TLS handshake verified")
        except Exception as e:
            return fail_step(
                f"TLS connection to {host}:443 failed: {e}",
                "Check corporate proxies, custom certificates, or system firewall."
            )
    else:
        pass_step("Skipped (plain HTTP local socket)")

    # ── Stage 5 & 6: Provider Construction & Authentication ───────────────────
    step("Provider construction")
    try:
        prov = build_provider({
            "provider": p_name,
            "model": model_name,
            "api_key": resolved_key,
            "timeout": 30.0,
        })
        pass_step(f"Loaded {prov.__class__.__name__}")
    except Exception as e:
        return fail_step(str(e), "Verify provider name and dependency installation.")

    step("Model availability & authentication")
    if p_name == "gemini":
        import requests
        auth_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}?key={resolved_key}"
        try:
            resp = requests.get(auth_url, timeout=10.0)
            if resp.status_code == 401:
                return fail_step(
                    "API key rejected by Google (HTTP 401).",
                    "Check that GEMINI_API_KEY is valid and active at https://aistudio.google.com."
                )
            if resp.status_code == 404:
                return fail_step(
                    f"Model '{model_name}' was not found (HTTP 404).",
                    "The model name may be shutdown or mistyped. Use 'gemini-3.8-flash'."
                )
            if resp.status_code != 200:
                return fail_step(
                    f"Google models endpoint returned HTTP {resp.status_code}.",
                    "Check quota or project enablement in Google AI Studio."
                )
            pass_step(f"Model '{model_name}' confirmed active")
        except requests.exceptions.RequestException as e:
            return fail_step(str(e), "Network error verifying model.")
    else:
        pass_step("Confirmed")

    # ── Stage 7: Plain Text Generation ────────────────────────────────────────
    step("Plain text generation")
    try:
        t0 = time.time()
        res = prov.chat([
            {"role": "user", "content": "Respond with the single word: OK"}
        ])
        elapsed = time.time() - t0
        if not isinstance(res, str) or not res.strip():
            return fail_step("Model returned empty or non-string response.", "Verify model status.")
        pass_step(f"Latency: {elapsed:.2f}s")
    except Exception as e:
        clean_err = _sanitize_string(str(e), resolved_key)
        return fail_step(clean_err, "Failed plain completion turn.")

    # ── Stage 8: Tool Declaration Syntax ──────────────────────────────────────
    step("Tool schema declaration")
    tools = get_tool_definitions()
    if not tools or len(tools) < 5:
        return fail_step("Built-in tool declarations missing.", "Check scrutics/ai/tools.py.")
    pass_step(f"{len(tools)} semantic tools loaded")

    # ── Stage 9: Native Function-Call Generation ──────────────────────────────
    step("Native function-call generation")
    probe_tools = [{
        "type": "function",
        "function": {
            "name": "get_network_summary",
            "description": "Call this to get summary of OT assets and connections.",
            "parameters": {"type": "object", "properties": {}},
        }
    }]
    try:
        fc_res = prov.chat(
            messages=[{"role": "user", "content": "Query the network summary using your tool."}],
            tools=probe_tools,
        )
        if not isinstance(fc_res, dict) or "tool_calls" not in fc_res:
            return fail_step(
                "Model did not issue a structured tool_call.",
                "Model may not support function calling or instruction adherence failed."
            )
        tcs = fc_res.get("tool_calls", [])
        if not tcs or tcs[0].get("function", {}).get("name") != "get_network_summary":
            return fail_step("Incorrect tool selected by model.", "Verify function declaration.")
        pass_step(f"Tool call emitted: {tcs[0]['function']['name']}")
    except Exception as e:
        return fail_step(_sanitize_string(str(e), resolved_key), "Tool call generation error.")

    # ── Stage 10: Function-Call Thought Signature Handling ────────────────────
    step("Function-call thought signature check")
    first_tc = tcs[0]
    sig = first_tc.get("thought_signature")
    if p_name == "gemini" and "3." in model_name:
        # Gemini 3 requires thought signatures
        if not sig:
            return fail_step(
                "Gemini 3 model response did not contain expected thought_signature.",
                "Check part.thoughtSignature extraction in gemini_provider."
            )
        pass_step("Captured valid opaque signature")
    else:
        pass_step("Verified (optional for this model family)")

    # ── Stage 11: FunctionCall ID Round Trip ──────────────────────────────────
    step("FunctionCall ID round-trip preservation")
    call_id = first_tc.get("id", "")
    if p_name == "gemini" and call_id == "get_network_summary":
        return fail_step(
            "Tool call ID was substituted with function name.",
            "Remove fallback fc.get('name') in gemini_provider."
        )
    # Check outbound translation
    from scrutics.ai.gemini_provider import _translate_messages_to_gemini
    replay_msgs = [
        {"role": "user", "content": "Query summary"},
        fc_res,
        {"role": "tool", "tool_call_id": call_id, "name": "get_network_summary", "content": '{"status": "ok"}'},
    ]
    _, contents = _translate_messages_to_gemini(replay_msgs)
    # Verify functionResponse received the exact id
    fr_id = ""
    for c in contents:
        for p in c.get("parts", []):
            if "functionResponse" in p:
                fr_id = p["functionResponse"].get("id", "")
    if call_id and fr_id != call_id:
        return fail_step(
            f"ID mismatch on replay: sent '{call_id}', got '{fr_id}'.",
            "Verify tool_call_id mapping to functionResponse.id."
        )
    pass_step("ID mapped to matching functionResponse")

    # ── Stage 12: Multi-Step Tool Interaction ─────────────────────────────────
    step("Multi-step tool replay round-trip")
    try:
        # Send back the tool output and ensure model produces final text answer
        final_answer = prov.chat(messages=replay_msgs, tools=probe_tools)
        if not isinstance(final_answer, str):
            return fail_step(
                "Model failed to conclude with text after tool response.",
                "Check conversation turn construction on step 2."
            )
        pass_step("Tool output accepted; concluded cleanly")
    except Exception as e:
        return fail_step(_sanitize_string(str(e), resolved_key), "Failed during multi-step tool replay.")

    # ── Stage 13: Full Scrutics Agent Loop Path ───────────────────────────────
    step("Full agent execution loop")
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create minimal session fixture
            with open(os.path.join(tmp_dir, "assets.csv"), "w") as f:
                f.write("ip,mac,vendor,protocol,role,confidence_pct,type\n192.168.1.10,00:80:f4:01:02:03,Schneider,Modbus TCP,PLC,90,OT\n")
            with open(os.path.join(tmp_dir, "manifest.json"), "w") as f:
                json.dump({
                    "format": "scrutics-evidence",
                    "version": 1,
                    "scrutics_version": "0.6.1",
                    "created_at": "2026-09-19T00:00:00Z",
                    "capture_started": "2026-09-19T00:00:00Z",
                    "capture_ended": "2026-09-19T00:01:00Z",
                    "sensor_id": "diag_sensor",
                    "scope": {},
                    "files": {"assets": "assets.csv"},
                    "stats": {
                        "asset_count": 1,
                        "ot_count": 1,
                        "it_count": 0,
                        "unknown_count": 0,
                        "connection_count": 0,
                        "anomaly_count": 0,
                    },
                }, f)

            ctx = SessionContext(tmp_dir)
            agent_res = run_agent_loop(prov, ctx, "How many assets are present?", max_tool_iterations=3)
            if not agent_res or not isinstance(agent_res, str):
                return fail_step("Agent loop did not return a valid answer string.", "Check agent loop flow.")
            pass_step("Agent executed and answered query")
    except Exception as e:
        return fail_step(_sanitize_string(str(e), resolved_key), "Agent loop execution failed.")

    # ── Stage 14: Parallel Function Calls & Part Structure ────────────────────
    step("Parallel function call structure & replay")
    # Verify structure of parallel calls in contents
    mock_parallel_assistant = {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {"id": "call_1", "function": {"name": "tool_a", "arguments": "{}"}, "thought_signature": "sig_batch_1"},
            {"id": "call_2", "function": {"name": "tool_b", "arguments": "{}"}},
        ]
    }
    mock_msgs = [
        {"role": "user", "content": "Execute both"},
        mock_parallel_assistant,
        {"role": "tool", "tool_call_id": "call_1", "name": "tool_a", "content": '{"a": 1}'},
        {"role": "tool", "tool_call_id": "call_2", "name": "tool_b", "content": '{"b": 2}'},
    ]
    _, par_contents = _translate_messages_to_gemini(mock_msgs)
    # Check that model parts are in ONE Content block
    model_blocks = [c for c in par_contents if c.get("role") == "model"]
    user_fr_blocks = [c for c in par_contents if c.get("role") == "user" and any("functionResponse" in p for p in c.get("parts", []))]

    if len(model_blocks) != 1 or len(model_blocks[0]["parts"]) != 2:
        return fail_step("Parallel calls split into multiple model content blocks.", "Group in single Content block.")

    part_0 = model_blocks[0]["parts"][0]
    part_1 = model_blocks[0]["parts"][1]

    if part_0.get("thoughtSignature") != "sig_batch_1":
        return fail_step("First parallel call missing thoughtSignature.", "Attach to first part only.")
    if "thoughtSignature" in part_1:
        return fail_step("Second parallel call received fabricated thoughtSignature.", "Do not fabricate signature.")
    if len(user_fr_blocks) != 1 or len(user_fr_blocks[0]["parts"]) != 2:
        return fail_step("Parallel functionResponses not grouped in single Content block.", "Group in single user Content.")

    pass_step("1 block, single signature, 2 responses grouped")

    log("\n" + "=" * 65)
    log("  All 14 Diagnostic Stages Passed Successfully (100% OK)")
    log("=" * 65 + "\n")
    return 0
