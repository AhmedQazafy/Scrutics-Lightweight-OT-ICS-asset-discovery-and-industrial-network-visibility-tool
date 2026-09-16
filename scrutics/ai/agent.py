"""
Tool-calling agent execution loop for Scrutics Intelligence.
Orchestrates multi-turn model interaction against the Semantic Tool API.
"""

from __future__ import annotations

import json
from typing import Any, Callable

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

# ── OT-Aware System Prompt ─────────────────────────────────────────────────────

OT_SYSTEM_PROMPT = """You are the Scrutics OT network analysis assistant.

Scrutics is a passive network sensor. It observes traffic without
interacting with devices. Its observations are authoritative for
what it has seen. It does not actively probe devices.

Your responsibilities:
1. Interpret Scrutics' evidence accurately.
2. Explain network observations in plain English.
3. Identify anomalies and their significance.
4. Relate findings to device behavior and constraints.
5. Recommend investigation actions when appropriate.

NEVER:
- Invent network observations that Scrutics did not report.
- Claim to know firmware versions or CVEs unless Scrutics evidence
  explicitly supports it.
- Pretend to have active discovery capabilities.
- Make absolute claims about device safety or security.
- Hallucinate data that Scrutics does not contain.

When evidence is insufficient, explicitly state what is unknown
and suggest how Scrutics could gather more information.
If a user asks about an IP address or device that does not exist in
the session evidence, clearly state that it was not observed, list or
summarize the devices/subnets that WERE observed, and suggest what
the user can check or ask next.

Distinguish between:
- Observed evidence (directly from traffic)
- Inferred conclusions (based on evidence patterns)
- Speculation (not supported by evidence)

Be honest about confidence levels. Low confidence is valuable
information — it tells the user to investigate further.

Your goal is to make OT network data accessible to operators,
engineers, and security staff who may not be network experts."""


TOOL_REGISTRY: dict[str, Callable[..., Any]] = {
    "get_statistics": get_statistics,
    "get_assets": get_assets,
    "get_asset": get_asset,
    "get_connections": get_connections,
    "get_anomalies": get_anomalies,
}


def run_agent_loop(
    provider: LLMProvider,
    ctx: SessionContext,
    user_message: str,
    system_prompt: str | None = None,
    max_tool_iterations: int = 5,
    status_callback: Callable[[str], None] | None = None,
) -> str:
    """
    Execute an agentic tool-calling loop for one user inquiry.

    Repeatedly sends the conversation and tool definitions to the LLM.
    If the model issues tool calls, executes them against SessionContext and appends
    tool responses, iterating until the model produces a final text answer or
    reaches max_tool_iterations.
    """
    effective_system_prompt = system_prompt or OT_SYSTEM_PROMPT
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": effective_system_prompt},
        {"role": "user", "content": user_message},
    ]
    tools = get_tool_definitions()

    for iteration in range(max_tool_iterations):
        if iteration == 0 and status_callback:
            status_callback("Thinking...")

        response = provider.chat(messages=messages, tools=tools, stream=False)

        # Plain text answer received -> complete
        if isinstance(response, str):
            return response

        # Structured tool-calls message returned
        if isinstance(response, dict) and "tool_calls" in response:
            messages.append(response)
            tool_calls = response.get("tool_calls") or []

            for call in tool_calls:
                call_id = call.get("id", "")
                func_info = call.get("function", {})
                fn_name = func_info.get("name", "")
                args_raw = func_info.get("arguments", "{}")

                if status_callback:
                    status_callback(f"Running {fn_name}...")

                # Parse JSON arguments safely
                if isinstance(args_raw, str):
                    try:
                        args = json.loads(args_raw) if args_raw.strip() else {}
                    except json.JSONDecodeError:
                        args = {}
                elif isinstance(args_raw, dict):
                    args = args_raw
                else:
                    args = {}

                # Execute requested tool from registry
                tool_fn = TOOL_REGISTRY.get(fn_name)
                if tool_fn is None:
                    result = {"error": f"Tool '{fn_name}' does not exist"}
                else:
                    try:
                        result = tool_fn(ctx, **args)
                    except Exception as e:
                        result = {"error": f"Error executing tool '{fn_name}': {e}"}

                messages.append({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "name": fn_name,
                    "content": json.dumps(result, default=str),
                })

            if status_callback:
                status_callback("Formulating answer...")
        else:
            # Fallback for unexpected response shape
            return str(response)

    return (
        f"I was unable to reach a final answer within the maximum allowed "
        f"tool iterations ({max_tool_iterations})."
    )
