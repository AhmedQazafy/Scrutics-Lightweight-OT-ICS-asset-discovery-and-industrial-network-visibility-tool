"""Anthropic Messages API provider for Scrutics Intelligence.

Implements LLMProvider using Anthropic's /v1/messages endpoint.
Internally translates between Anthropic's native request/response shapes
(input_schema, tool_use content blocks, tool_result) and the internal
OpenAI-compatible contract expected by run_agent_loop():
  - Incoming tool_calls → normalized to {id, type, function: {name, arguments: str}}
  - Outgoing tool messages (role=tool) → translated to Anthropic tool_result blocks
"""

import json
from typing import Any, Iterator

import requests

from scrutics.ai.provider import (
    LLMProvider,
    LLMConnectionError,
    LLMTimeoutError,
    LLMResponseError,
    LLMProviderError,
)

_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


def _openai_tools_to_anthropic(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert OpenAI-style tool definitions to Anthropic format.

    OpenAI:  {"type": "function", "function": {"name": ..., "description": ..., "parameters": {...}}}
    Anthropic: {"name": ..., "description": ..., "input_schema": {...}}
    """
    result = []
    for tool in tools:
        fn = tool.get("function", tool)  # handle flat or nested
        result.append({
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters") or fn.get("input_schema") or {
                "type": "object", "properties": {}
            },
        })
    return result


def _translate_messages_to_anthropic(
    messages: list[dict[str, Any]],
) -> tuple[str | None, list[dict[str, Any]]]:
    """Separate the system prompt and translate messages to Anthropic format.

    Returns (system_prompt_str | None, anthropic_messages_list).

    Handles:
    - role=system → extracted as system string
    - role=user   → {"role": "user", "content": str | list}
    - role=assistant with tool_calls → {"role": "assistant", "content": [tool_use blocks]}
    - role=tool   → {"role": "user", "content": [tool_result blocks]}
    """
    system_prompt: str | None = None
    out: list[dict[str, Any]] = []

    i = 0
    while i < len(messages):
        msg = messages[i]
        role = msg.get("role", "")

        if role == "system":
            system_prompt = str(msg.get("content", ""))
            i += 1
            continue

        if role == "user":
            out.append({"role": "user", "content": str(msg.get("content", ""))})
            i += 1
            continue

        if role == "assistant":
            tool_calls = msg.get("tool_calls")
            if tool_calls:
                # Translate to tool_use content blocks
                content_blocks = []
                text = msg.get("content", "")
                if text:
                    content_blocks.append({"type": "text", "text": text})
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    args_raw = fn.get("arguments", "{}")
                    if isinstance(args_raw, str):
                        try:
                            args = json.loads(args_raw) if args_raw.strip() else {}
                        except json.JSONDecodeError:
                            args = {}
                    else:
                        args = args_raw if isinstance(args_raw, dict) else {}
                    content_blocks.append({
                        "type": "tool_use",
                        "id": tc.get("id", ""),
                        "name": fn.get("name", ""),
                        "input": args,
                    })
                out.append({"role": "assistant", "content": content_blocks})
            else:
                out.append({
                    "role": "assistant",
                    "content": str(msg.get("content", "")),
                })
            i += 1
            # Collect any immediately following tool-result messages and group into one user turn
            tool_result_blocks = []
            while i < len(messages) and messages[i].get("role") == "tool":
                tm = messages[i]
                tool_result_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": tm.get("tool_call_id", ""),
                    "content": str(tm.get("content", "")),
                })
                i += 1
            if tool_result_blocks:
                out.append({"role": "user", "content": tool_result_blocks})
            continue

        # Skip unrecognized roles
        i += 1

    return system_prompt, out


def _normalize_anthropic_response(response_body: dict[str, Any]) -> str | dict[str, Any]:
    """Translate Anthropic's response to the internal OpenAI-compatible contract.

    Returns:
      str  — if the model produced a final text answer
      dict — with 'role', 'content', 'tool_calls' (OpenAI-style) if the model called tools
    """
    stop_reason = response_body.get("stop_reason", "")
    content_blocks = response_body.get("content", [])

    tool_use_blocks = [b for b in content_blocks if b.get("type") == "tool_use"]
    text_blocks = [b for b in content_blocks if b.get("type") == "text"]
    text_content = " ".join(b.get("text", "") for b in text_blocks).strip()

    if stop_reason == "tool_use" and tool_use_blocks:
        # Normalize to OpenAI tool_calls shape
        tool_calls = []
        for block in tool_use_blocks:
            tool_calls.append({
                "id": block.get("id", ""),
                "type": "function",
                "function": {
                    "name": block.get("name", ""),
                    # Arguments as JSON string to match OpenAI / agent loop expectation
                    "arguments": json.dumps(block.get("input", {})),
                },
            })
        return {
            "role": "assistant",
            "content": text_content,
            "tool_calls": tool_calls,
        }

    return text_content


class AnthropicProvider(LLMProvider):
    """LLM provider backed by Anthropic's Messages API."""

    def __init__(
        self,
        model: str = "claude-haiku-4-5",
        api_key: str = "",
        temperature: float = 0.3,
        max_tokens: int = 1024,
        timeout: float = 60.0,
    ):
        if not api_key:
            raise LLMProviderError(
                "Anthropic API key is required. Set 'api_key: ${ANTHROPIC_API_KEY}' in ai.yaml "
                "and export the ANTHROPIC_API_KEY environment variable."
            )
        self.model = model
        self._api_key = api_key          # stored privately, never logged
        self.temperature = float(temperature)
        self.max_tokens = int(max_tokens)
        self.timeout = float(timeout)

    def _auth_headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        stream: bool = False,
        timeout: float | None = None,
    ) -> str | dict[str, Any] | Iterator[str]:
        effective_timeout = timeout if timeout is not None else self.timeout

        system_prompt, anthropic_messages = _translate_messages_to_anthropic(messages)

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": anthropic_messages,
            "temperature": self.temperature,
        }
        if system_prompt:
            payload["system"] = system_prompt
        if tools:
            payload["tools"] = _openai_tools_to_anthropic(tools)

        if stream:
            # Anthropic streaming uses SSE — out of scope for current usage
            # (run_agent_loop always uses stream=False for tool-calling turns)
            raise LLMProviderError(
                "Streaming is not yet implemented for AnthropicProvider. "
                "Use stream=False."
            )

        try:
            resp = requests.post(
                _ANTHROPIC_API_URL,
                json=payload,
                headers=self._auth_headers(),
                timeout=effective_timeout,
            )
        except requests.exceptions.ConnectionError as e:
            raise LLMConnectionError(
                f"Cannot connect to Anthropic API at {_ANTHROPIC_API_URL}."
            ) from e
        except requests.exceptions.Timeout as e:
            raise LLMTimeoutError(
                f"Request to Anthropic timed out after {effective_timeout}s."
            ) from e
        except requests.exceptions.RequestException as e:
            raise LLMProviderError(
                f"HTTP request to Anthropic failed: {type(e).__name__}"
            ) from e

        if resp.status_code in (401, 403):
            raise LLMResponseError(
                "Authentication failed for Anthropic. "
                "Check that your API key is valid and correctly set."
            )
        if resp.status_code != 200:
            # Never echo response body — may contain auth-related detail
            raise LLMResponseError(
                f"Anthropic returned HTTP {resp.status_code}. "
                "Check the model name and account limits."
            )

        try:
            data = resp.json()
        except Exception as e:
            raise LLMResponseError("Malformed JSON response from Anthropic.") from e

        if not isinstance(data, dict):
            raise LLMResponseError(
                f"Unexpected top-level response type from Anthropic: {type(data).__name__}"
            )

        return _normalize_anthropic_response(data)
