"""Google Gemini generateContent provider for Scrutics Intelligence.

Uses the Gemini REST API at:
  POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key=...

Translates between Gemini's native shapes (contents[], functionDeclarations,
functionCall/functionResponse) and the internal OpenAI-compatible contract
expected by run_agent_loop():
  - Outgoing: converts messages + OpenAI-style tools → Gemini contents + functionDeclarations
  - Incoming: normalizes functionCall parts → {role, content, tool_calls}
  - Tool results: role=tool messages → functionResponse parts in a subsequent user turn
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

_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"


def _openai_tools_to_gemini(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert OpenAI-style tool definitions to Gemini functionDeclarations format.

    OpenAI:  {"type": "function", "function": {"name": ..., "description": ..., "parameters": {...}}}
    Gemini:  [{"functionDeclarations": [{"name": ..., "description": ..., "parameters": {...}}]}]
    """
    declarations = []
    for tool in tools:
        fn = tool.get("function", tool)
        declarations.append({
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "parameters": fn.get("parameters") or {"type": "object", "properties": {}},
        })
    return [{"functionDeclarations": declarations}]


def _translate_messages_to_gemini(
    messages: list[dict[str, Any]],
) -> tuple[str | None, list[dict[str, Any]]]:
    """Translate internal messages to Gemini contents format.

    Returns (system_instruction_str | None, gemini_contents_list).

    Gemini roles: "user" and "model" (assistant → model).
    Tool calls become functionCall parts; tool results become functionResponse parts.
    """
    system_instruction: str | None = None
    contents: list[dict[str, Any]] = []

    i = 0
    while i < len(messages):
        msg = messages[i]
        role = msg.get("role", "")

        if role == "system":
            system_instruction = str(msg.get("content", ""))
            i += 1
            continue

        if role == "user":
            contents.append({
                "role": "user",
                "parts": [{"text": str(msg.get("content", ""))}],
            })
            i += 1
            continue

        if role == "assistant":
            tool_calls = msg.get("tool_calls")
            if tool_calls:
                parts = []
                text = msg.get("content", "")
                if text:
                    parts.append({"text": text})
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
                    
                    fc_part = {
                        "functionCall": {
                            "id": tc.get("id", ""),
                            "name": fn.get("name", ""),
                            "args": args,
                        }
                    }
                    # Pass back thought_signature exactly as received (required for Gemini 3)
                    if "thought_signature" in tc:
                        fc_part["functionCall"]["thought_signature"] = tc["thought_signature"]
                    
                    parts.append(fc_part)
                contents.append({"role": "model", "parts": parts})
            else:
                contents.append({
                    "role": "model",
                    "parts": [{"text": str(msg.get("content", ""))}],
                })
            i += 1

            # Collect any immediately following tool-result messages as functionResponse parts
            fn_response_parts = []
            while i < len(messages) and messages[i].get("role") == "tool":
                tm = messages[i]
                result_str = str(tm.get("content", ""))
                # Wrap plain string in a response object
                try:
                    parsed = json.loads(result_str) if result_str.strip() else {}
                    # Gemini's FunctionResponse.response must be a Struct (JSON object),
                    # never a bare list. Wrap lists and scalars in {"output": ...}
                    if isinstance(parsed, dict):
                        result_obj = parsed
                    else:
                        result_obj = {"output": parsed}
                except Exception:
                    result_obj = {"output": result_str}
                fn_response_parts.append({
                    "functionResponse": {
                        "id": tm.get("tool_call_id", ""),
                        "name": tm.get("name", ""),
                        "response": result_obj,
                    }
                })
                i += 1
            if fn_response_parts:
                contents.append({"role": "user", "parts": fn_response_parts})
            continue

        # Skip unrecognized roles
        i += 1

    return system_instruction, contents


def _normalize_gemini_response(response_body: dict[str, Any]) -> str | dict[str, Any]:
    """Translate Gemini's generateContent response to the internal OpenAI-compatible contract.

    Returns:
      str  — if the model produced a final text answer
      dict — with 'role', 'content', 'tool_calls' (OpenAI-style) if the model called functions
             'tool_calls' entries include a 'thought_signature' field when present,
             which MUST be passed back on the next turn per Gemini 3 requirement.
    """
    candidates = response_body.get("candidates", [])
    if not candidates:
        raise LLMResponseError(
            "Gemini returned no candidates in response. "
            "Check model name and input validity."
        )

    content_obj = candidates[0].get("content", {})
    parts = content_obj.get("parts", [])

    fn_call_parts = [p for p in parts if "functionCall" in p]
    text_parts = [p for p in parts if "text" in p]
    text_content = " ".join(p["text"] for p in text_parts).strip()

    if fn_call_parts:
        tool_calls = []
        for p in fn_call_parts:
            fc = p["functionCall"]
            tool_call = {
                "id": fc.get("id", fc.get("name", "")),
                "type": "function",
                "function": {
                    "name": fc.get("name", ""),
                    # Normalize args dict → JSON string to match OpenAI / agent loop
                    "arguments": json.dumps(fc.get("args", {})),
                },
            }
            # Preserve thought_signature if present (required for Gemini 3 multi-turn)
            if "thought_signature" in fc:
                tool_call["thought_signature"] = fc["thought_signature"]
            tool_calls.append(tool_call)
        return {
            "role": "assistant",
            "content": text_content,
            "tool_calls": tool_calls,
        }

    return text_content


class GeminiProvider(LLMProvider):
    """LLM provider backed by Google's Gemini generateContent REST API."""

    def __init__(
        self,
        model: str = "gemini-2.0-flash",
        api_key: str = "",
        temperature: float = 0.3,
        max_tokens: int = 1024,
        timeout: float = 60.0,
    ):
        if not api_key:
            raise LLMProviderError(
                "Gemini API key is required. Set 'api_key: ${GEMINI_API_KEY}' in ai.yaml "
                "and export the GEMINI_API_KEY environment variable."
            )
        self.model = model
        self._api_key = api_key          # stored privately, never logged
        self.temperature = float(temperature)
        self.max_tokens = int(max_tokens)
        self.timeout = float(timeout)

    def _endpoint_url(self) -> str:
        # API key as query param — Gemini generateContent convention
        return f"{_GEMINI_BASE_URL}/{self.model}:generateContent?key={self._api_key}"

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        stream: bool = False,
        timeout: float | None = None,
    ) -> str | dict[str, Any] | Iterator[str]:
        if stream:
            raise LLMProviderError(
                "Streaming is not yet implemented for GeminiProvider. "
                "Use stream=False."
            )

        effective_timeout = timeout if timeout is not None else self.timeout
        system_instruction, contents = _translate_messages_to_gemini(messages)

        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_tokens,
            },
        }
        if system_instruction:
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }
        if tools:
            payload["tools"] = _openai_tools_to_gemini(tools)
            payload["toolConfig"] = {
                "functionCallingConfig": {"mode": "auto"}
            }

        try:
            resp = requests.post(
                self._endpoint_url(),
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=effective_timeout,
            )
            # Retry once on 503 (transient server overload)
            if resp.status_code == 503:
                import time as _time
                _time.sleep(3)
                resp = requests.post(
                    self._endpoint_url(),
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=effective_timeout,
                )
        except requests.exceptions.ConnectionError as e:
            raise LLMConnectionError(
                "Cannot connect to Google Gemini API."
            ) from e
        except requests.exceptions.Timeout as e:
            raise LLMTimeoutError(
                f"Request to Gemini timed out after {effective_timeout}s."
            ) from e
        except requests.exceptions.RequestException as e:
            raise LLMProviderError(
                f"HTTP request to Gemini failed: {type(e).__name__}"
            ) from e

        if resp.status_code == 503:
            raise LLMResponseError(
                "Gemini is temporarily overloaded (HTTP 503). Wait a moment and try again."
            )
        if resp.status_code in (401, 403):
            raise LLMResponseError(
                "Authentication failed for Gemini. "
                "Check that your API key is valid and correctly set."
            )
        if resp.status_code == 400:
            # 400 usually means malformed request — wrong conversation structure or unsupported model
            try:
                body = resp.json()
                detail = body.get("error", {}).get("message", "")
            except Exception:
                detail = ""
            hint = f" ({detail})" if detail else ""
            raise LLMResponseError(
                f"Gemini rejected the request (HTTP 400){hint}. "
                "This may be a conversation structure issue or unsupported model name."
            )
        if resp.status_code != 200:
            raise LLMResponseError(
                f"Gemini returned HTTP {resp.status_code}. "
                "Check model name, quota, and account limits."
            )

        try:
            data = resp.json()
        except Exception as e:
            raise LLMResponseError("Malformed JSON response from Gemini.") from e

        if not isinstance(data, dict):
            raise LLMResponseError(
                f"Unexpected top-level response type from Gemini: {type(data).__name__}"
            )

        return _normalize_gemini_response(data)
