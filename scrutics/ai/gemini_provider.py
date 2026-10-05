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

from __future__ import annotations

import json
import random
import re
import time
from typing import Any, Callable, Iterator

import requests

from scrutics.ai.provider import (
    ChatResult,
    LLMProvider,
    LLMConnectionError,
    LLMTimeoutError,
    LLMResponseError,
    LLMProviderError,
)

_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
_RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
_MAX_RETRY_ATTEMPTS = 4
_MAX_BACKOFF_DELAY = 60.0


def _extract_retry_delay(resp: requests.Response | None) -> float | None:
    """Extract retry delay from Google RPC RetryInfo in error response, if present.

    Supports protobuf-duration strings ("39s", "1.5s") and struct representations
    ({"seconds": 1, "nanos": 500000000}). Returns seconds as float or None.
    """
    if resp is None:
        return None
    try:
        data = resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    error = data.get("error", {})
    details = error.get("details", [])
    if not isinstance(details, list):
        return None

    for item in details:
        if not isinstance(item, dict):
            continue
        item_type = item.get("@type", "")
        if "RetryInfo" in item_type or "retryInfo" in item_type:
            delay_val = item.get("retryDelay")
            if isinstance(delay_val, (int, float)):
                return float(delay_val)
            if isinstance(delay_val, str):
                m = re.match(r"^([0-9]+(?:\.[0-9]+)?)s$", delay_val.strip())
                if m:
                    return float(m.group(1))
            elif isinstance(delay_val, dict):
                sec = float(delay_val.get("seconds", 0))
                nanos = float(delay_val.get("nanos", 0))
                return sec + (nanos / 1e9)
    return None


def _format_gemini_error(resp: requests.Response, model: str) -> str:
    """Format a sanitized, actionable error message mapping HTTP and Google RPC status codes.

    Never exposes API keys, URLs with keys, prompts, IPs, MACs, or raw signatures.
    """
    rpc_status = ""
    detail = ""
    try:
        body = resp.json()
        if isinstance(body, dict):
            err = body.get("error", {})
            rpc_status = str(err.get("status", "")).strip()
            detail = str(err.get("message", "")).strip()
    except Exception:
        pass

    code = resp.status_code
    if rpc_status == "INVALID_ARGUMENT" or code == 400:
        msg = f"Gemini rejected the request (HTTP 400 / INVALID_ARGUMENT). Check model '{model}' compatibility or conversation structure."
        if detail:
            # Sanitize any potential query key leak from error message if Google reflected URL
            sanitized_detail = re.sub(r"key=[^&\s]+", "key=[REDACTED]", detail)
            msg += f" Details: {sanitized_detail}"
        return msg
    elif rpc_status == "UNAUTHENTICATED" or code == 401:
        return "Authentication failed for Gemini (HTTP 401 / UNAUTHENTICATED). Verify GEMINI_API_KEY is valid."
    elif rpc_status == "PERMISSION_DENIED" or code == 403:
        return "Permission denied for Gemini (HTTP 403 / PERMISSION_DENIED). Check API key permissions and enabled Google Cloud services."
    elif rpc_status == "NOT_FOUND" or code == 404:
        return f"Gemini model or resource not found (HTTP 404 / NOT_FOUND). Model '{model}' may be unsupported or shutdown."
    elif rpc_status == "RESOURCE_EXHAUSTED" or code == 429:
        return "Gemini quota or rate limit reached (HTTP 429 / RESOURCE_EXHAUSTED). Please wait before retrying."
    elif rpc_status == "UNAVAILABLE" or code == 503:
        return "Gemini service is temporarily unavailable (HTTP 503 / UNAVAILABLE). The server may be overloaded."
    elif rpc_status == "INTERNAL" or code == 500:
        return "Gemini encountered an internal server error (HTTP 500 / INTERNAL)."
    elif code in (502, 504):
        return f"Gateway error connecting to Gemini (HTTP {code})."
    elif code == 408:
        return "Request to Gemini timed out on the server (HTTP 408)."
    else:
        return f"Gemini request failed with HTTP {code}."


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
            content_val = msg.get("content", "")
            text_sig = msg.get("thought_signature") or getattr(content_val, "thought_signature", None)

            if tool_calls:
                parts = []
                if content_val:
                    text_part: dict[str, Any] = {"text": str(content_val)}
                    if text_sig:
                        text_part["thoughtSignature"] = text_sig
                    parts.append(text_part)

                for idx, tc in enumerate(tool_calls):
                    fn = tc.get("function", {})
                    args_raw = fn.get("arguments", "{}")
                    if isinstance(args_raw, str):
                        try:
                            args = json.loads(args_raw) if args_raw.strip() else {}
                        except json.JSONDecodeError:
                            args = {}
                    else:
                        args = args_raw if isinstance(args_raw, dict) else {}

                    fc_dict: dict[str, Any] = {
                        "name": fn.get("name", ""),
                        "args": args,
                    }
                    if tc.get("id"):
                        fc_dict["id"] = tc["id"]

                    fc_part: dict[str, Any] = {"functionCall": fc_dict}
                    # Gemini 3 protocol: only the first functionCall in a parallel batch carries thoughtSignature
                    fc_sig = tc.get("thought_signature") or (text_sig if idx == 0 else None)
                    if idx == 0 and fc_sig:
                        fc_part["thoughtSignature"] = fc_sig

                    parts.append(fc_part)
                contents.append({"role": "model", "parts": parts})
            else:
                text_part = {"text": str(content_val)}
                if text_sig:
                    text_part["thoughtSignature"] = text_sig
                contents.append({
                    "role": "model",
                    "parts": [text_part],
                })
            i += 1

            # Collect contiguous tool-result messages into a single user turn with functionResponse parts
            fn_response_parts = []
            while i < len(messages) and messages[i].get("role") == "tool":
                tm = messages[i]
                result_str = str(tm.get("content", ""))
                try:
                    parsed = json.loads(result_str) if result_str.strip() else {}
                    if isinstance(parsed, dict):
                        result_obj = parsed
                    else:
                        result_obj = {"output": parsed}
                except Exception:
                    result_obj = {"output": result_str}

                fr_dict: dict[str, Any] = {
                    "name": tm.get("name", ""),
                    "response": result_obj,
                }
                if tm.get("tool_call_id"):
                    fr_dict["id"] = tm["tool_call_id"]

                fn_response_parts.append({"functionResponse": fr_dict})
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
      ChatResult (str subclass): if the model produced a final text answer
      dict: with 'role', 'content', 'tool_calls' (OpenAI-style) if the model called functions
             'tool_calls' entries include 'thought_signature' when present per Gemini 3 requirement.
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
        for idx, p in enumerate(fn_call_parts):
            fc = p["functionCall"]
            call_id = fc.get("id", "")
            tool_call: dict[str, Any] = {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": fc.get("name", ""),
                    "arguments": json.dumps(fc.get("args", {})),
                },
            }
            # Capture thoughtSignature on part (canonical) or fallback inside fc
            sig = (
                p.get("thoughtSignature")
                or p.get("thought_signature")
                or fc.get("thought_signature")
                or fc.get("thoughtSignature")
            )
            # Per Gemini 3 contract: only the first functionCall in parallel batch carries the signature
            if idx == 0 and sig:
                tool_call["thought_signature"] = sig
            elif sig and len(fn_call_parts) == 1:
                tool_call["thought_signature"] = sig

            tool_calls.append(tool_call)
        first_sig = tool_calls[0].get("thought_signature") if tool_calls else None
        res_dict: dict[str, Any] = {
            "role": "assistant",
            "content": ChatResult(text_content, thought_signature=first_sig) if first_sig else text_content,
            "tool_calls": tool_calls,
        }
        if first_sig:
            res_dict["thought_signature"] = first_sig
        return res_dict

    # Text-only response: capture thoughtSignature from last part if present
    last_part = parts[-1] if parts else {}
    sig = last_part.get("thoughtSignature") or last_part.get("thought_signature")
    return ChatResult(text_content, thought_signature=sig)


class GeminiProvider(LLMProvider):
    """LLM provider backed by Google's Gemini generateContent REST API."""

    def __init__(
        self,
        model: str = "gemini-3.8-flash",
        api_key: str = "",
        temperature: float = 0.3,
        max_tokens: int = 1024,
        timeout: float = 60.0,
        retry_callback: Callable[[int, int, float], None] | None = None,
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
        self.retry_callback = retry_callback

    def set_retry_callback(self, cb: Callable[[int, int, float], None] | None) -> None:
        """Register or clear the retry status callback."""
        self.retry_callback = cb

    def _endpoint_url(self) -> str:
        # API key as query param (Gemini generateContent convention
        return f"{_GEMINI_BASE_URL}/{self.model}:generateContent?key={self._api_key}"

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        stream: bool = False,
        timeout: float | None = None,
        retry_callback: Callable[[int, int, float], None] | None = None,
        **kwargs: Any,
    ) -> str | dict[str, Any] | Iterator[str]:
        if stream:
            raise LLMProviderError(
                "Streaming is not yet implemented for GeminiProvider. "
                "Use stream=False."
            )

        effective_timeout = timeout if timeout is not None else self.timeout
        effective_cb = retry_callback if retry_callback is not None else self.retry_callback
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

        attempt = 0
        last_error: Exception | None = None

        while attempt < _MAX_RETRY_ATTEMPTS:
            attempt += 1
            if attempt > 1 and effective_cb:
                try:
                    effective_cb(attempt, _MAX_RETRY_ATTEMPTS, 0.0)
                except Exception:
                    pass

            resp: requests.Response | None = None
            try:
                resp = requests.post(
                    self._endpoint_url(),
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=effective_timeout,
                )
            except requests.exceptions.Timeout as e:
                last_error = LLMTimeoutError(
                    f"Request to Gemini timed out after {effective_timeout}s."
                )
                if attempt >= _MAX_RETRY_ATTEMPTS:
                    raise last_error from e
                delay = min(_MAX_BACKOFF_DELAY, (1.0 * (2 ** (attempt - 1))) + random.uniform(0.1, 0.4))
                if effective_cb:
                    try:
                        effective_cb(attempt + 1, _MAX_RETRY_ATTEMPTS, delay)
                    except Exception:
                        pass
                time.sleep(delay)
                continue
            except requests.exceptions.ConnectionError as e:
                last_error = LLMConnectionError(
                    "Cannot connect to Google Gemini API."
                )
                if attempt >= _MAX_RETRY_ATTEMPTS:
                    raise last_error from e
                delay = min(_MAX_BACKOFF_DELAY, (1.0 * (2 ** (attempt - 1))) + random.uniform(0.1, 0.4))
                if effective_cb:
                    try:
                        effective_cb(attempt + 1, _MAX_RETRY_ATTEMPTS, delay)
                    except Exception:
                        pass
                time.sleep(delay)
                continue
            except requests.exceptions.RequestException as e:
                raise LLMProviderError(
                    f"HTTP request to Gemini failed: {type(e).__name__}"
                ) from e

            # Immediate client failure: non-retryable
            if resp.status_code in (400, 401, 403, 404):
                error_msg = _format_gemini_error(resp, self.model)
                raise LLMResponseError(error_msg)

            # Retryable server or rate limit errors
            if resp.status_code in _RETRYABLE_STATUS_CODES:
                if attempt < _MAX_RETRY_ATTEMPTS:
                    server_delay = _extract_retry_delay(resp)
                    if server_delay is not None:
                        delay = min(_MAX_BACKOFF_DELAY, max(0.5, server_delay))
                    else:
                        delay = min(_MAX_BACKOFF_DELAY, (1.0 * (2 ** (attempt - 1))) + random.uniform(0.1, 0.5))
                    if effective_cb:
                        try:
                            effective_cb(attempt + 1, _MAX_RETRY_ATTEMPTS, delay)
                        except Exception:
                            pass
                    time.sleep(delay)
                    continue
                else:
                    error_msg = _format_gemini_error(resp, self.model)
                    raise LLMResponseError(error_msg)

            if resp.status_code != 200:
                error_msg = _format_gemini_error(resp, self.model)
                raise LLMResponseError(error_msg)

            try:
                data = resp.json()
            except Exception as e:
                raise LLMResponseError("Malformed JSON response from Gemini.") from e

            if not isinstance(data, dict):
                raise LLMResponseError(
                    f"Unexpected top-level response type from Gemini: {type(data).__name__}"
                )

            return _normalize_gemini_response(data)

        if last_error:
            raise last_error
        raise LLMResponseError("Gemini request failed after maximum retry attempts.")
