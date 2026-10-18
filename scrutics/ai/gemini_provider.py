"""Google Gemini generateContent provider for Scrutics Intelligence.

Uses the Gemini REST API at:
  POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
with the API key in the x-goog-api-key header, never in the URL.

Translates between Gemini's native shapes (contents[], functionDeclarations,
functionCall/functionResponse) and the internal OpenAI-compatible contract
expected by run_agent_loop():
  - Outgoing: converts messages + OpenAI-style tools → Gemini contents + functionDeclarations
  - Incoming: normalizes functionCall parts → {role, content, tool_calls}
  - Tool results: role=tool messages → functionResponse parts in a subsequent user turn
"""

from __future__ import annotations

import json
import re
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
from scrutics.ai.model_rules import DEFAULT_MAX_TOKENS, gemini_options
from scrutics.ai.redact import describe_error, redact
from scrutics.ai.retry import send_with_retry

_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"


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
    # Proxies and gateways can answer with "error" as a string or null
    error = data.get("error")
    if not isinstance(error, dict):
        return None
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


def _format_gemini_error(resp: requests.Response, model: str, secrets: tuple[str, ...] = ()) -> str:
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
            # Google can reflect request details in the message; strip anything credential-shaped
            msg += f" Details: {redact(detail, secrets)}"
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


def _normalize_gemini_response(response_body: dict[str, Any], max_tokens: int | None = None) -> str | dict[str, Any]:
    """Translate Gemini's generateContent response to the internal OpenAI-compatible contract.

    Returns:
      ChatResult (str subclass): if the model produced a final text answer, marked truncated when
             finishReason is MAX_TOKENS (the answer reached maxOutputTokens)
      dict: with 'role', 'content', 'tool_calls' (OpenAI-style) if the model called functions
             'tool_calls' entries include 'thought_signature' when present per Gemini 3 requirement.
    Raises LLMResponseError when the limit was reached before any text or function call.
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
    truncated = candidates[0].get("finishReason") == "MAX_TOKENS"
    if truncated and not fn_call_parts and not text_content:
        # Thinking tokens count toward maxOutputTokens, so the limit can be spent before answering
        limit = f" (maxOutputTokens {max_tokens})" if max_tokens else ""
        raise LLMResponseError(
            f"Gemini stopped at the token limit{limit} before writing an answer; the model most "
            "likely used it on thinking. Raise max_tokens in ~/.scrutics/ai.yaml or ask a shorter question."
        )

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
    return ChatResult(text_content, thought_signature=sig, truncated=truncated, limit=max_tokens)


class GeminiProvider(LLMProvider):
    """LLM provider backed by Google's Gemini generateContent REST API."""

    def __init__(
        self,
        model: str = "gemini-3.8-flash",
        api_key: str = "",
        temperature: float = 0.3,
        max_tokens: int = DEFAULT_MAX_TOKENS["gemini"],
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
        self.output_limit = self.max_tokens
        self.timeout = float(timeout)
        self.retry_callback = retry_callback

    def set_retry_callback(self, cb: Callable[[int, int, float], None] | None) -> None:
        """Register or clear the retry status callback."""
        self.retry_callback = cb

    def _endpoint_url(self) -> str:
        return f"{_GEMINI_BASE_URL}/{self.model}:generateContent"

    def _auth_headers(self) -> dict[str, str]:
        return {"Content-Type": "application/json", "x-goog-api-key": self._api_key}

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
                **gemini_options(self.model),
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

        secrets = (self._api_key,)
        try:
            resp = send_with_retry(
                lambda: requests.post(
                    self._endpoint_url(),
                    json=payload,
                    headers=self._auth_headers(),
                    timeout=effective_timeout,
                ),
                "Gemini",
                on_retry=effective_cb,
                server_delay=_extract_retry_delay,
                detail=lambda r: _format_gemini_error(r, self.model, secrets),
                secrets=secrets,
            )
        except requests.exceptions.Timeout as e:
            raise LLMTimeoutError(
                f"Request to Gemini timed out after {effective_timeout}s "
                f"({describe_error(e, secrets)})."
            ) from None
        except requests.exceptions.ConnectionError as e:
            raise LLMConnectionError(f"Cannot connect to Google Gemini API ({describe_error(e, secrets)}).") from None
        except requests.exceptions.RequestException as e:
            raise LLMProviderError(f"HTTP request to Gemini failed: {describe_error(e, secrets)}") from None

        if resp.status_code != 200:
            raise LLMResponseError(_format_gemini_error(resp, self.model, secrets))

        try:
            data = resp.json()
        except Exception as e:
            raise LLMResponseError("Malformed JSON response from Gemini.") from e

        if not isinstance(data, dict):
            raise LLMResponseError(
                f"Unexpected top-level response type from Gemini: {type(data).__name__}"
            )

        return _normalize_gemini_response(data, self.max_tokens)
