"""Shared mixin for providers using the OpenAI /v1/chat/completions wire format.

Both OllamaProvider (local, OpenAI-compatible endpoint) and OpenAIProvider (cloud)
speak the same request/response shape. This mixin holds the common HTTP +
parsing logic so neither class duplicates it.

IMPORTANT: This mixin never accesses self._api_key and never logs credentials.
"""

import json
from typing import Any, Iterator

import requests

from scrutics.ai.provider import (
    LLMConnectionError,
    LLMTimeoutError,
    LLMResponseError,
    LLMProviderError,
)


class OpenAICompatMixin:
    """
    Mixin that implements chat() for any provider using the OpenAI-compatible
    /v1/chat/completions wire format.

    Concrete provider must supply:
      self.model      - model name string
      self.timeout    - default float timeout
    """

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_openai_error(response: requests.Response) -> str:
        """Extract a safe, credential-free error description from a response."""
        try:
            body = response.json()
            if isinstance(body, dict):
                err = body.get("error")
                if isinstance(err, dict) and "message" in err:
                    return str(err["message"])
                if "error" in body:
                    return str(body["error"])
        except Exception:
            pass
        # Return status only — never echo raw body that might contain auth info
        return f"HTTP {response.status_code}"

    def _check_openai_status(
        self, response: requests.Response, provider_name: str = "provider"
    ) -> None:
        if response.status_code == 200:
            return
        err_msg = self._extract_openai_error(response)
        if response.status_code in (401, 403):
            raise LLMResponseError(
                f"Authentication failed for {provider_name}. "
                "Check that your API key is valid and correctly set."
            )
        raise LLMResponseError(
            f"{provider_name} returned HTTP {response.status_code}: {err_msg}"
        )

    # ── Core chat implementation ───────────────────────────────────────────────

    def _openai_chat(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        stream: bool,
        timeout: float,
        provider_name: str = "provider",
    ) -> str | dict[str, Any] | Iterator[str]:

        # ── Non-streaming ──────────────────────────────────────────────────────
        if not stream:
            try:
                resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
            except requests.exceptions.ConnectionError as e:
                raise LLMConnectionError(
                    f"Cannot connect to {provider_name} at {url}."
                ) from e
            except requests.exceptions.Timeout as e:
                raise LLMTimeoutError(
                    f"Request to {provider_name} timed out after {timeout}s."
                ) from e
            except requests.exceptions.RequestException as e:
                raise LLMProviderError(
                    f"HTTP request to {provider_name} failed: {type(e).__name__}"
                ) from e

            self._check_openai_status(resp, provider_name)

            try:
                data = resp.json()
            except Exception as e:
                raise LLMResponseError(
                    f"Malformed JSON from {provider_name}."
                ) from e

            if not isinstance(data, dict) or "choices" not in data or not data["choices"]:
                raise LLMResponseError(
                    f"Unexpected response structure from {provider_name}."
                )

            message = data["choices"][0].get("message")
            if not isinstance(message, dict):
                raise LLMResponseError(
                    f"Missing message in {provider_name} choice."
                )

            tool_calls = message.get("tool_calls")
            if tool_calls:
                return {
                    "role": "assistant",
                    "content": message.get("content") or "",
                    "tool_calls": tool_calls,
                }

            content = message.get("content")
            reasoning = message.get("reasoning") or message.get("reasoning_content")
            if not (content and str(content).strip()):
                if reasoning and str(reasoning).strip():
                    raise LLMResponseError(
                        f"{provider_name} returned only reasoning without a final answer. "
                        "Consider adjusting reasoning settings or increasing max_tokens."
                    )
                return content if content is not None else ""

            return content

        # ── Streaming ──────────────────────────────────────────────────────────
        try:
            resp = requests.post(
                url, json=payload, headers=headers, timeout=timeout, stream=True
            )
        except requests.exceptions.ConnectionError as e:
            raise LLMConnectionError(
                f"Cannot connect to {provider_name} at {url}."
            ) from e
        except requests.exceptions.Timeout as e:
            raise LLMTimeoutError(
                f"Request to {provider_name} timed out after {timeout}s."
            ) from e
        except requests.exceptions.RequestException as e:
            raise LLMProviderError(
                f"HTTP request to {provider_name} failed: {type(e).__name__}"
            ) from e

        try:
            self._check_openai_status(resp, provider_name)
        except Exception:
            resp.close()
            raise

        def _stream() -> Iterator[str]:
            try:
                for raw_line in resp.iter_lines(decode_unicode=True):
                    if not raw_line:
                        continue
                    line = raw_line.strip()
                    if not line.startswith("data:"):
                        continue
                    data_str = line[5:].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                    except Exception as e:
                        raise LLMResponseError(
                            f"Failed to parse streaming chunk from {provider_name}."
                        ) from e
                    choices = chunk.get("choices")
                    if not choices:
                        continue
                    delta = choices[0].get("delta", {})
                    token = delta.get("content")
                    if token:
                        yield token
            except requests.exceptions.Timeout as e:
                raise LLMTimeoutError(
                    f"{provider_name} streaming timed out."
                ) from e
            except requests.exceptions.ConnectionError as e:
                raise LLMConnectionError(
                    f"Connection lost while streaming from {provider_name}."
                ) from e
            except requests.exceptions.RequestException as e:
                raise LLMResponseError(
                    f"Streaming error from {provider_name}: {type(e).__name__}"
                ) from e
            finally:
                resp.close()

        return _stream()
