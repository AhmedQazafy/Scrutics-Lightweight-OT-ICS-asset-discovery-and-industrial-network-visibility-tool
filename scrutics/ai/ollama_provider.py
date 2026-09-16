"""Ollama concrete LLM provider using OpenAI-compatible /v1/chat/completions."""

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


class OllamaProvider(LLMProvider):
    def __init__(
        self,
        model: str = "qwen3.5:4b",
        base_url: str = "http://localhost:11434",
        temperature: float = 0.3,
        reasoning_effort: str = "low",
        timeout: float = 180.0,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = float(temperature)
        self.reasoning_effort = str(reasoning_effort).strip().lower()
        self.timeout = float(timeout)

    def _extract_error_message(self, response: requests.Response) -> str:
        """Helper to extract a descriptive error message from an Ollama response."""
        try:
            body = response.json()
            if isinstance(body, dict):
                # Standard OpenAI error payload: {"error": {"message": "..."}}
                err = body.get("error")
                if isinstance(err, dict) and "message" in err:
                    return str(err["message"])
                # Ollama native error payload: {"error": "..."}
                if "error" in body:
                    return str(body["error"])
        except Exception:
            pass
        return response.text[:200] if response.text else f"HTTP {response.status_code}"

    def _check_http_status(self, response: requests.Response) -> None:
        """Validate response status and map model-not-found to helpful guidance."""
        if response.status_code == 200:
            return

        err_msg = self._extract_error_message(response)
        # Handle Ollama model-not-found heuristic (often 404 with message referencing model)
        if response.status_code == 404 and ("model" in err_msg.lower() and "not found" in err_msg.lower()):
            raise LLMResponseError(
                f"Model '{self.model}' not found on Ollama server. "
                f"Try running 'ollama pull {self.model}'. (HTTP {response.status_code}: {err_msg})"
            )

        # Graceful fallback: non-200 responses that don't match the model heuristic
        raise LLMResponseError(f"Ollama returned HTTP {response.status_code}: {err_msg}")

    def chat(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]] | None = None,
        stream: bool = False,
        timeout: float | None = None,
    ) -> str | Iterator[str]:
        effective_timeout = timeout if timeout is not None else self.timeout
        url = f"{self.base_url}/v1/chat/completions"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "reasoning_effort": self.reasoning_effort,
            "stream": stream,
        }
        if tools:
            payload["tools"] = tools

        # ── 1. Non-streaming path ─────────────────────────────────────────────
        if not stream:
            try:
                resp = requests.post(url, json=payload, timeout=effective_timeout)
            except requests.exceptions.ConnectionError as e:
                raise LLMConnectionError(
                    f"Cannot connect to Ollama at {self.base_url}. Ensure 'ollama serve' is running."
                ) from e
            except requests.exceptions.Timeout as e:
                raise LLMTimeoutError(f"Request to Ollama timed out after {effective_timeout}s.") from e
            except requests.exceptions.RequestException as e:
                raise LLMProviderError(f"HTTP request to Ollama failed: {e}") from e

            self._check_http_status(resp)

            try:
                data = resp.json()
            except Exception as e:
                raise LLMResponseError(
                    f"Malformed JSON response from Ollama: {resp.text[:200]}"
                ) from e

            if not isinstance(data, dict) or "choices" not in data or not data["choices"]:
                raise LLMResponseError(f"Unexpected response structure from Ollama: {data}")

            message = data["choices"][0].get("message")
            if not isinstance(message, dict):
                raise LLMResponseError(f"Missing message in Ollama choice: {data['choices'][0]}")

            # If the model emitted tool calls, return structured message dict
            tool_calls = message.get("tool_calls")
            if tool_calls:
                return {
                    "role": "assistant",
                    "content": message.get("content") or "",
                    "tool_calls": tool_calls,
                }

            content = message.get("content")
            if content and str(content).strip():
                return content

            # Defensive check: did the model return only reasoning without a final answer?
            reasoning = message.get("reasoning") or message.get("reasoning_content")
            if reasoning and str(reasoning).strip():
                raise LLMResponseError(
                    "Model returned reasoning content without a final answer. "
                    "Consider adjusting 'reasoning_effort' or increasing 'max_tokens'."
                )

            return content if content is not None else ""

        # ── 2. Streaming path ─────────────────────────────────────────────────
        try:
            resp = requests.post(url, json=payload, timeout=effective_timeout, stream=True)
        except requests.exceptions.ConnectionError as e:
            raise LLMConnectionError(
                f"Cannot connect to Ollama at {self.base_url}. Ensure 'ollama serve' is running."
            ) from e
        except requests.exceptions.Timeout as e:
            raise LLMTimeoutError(f"Request to Ollama timed out after {effective_timeout}s.") from e
        except requests.exceptions.RequestException as e:
            raise LLMProviderError(f"HTTP request to Ollama failed: {e}") from e

        # Validate HTTP status immediately before returning the generator
        try:
            self._check_http_status(resp)
        except Exception:
            resp.close()
            raise

        def _generate_stream() -> Iterator[str]:
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
                            f"Failed to parse streaming JSON chunk from Ollama: {data_str[:100]}"
                        ) from e

                    choices = chunk.get("choices")
                    if not choices or not isinstance(choices, list):
                        continue
                    delta = choices[0].get("delta", {})
                    content = delta.get("content")
                    if content:
                        yield content
            # NOTE: Only catch requests.exceptions below. LLMResponseError raised inside the loop
            # must propagate untouched — do NOT add a broad 'except Exception:' here.
            except requests.exceptions.Timeout as e:
                raise LLMTimeoutError(f"Ollama streaming timed out: {e}") from e
            except requests.exceptions.ConnectionError as e:
                raise LLMConnectionError(f"Connection lost while streaming from Ollama: {e}") from e
            except requests.exceptions.RequestException as e:
                raise LLMResponseError(f"Streaming error from Ollama: {e}") from e
            finally:
                resp.close()

        return _generate_stream()
