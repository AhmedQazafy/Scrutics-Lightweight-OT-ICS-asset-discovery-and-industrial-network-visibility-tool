"""OpenAI ChatCompletions provider for Scrutics Intelligence.

Uses the standard OpenAI /v1/chat/completions endpoint with Bearer token auth.
Request/response shape is identical to OllamaProvider's OpenAI-compatible endpoint,
so the parsing logic is shared via a common mixin.
"""

from typing import Any, Iterator

import requests

from scrutics.ai.provider import (
    LLMProvider,
    LLMConnectionError,
    LLMTimeoutError,
    LLMResponseError,
    LLMProviderError,
)
from scrutics.ai._openai_compat import OpenAICompatMixin


class OpenAIProvider(OpenAICompatMixin, LLMProvider):
    """LLM provider backed by OpenAI's Chat Completions API."""

    DEFAULT_BASE_URL = "https://api.openai.com"

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: str = "",
        base_url: str = DEFAULT_BASE_URL,
        temperature: float = 0.3,
        timeout: float = 60.0,
    ):
        if not api_key:
            raise LLMProviderError(
                "OpenAI API key is required. Set 'api_key: ${OPENAI_API_KEY}' in ai.yaml "
                "and export the OPENAI_API_KEY environment variable."
            )
        self.model = model
        self._api_key = api_key          # stored privately, never logged
        self.base_url = base_url.rstrip("/")
        self.temperature = float(temperature)
        self.timeout = float(timeout)

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        stream: bool = False,
        timeout: float | None = None,
    ) -> str | dict[str, Any] | Iterator[str]:
        effective_timeout = timeout if timeout is not None else self.timeout
        url = f"{self.base_url}/v1/chat/completions"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "stream": stream,
        }
        if tools:
            payload["tools"] = tools

        return self._openai_chat(
            url=url,
            payload=payload,
            headers=self._auth_headers(),
            stream=stream,
            timeout=effective_timeout,
            provider_name="OpenAI",
        )
