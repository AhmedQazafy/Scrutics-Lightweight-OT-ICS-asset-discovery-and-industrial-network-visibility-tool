"""LLM Provider abstraction and exception hierarchy for Scrutics."""

from abc import ABC, abstractmethod
from typing import Any, Iterator


class LLMProviderError(Exception):
    """Base exception for all LLM provider errors."""


class LLMConnectionError(LLMProviderError):
    """Raised when the provider cannot be reached (e.g. Ollama not running)."""


class LLMTimeoutError(LLMProviderError):
    """Raised when a request exceeds the configured timeout."""


class LLMResponseError(LLMProviderError):
    """Raised when the provider returns a malformed or error response."""


class LLMProvider(ABC):
    """
    Abstract interface for a chat-completion LLM provider.
    Concrete providers (Ollama, and later OpenAI/Anthropic) implement this.
    Callers depend only on this interface, never on a concrete provider class directly.
    """

    @abstractmethod
    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        stream: bool = False,
        timeout: float = 180.0,
    ) -> str | dict[str, Any] | Iterator[str]:
        """
        Send a chat completion request.

        messages: list of message dicts (e.g. role, content, tool_calls, tool_call_id, name).
        tools: optional list of tool definitions (OpenAI-style function-calling schema).
        stream: if True, returns an iterator of string chunks instead of one string.
        timeout: seconds before raising LLMTimeoutError.

        Returns:
            - str: Plain text response (when stream=False and no tools called).
            - dict[str, Any]: Message dict with 'role', 'content', and 'tool_calls' (when model invokes tools).
            - Iterator[str]: Stream of text tokens (when stream=True).

        Raises:
            LLMConnectionError: Provider unreachable.
            LLMTimeoutError: Request or stream timed out.
            LLMResponseError: Non-200 status, missing model, or malformed body.
        """

