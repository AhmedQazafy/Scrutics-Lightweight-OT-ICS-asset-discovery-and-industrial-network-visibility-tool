"""LLM Provider abstraction and exception hierarchy for Scrutics."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Iterator


class ChatResult(str):
    """Plain text response from an LLM provider, preserving optional thought signature.

    `truncated` is True when the provider stopped because the answer reached the output token
    limit, so the text is cut off; `limit` is the limit that was sent, or None when Scrutics sent
    none and the model's own limit applied.
    """

    def __new__(cls, content: str, thought_signature: str | None = None,
                truncated: bool = False, limit: int | None = None):
        obj = super().__new__(cls, content)
        obj.thought_signature = thought_signature
        obj.truncated = truncated
        obj.limit = limit
        return obj


def truncation_notice(answer: Any) -> str | None:
    """The line to show after an answer that stopped at the output limit, or None."""
    if not getattr(answer, "truncated", False):
        return None
    limit = getattr(answer, "limit", None)
    if limit:
        return (f"Answer cut off: the model reached its output limit (max_tokens {limit}). "
                "Ask for a shorter answer, or raise max_tokens in ~/.scrutics/ai.yaml.")
    return "Answer cut off: the model reached its output limit. Ask for a shorter answer."


@dataclass
class ToolCall:
    """Represents a normalized tool call invocation from an LLM provider."""

    id: str = ""
    name: str = ""
    arguments: str = ""
    thought_signature: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "type": "function",
            "function": {
                "name": self.name,
                "arguments": self.arguments,
            },
        }
        if self.thought_signature is not None:
            d["thought_signature"] = self.thought_signature
        return d


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

    # Called as (attempt, total, delay_seconds[, reason]) while a request is retried
    retry_callback: Any = None

    # Output token limit sent with each request, or None when the model's own limit applies
    output_limit: int | None = None

    def set_retry_callback(self, cb: Any) -> None:
        """Register or clear the retry status callback."""
        self.retry_callback = cb

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

