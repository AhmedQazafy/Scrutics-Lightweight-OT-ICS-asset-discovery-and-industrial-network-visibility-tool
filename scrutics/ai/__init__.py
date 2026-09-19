"""Scrutics AI Intelligence subpackage."""

from typing import Any

from scrutics.ai.provider import (
    LLMProvider,
    LLMProviderError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMResponseError,
    ChatResult,
    ToolCall,
)
from scrutics.ai.config import load_ai_config, build_provider
from scrutics.ai.tools import (
    SessionContext,
    get_statistics,
    get_assets,
    get_asset,
    get_connections,
    get_anomalies,
    get_tool_definitions,
)
from scrutics.ai.agent import (
    TOOL_REGISTRY,
    OT_SYSTEM_PROMPT,
    run_agent_loop,
)

_LAZY_PROVIDERS = {
    "OllamaProvider": "scrutics.ai.ollama_provider",
    "OpenAIProvider": "scrutics.ai.openai_provider",
    "AnthropicProvider": "scrutics.ai.anthropic_provider",
    "GeminiProvider": "scrutics.ai.gemini_provider",
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_PROVIDERS:
        import importlib
        mod = importlib.import_module(_LAZY_PROVIDERS[name])
        return getattr(mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "LLMProvider",
    "LLMProviderError",
    "LLMConnectionError",
    "LLMTimeoutError",
    "LLMResponseError",
    "ChatResult",
    "ToolCall",
    "OllamaProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "GeminiProvider",
    "load_ai_config",
    "build_provider",
    "SessionContext",
    "get_statistics",
    "get_assets",
    "get_asset",
    "get_connections",
    "get_anomalies",
    "get_tool_definitions",
    "TOOL_REGISTRY",
    "OT_SYSTEM_PROMPT",
    "run_agent_loop",
]

