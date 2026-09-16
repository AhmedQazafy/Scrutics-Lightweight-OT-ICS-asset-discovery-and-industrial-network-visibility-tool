"""Scrutics AI Intelligence subpackage."""

from scrutics.ai.provider import (
    LLMProvider,
    LLMProviderError,
    LLMConnectionError,
    LLMTimeoutError,
    LLMResponseError,
)
from scrutics.ai.ollama_provider import OllamaProvider
from scrutics.ai.openai_provider import OpenAIProvider
from scrutics.ai.anthropic_provider import AnthropicProvider
from scrutics.ai.gemini_provider import GeminiProvider
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

__all__ = [
    "LLMProvider",
    "LLMProviderError",
    "LLMConnectionError",
    "LLMTimeoutError",
    "LLMResponseError",
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

