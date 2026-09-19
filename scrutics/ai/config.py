"""Configuration loading and provider factory for Scrutics AI."""

import os
import re
from typing import Any

import yaml

from scrutics.ai.provider import LLMProvider, LLMProviderError

_PKG_DIR = os.path.dirname(os.path.dirname(__file__))
_DEFAULT_PKG_AI_CONFIG = os.path.join(_PKG_DIR, "config", "ai.yaml")

# Pattern: ${VAR_NAME} — resolves to the environment variable VAR_NAME
_ENV_VAR_PATTERN = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def _resolve_env_var(value: str) -> str:
    """Resolve an environment-variable reference like ${MY_KEY} to its value.

    Returns the resolved string, or raises LLMProviderError if the referenced
    variable is not set. Never logs or includes the resolved value in error messages.
    If value is not an env-var reference, returns it unchanged.
    """
    match = _ENV_VAR_PATTERN.match(str(value).strip())
    if not match:
        return value
    var_name = match.group(1)
    resolved = os.environ.get(var_name)
    if not resolved:
        raise LLMProviderError(
            f"API key environment variable '{var_name}' is not set. "
            f"Export it before starting Scrutics: export {var_name}=<your-key>"
        )
    return resolved


def get_user_ai_config_paths() -> list[str]:
    """Return user-override AI config paths in search order."""
    return [
        os.path.join(os.path.expanduser("~"), ".scrutics", "ai.yaml"),
    ]


def load_ai_config() -> dict[str, Any]:
    """
    Load AI configuration following Scrutics dual-search convention:
      1. ~/.scrutics/ai.yaml (user home directory override)
      2. scrutics/config/ai.yaml (packaged default template)

    Returns empty dict if no config exists or if AI is disabled.
    Never raises for a missing file.
    Raises LLMProviderError for malformed YAML.
    """
    target_path = None
    for path in get_user_ai_config_paths():
        if os.path.exists(path):
            target_path = path
            break

    is_user_override = target_path is not None

    if target_path is None and os.path.exists(_DEFAULT_PKG_AI_CONFIG):
        target_path = _DEFAULT_PKG_AI_CONFIG

    if not target_path or not os.path.exists(target_path):
        return {}

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise LLMProviderError(f"Malformed YAML in {target_path}: {e}") from e
    except OSError as e:
        raise LLMProviderError(f"Cannot read AI config at {target_path}: {e}") from e

    if not isinstance(data, dict):
        raise LLMProviderError(f"Top-level YAML value in {target_path} must be a mapping")

    # If loading from packaged default, respect enabled: false flag
    if not is_user_override and not data.get("enabled", True):
        return {}

    return data


def build_provider(config: dict[str, Any] | None = None) -> LLMProvider:
    """
    Construct an LLMProvider instance from configuration.
    Defaults to OllamaProvider if config is empty or unspecified.

    Supported providers: 'ollama', 'openai', 'anthropic', 'gemini'.
    API keys are resolved from environment variable references (e.g. ${OPENAI_API_KEY}).
    """
    cfg = config if config is not None else load_ai_config()
    provider_name = str(cfg.get("provider", "ollama")).strip().lower()

    if provider_name == "ollama":
        from scrutics.ai.ollama_provider import OllamaProvider
        model = str(cfg.get("model", "qwen3.5:4b"))
        base_url = str(cfg.get("base_url", "http://localhost:11434"))
        temperature = float(cfg.get("temperature", 0.3))
        reasoning_effort = str(cfg.get("reasoning_effort", "low")).strip().lower()
        valid_efforts = {"high", "medium", "low", "none"}
        if reasoning_effort not in valid_efforts:
            raise LLMProviderError(
                f"Invalid reasoning_effort '{reasoning_effort}'. Must be one of: "
                f"{', '.join(sorted(valid_efforts))}."
            )
        timeout = float(cfg.get("timeout", 180.0))
        return OllamaProvider(
            model=model,
            base_url=base_url,
            temperature=temperature,
            reasoning_effort=reasoning_effort,
            timeout=timeout,
        )

    if provider_name == "openai":
        from scrutics.ai.openai_provider import OpenAIProvider
        api_key = _resolve_env_var(str(cfg.get("api_key", "")))
        return OpenAIProvider(
            model=str(cfg.get("model", "gpt-4o-mini")),
            api_key=api_key,
            base_url=str(cfg.get("base_url", OpenAIProvider.DEFAULT_BASE_URL)),
            temperature=float(cfg.get("temperature", 0.3)),
            timeout=float(cfg.get("timeout", 60.0)),
        )

    if provider_name == "anthropic":
        from scrutics.ai.anthropic_provider import AnthropicProvider
        api_key = _resolve_env_var(str(cfg.get("api_key", "")))
        return AnthropicProvider(
            model=str(cfg.get("model", "claude-haiku-4-5")),
            api_key=api_key,
            temperature=float(cfg.get("temperature", 0.3)),
            max_tokens=int(cfg.get("max_tokens", 1024)),
            timeout=float(cfg.get("timeout", 60.0)),
        )

    if provider_name == "gemini":
        from scrutics.ai.gemini_provider import GeminiProvider
        api_key = _resolve_env_var(str(cfg.get("api_key", "")))
        return GeminiProvider(
            model=str(cfg.get("model", "gemini-3.8-flash")),
            api_key=api_key,
            temperature=float(cfg.get("temperature", 0.3)),
            max_tokens=int(cfg.get("max_tokens", 1024)),
            timeout=float(cfg.get("timeout", 60.0)),
        )

    raise LLMProviderError(
        f"Unsupported LLM provider: '{provider_name}'. "
        "Supported providers: 'ollama', 'openai', 'anthropic', 'gemini'."
    )
