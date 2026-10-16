"""
Utilities for discovering available models from AI providers.
Used during onboarding to present the user with models their key can actually access.
All functions are best-effort: they return a fallback list on any error so
onboarding never stalls due to a failed model query.
"""

from __future__ import annotations

import re as _re
from typing import Any

from scrutics.ai.model_rules import (
    DEFAULT_ANTHROPIC_MODEL,
    DEFAULT_OPENAI_MODEL,
    fallback_models,
    order_models,
)
from scrutics.ai.redact import describe_error

_ANTHROPIC_MODELS_URL = "https://api.anthropic.com/v1/models"
_ANTHROPIC_VERSION = "2023-06-01"
_ANTHROPIC_MAX_PAGES = 5

# Lists used when a provider's model list cannot be fetched. OpenAI and Anthropic offer only the
# models whose request rules are known (see model_rules); fetch_models_with_source labels them.
_FALLBACK_MODELS: dict[str, list[str]] = {
    "gemini":    [
        "gemini-3.8-flash", "gemini-3.8-flash-lite",
        "gemini-2.5-flash", "gemini-2.5-flash-lite",
    ],
    "openai":    fallback_models("openai"),
    "anthropic": fallback_models("anthropic"),
    "ollama":    [],  # populated from local Ollama instance
}

# Providers whose offered list and order come from model_rules
_DEFAULTS = {"openai": DEFAULT_OPENAI_MODEL, "anthropic": DEFAULT_ANTHROPIC_MODEL}

# Model name substrings that always indicate a non-chat utility model
_EXCLUDE_PATTERNS = {
    "embedding", "embed", "aqa", "vision", "nano",
    "retrieval", "classify", "score", "tts", "whisper", "dall-e",
    "text-moderation", "moderation", "curie", "babbage", "ada",
    "robotics", "lyria", "imagen", "veo",
}

# Gemini chat models follow the pattern gemini-<major>.<minor>-<variant>
# e.g. gemini-3.8-flash, gemini-2.0-flash, gemini-1.5-pro
# Reject anything that doesn't match: gemini-robotics, gemma-*, lyria-*, etc.
_GEMINI_CHAT_RE = _re.compile(r"^gemini-\d+\.\d+", _re.IGNORECASE)


def _is_chat_model(name: str, provider_id: str = "") -> bool:
    """Return True if a model name is a generative chat model worth showing to users."""
    lower = name.lower()

    if any(pat in lower for pat in _EXCLUDE_PATTERNS):
        return False

    if provider_id == "gemini":
        return bool(_GEMINI_CHAT_RE.match(name))

    # OpenAI is limited to the offered models afterwards; Ollama and Anthropic accept anything
    # not excluded
    return True


def fetch_models(
    provider_id: str,
    api_key: str = "",
    base_url: str = "",
    timeout: float = 8.0,
    max_results: int = 20,
) -> list[str]:
    """
    Query a provider's models endpoint and return up to max_results chat-capable
    model names. OpenAI and Anthropic come in the order Scrutics offers them, default
    first (model_rules.order_models); Gemini and Ollama are sorted by name, newest first.

    Returns empty list on failure so callers can decide whether to proceed
    with fallback or show an error to the user.
    
    Note: Users can always manually edit ~/.scrutics/ai.yaml to specify any
    model name, even if it doesn't appear in this list. This list is just
    for convenience during setup.
    """
    try:
        return _listed(provider_id, api_key, base_url, timeout)[:max_results]
    except Exception:
        # Return empty list - let caller decide how to handle
        return []


def fetch_models_with_source(
    provider_id: str,
    api_key: str = "",
    base_url: str = "",
    timeout: float = 8.0,
    max_results: int = 20,
) -> tuple[list[str], str, str]:
    """
    (models, source, reason): the provider's own list ("live"), or the fallback list
    ("fallback") with the reason the list could not be fetched. The reason never holds the key.
    """
    reason = ""
    if provider_id != "ollama" and not api_key:
        reason = "no API key"
    else:
        try:
            models = _listed(provider_id, api_key, base_url, timeout)[:max_results]
            if models:
                return models, "live", ""
            reason = "the provider listed no usable models"
        except Exception as e:
            reason = describe_error(e, (api_key,))
    return list(_FALLBACK_MODELS.get(provider_id, [])), "fallback", reason


def _listed(provider_id: str, api_key: str, base_url: str, timeout: float) -> list[str]:
    import requests
    models = _query_models(provider_id, api_key, base_url, requests, timeout)
    chat_models = [m for m in models if _is_chat_model(m, provider_id)]
    if provider_id in _DEFAULTS:
        return order_models(provider_id, chat_models, _DEFAULTS[provider_id])
    # Newest first by name (gemini-2.x sorts after gemini-1.x)
    chat_models.sort(reverse=True)
    return chat_models


def _query_models(
    provider_id: str,
    api_key: str,
    base_url: str,
    requests_module: Any,
    timeout: float,
) -> list[str]:
    """
    Internal: call the provider's model list endpoint and return raw model name strings.
    Raises on any error; the caller handles it.
    """
    req = requests_module

    if provider_id == "gemini":
        resp = req.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            headers={"x-goog-api-key": api_key},
            timeout=timeout,
        )
        if resp.status_code != 200:
            # Raise with detailed error for debugging
            raise RuntimeError(f"Gemini API returned {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        names = []
        for m in data.get("models", []):
            if "generateContent" in m.get("supportedGenerationMethods", []):
                names.append(m["name"].replace("models/", ""))
        return names

    if provider_id == "openai":
        effective_base = (base_url or "https://api.openai.com").rstrip("/")
        resp = req.get(
            f"{effective_base}/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"OpenAI API returned {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        return [m["id"] for m in data.get("data", [])]

    if provider_id == "anthropic":
        # Models API: newest first, paged by after_id; only models open to use are kept
        names: list[str] = []
        params: dict[str, Any] = {"limit": 1000}
        for _page in range(_ANTHROPIC_MAX_PAGES):
            resp = req.get(
                _ANTHROPIC_MODELS_URL,
                headers={"x-api-key": api_key, "anthropic-version": _ANTHROPIC_VERSION},
                params=params,
                timeout=timeout,
            )
            if resp.status_code != 200:
                raise RuntimeError(f"Anthropic API returned {resp.status_code}")
            data = resp.json()
            for m in data.get("data", []):
                if isinstance(m, dict) and m.get("id") and m.get("lifecycle", "active") == "active":
                    names.append(str(m["id"]))
            if not data.get("has_more") or not data.get("last_id"):
                break
            params = {"limit": 1000, "after_id": data["last_id"]}
        return names

    if provider_id == "ollama":
        effective_base = (base_url or "http://localhost:11434").rstrip("/")
        resp = req.get(f"{effective_base}/api/tags", timeout=timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"Ollama API returned {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        return [m["name"] for m in data.get("models", [])]

    return []
