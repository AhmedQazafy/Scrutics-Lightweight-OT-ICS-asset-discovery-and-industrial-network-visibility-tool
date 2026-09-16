"""
Utilities for discovering available models from AI providers.
Used during onboarding to present the user with models their key can actually access.
All functions are best-effort: they return a fallback list on any error so
onboarding never stalls due to a failed model query.
"""

from __future__ import annotations

import re as _re
from typing import Any


# Hardcoded fallback lists used when the discovery endpoint is unavailable.
# Keep these updated with newest models as providers release them.
# The fetch_models() function queries the live API first and only uses
# these as a last resort when the API is unreachable.
_FALLBACK_MODELS: dict[str, list[str]] = {
    "gemini":    [
        "gemini-3.8-flash", "gemini-3.8-flash-lite",
        "gemini-2.0-flash", "gemini-2.0-flash-lite",
        "gemini-1.5-flash", "gemini-1.5-pro",
    ],
    "openai":    [
        "gpt-4o-mini", "gpt-4o", "gpt-4-turbo",
        "gpt-3.5-turbo", "o1-mini", "o1-preview",
    ],
    "anthropic": [
        "claude-haiku-4-5", "claude-sonnet-4", "claude-opus-4",
        "claude-3-5-sonnet-20241022", "claude-3-haiku-20240307",
    ],
    "ollama":    [],  # populated from local Ollama instance
}

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

# OpenAI chat model prefixes
_OPENAI_CHAT_PREFIXES = ("gpt-3", "gpt-4", "o1-", "o3-", "o4-")


def _is_chat_model(name: str, provider_id: str = "") -> bool:
    """Return True if a model name is a generative chat model worth showing to users."""
    lower = name.lower()

    if any(pat in lower for pat in _EXCLUDE_PATTERNS):
        return False

    if provider_id == "gemini":
        return bool(_GEMINI_CHAT_RE.match(name))

    if provider_id == "openai":
        return any(lower.startswith(p) for p in _OPENAI_CHAT_PREFIXES)

    # Ollama and Anthropic: accept anything not excluded
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
    model names, sorted newest-first by name.

    Returns empty list on failure so callers can decide whether to proceed
    with fallback or show an error to the user.
    
    Note: Users can always manually edit ~/.scrutics/ai.yaml to specify any
    model name, even if it doesn't appear in this list. This list is just
    for convenience during setup.
    """
    try:
        import requests
        models = _query_models(provider_id, api_key, base_url, requests, timeout)
        chat_models = [m for m in models if _is_chat_model(m, provider_id)]
        # Sort newest-first: reverse-alphabetical is a reasonable heuristic
        # (gemini-2.x sorts after gemini-1.x, gpt-4o sorts after gpt-3.5)
        chat_models.sort(reverse=True)
        return chat_models[:max_results]
    except Exception:
        # Return empty list - let caller decide how to handle
        return []


def _query_models(
    provider_id: str,
    api_key: str,
    base_url: str,
    requests_module: Any,
    timeout: float,
) -> list[str]:
    """
    Internal: call the provider's model list endpoint and return raw model name strings.
    Raises on any error — caller handles.
    """
    req = requests_module

    if provider_id == "gemini":
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
        resp = req.get(url, timeout=timeout)
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
        # Anthropic has no public model list endpoint; return hardcoded
        return _FALLBACK_MODELS["anthropic"]

    if provider_id == "ollama":
        effective_base = (base_url or "http://localhost:11434").rstrip("/")
        resp = req.get(f"{effective_base}/api/tags", timeout=timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"Ollama API returned {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        return [m["name"] for m in data.get("models", [])]

    return []
