"""Which models Scrutics offers per provider, and which optional request parameters each accepts.

A parameter is sent only where it is stated here; an unknown model gets no optional parameters.
Anthropic: temperature, top_p and top_k return HTTP 400 at non-default values on Claude 4.7 and
later models; Claude Haiku 5.5 accepts thinking {"type": "disabled"}. OpenAI: GPT-6 Luna and Sol
support function calling on Chat Completions only with reasoning_effort "none"; GPT-6 Astra and
GPT-6.1 Sol need the Responses API for tools, which Scrutics does not use. Gemini: a thinking level
only for the models listed below. Output token limits and the answer length told to the model are
also set here.
"""

from __future__ import annotations

from typing import Any

# Date the fallback lists and rules were last checked against the providers' documentation
FALLBACK_CHECKED = "2026-10-16"
FALLBACK_LABEL = (
    f"Fallback list (not from your account; checked against provider documentation on {FALLBACK_CHECKED})"
)

DEFAULT_ANTHROPIC_MODEL = "claude-haiku-5-5"
DEFAULT_OPENAI_MODEL = "gpt-6-luna"

# Models offered during setup, in the order they are offered. The first is the default.
_OFFERED = {
    "anthropic": ("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"),
    "openai": ("gpt-6-luna", "gpt-6-sol"),
}

# Models that accept temperature: Claude models before 4.7, and the deprecated GPT-4o / GPT-4.1
# models that existing configurations may still name.
_ACCEPTS_TEMPERATURE = {
    "anthropic": ("claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus-4-6",
                  "claude-opus-4-5", "claude-sonnet-4-5"),
    "openai": ("gpt-4o-mini", "gpt-4o", "gpt-4.1", "gpt-4.1-mini"),
}
_ANTHROPIC_THINKING_DISABLED = ("claude-haiku-5-5",)
_OPENAI_REASONING_NONE = ("gpt-6-luna", "gpt-6-sol")

# Gemini thinking level sent as generationConfig.thinkingConfig.thinkingLevel (generateContent API
# reference: MINIMAL, LOW, MEDIUM, HIGH, for Gemini 3 and later). Per-model levels from the
# thinking guide, checked 2026-10-18: gemini-3.8-flash accepts low, medium and high (default
# medium). Thinking tokens count toward maxOutputTokens, so a low level leaves the answer more room.
_GEMINI_THINKING_LEVEL = {"gemini-3.8-flash": "LOW"}

# Output token limit sent when the configuration sets none. Gemini counts thinking tokens toward
# maxOutputTokens. OpenAI and Ollama requests carry no limit, so the model's own limit applies.
DEFAULT_MAX_TOKENS = {"gemini": 8192, "anthropic": 4096}

# The max_tokens value every setup flow wrote before v0.7; a configuration holding exactly this
# value gets the provider's default instead
LEGACY_SETUP_MAX_TOKENS = 1024

# Answer length asked of the model: about 3 characters per token (addresses, tables and markdown
# tokenize worse than prose at about 4), on three quarters of the limit (the rest left for thinking
# and formatting)
_CHARS_PER_TOKEN = 3
_ANSWER_SHARE = 0.75


def _is(model: str, names: tuple[str, ...]) -> bool:
    """True if model is one of names or a dated snapshot of one (name followed by -YYYY...)."""
    model = (model or "").strip().lower()
    return any(model == name or model.startswith(name + "-20") for name in names)


def offered_models(provider: str) -> tuple[str, ...]:
    return _OFFERED.get(provider, ())


def fallback_models(provider: str) -> list[str]:
    """The fallback list for a provider whose model list could not be fetched."""
    return list(_OFFERED.get(provider, ()))


def anthropic_options(model: str, temperature: float | None) -> dict[str, Any]:
    """Optional Messages API fields for this model."""
    options: dict[str, Any] = {}
    if temperature is not None and _is(model, _ACCEPTS_TEMPERATURE["anthropic"]):
        options["temperature"] = temperature
    if _is(model, _ANTHROPIC_THINKING_DISABLED):
        options["thinking"] = {"type": "disabled"}
    return options


def openai_options(model: str, temperature: float | None) -> dict[str, Any]:
    """Optional Chat Completions fields for this model."""
    options: dict[str, Any] = {}
    if temperature is not None and _is(model, _ACCEPTS_TEMPERATURE["openai"]):
        options["temperature"] = temperature
    if _is(model, _OPENAI_REASONING_NONE):
        options["reasoning_effort"] = "none"
    return options


def gemini_options(model: str) -> dict[str, Any]:
    """Optional generationConfig fields for this Gemini model."""
    level = next((lvl for name, lvl in _GEMINI_THINKING_LEVEL.items() if _is(model, (name,))), None)
    return {"thinkingConfig": {"thinkingLevel": level}} if level else {}


def max_tokens_for(provider: str, configured: Any) -> int | None:
    """
    The output token limit to send: the configured value, except that a missing value or the old
    setup value 1024 gives the provider's default (None for providers that send no limit).
    """
    default = DEFAULT_MAX_TOKENS.get(provider)
    if configured is None or str(configured).strip() == "":
        return default
    value = int(configured)
    if value == LEGACY_SETUP_MAX_TOKENS and default is not None:
        return default
    return value


def answer_char_budget(limit: int | None) -> int | None:
    """Characters an answer should stay under for an output limit of `limit` tokens."""
    if not limit:
        return None
    return int(limit * _ANSWER_SHARE * _CHARS_PER_TOKEN) // 100 * 100


def answer_length_instruction(limit: int | None) -> str:
    """System prompt sentence telling the model its answer length, or "" when no limit is sent."""
    chars = answer_char_budget(limit)
    if not chars:
        return ""
    return (f"Your output is limited to {limit} tokens. Keep each answer under about {chars:,} "
            "characters; when there is more, summarise and offer to go into detail.")


def order_models(provider: str, ids: list[str], default: str | None = None) -> list[str]:
    """Model IDs from a provider's list, in the order Scrutics offers them.

    OpenAI: only the offered models, in table order. Anthropic: the offered models in table order,
    then any other listed model in the provider's own order. The default comes first when listed.
    """
    seen: list[str] = []
    for model_id in ids:
        if model_id not in seen:
            seen.append(model_id)
    table = [m for m in _OFFERED.get(provider, ()) if m in seen]
    rest = [] if provider == "openai" else [m for m in seen if m not in table]
    ordered = table + rest
    if default and default in ordered:
        ordered.remove(default)
        ordered.insert(0, default)
    return ordered


def default_index(models: list[str], default: str) -> int:
    """Position of the default in an offered list, or 0 when it is not there."""
    return models.index(default) if default in models else 0
