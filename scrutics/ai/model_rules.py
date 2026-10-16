"""Which models Scrutics offers per provider, and which optional request parameters each accepts.

A parameter is sent only where it is stated here; an unknown model gets no optional parameters.
Anthropic: temperature, top_p and top_k return HTTP 400 at non-default values on Claude 4.7 and
later models; Claude Haiku 5.5 accepts thinking {"type": "disabled"}. OpenAI: GPT-6 Luna and Sol
support function calling on Chat Completions only with reasoning_effort "none"; GPT-6 Astra and
GPT-6.1 Sol need the Responses API for tools, which Scrutics does not use.
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
