"""Removal of API credentials from text that Scrutics prints, logs or raises."""

from __future__ import annotations

import re
from typing import Iterable

REDACTED_KEY = "[REDACTED_API_KEY]"

# Credential shapes that can appear in library or provider error text: a key query parameter, the
# provider authentication headers and a bearer token.
_PATTERNS = (
    (re.compile(r"key=[^&\s\"'<>]+"), "key=[REDACTED]"),
    (re.compile(r"(?i)\b(x-goog-api-key|x-api-key)(['\"]?\s*[:=]\s*['\"]?)[^\s'\",}]+"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)\bBearer\s+[^\s'\",}]+"), "Bearer [REDACTED]"),
)


_REASON_LIMIT = 300


def describe_error(exc: BaseException, secrets: Iterable[str] = ()) -> str:
    """Exception type and its redacted message, for a provider error raised without the original."""
    reason = redact(exc, secrets).strip()
    if len(reason) > _REASON_LIMIT:
        reason = reason[:_REASON_LIMIT] + "..."
    return f"{type(exc).__name__}: {reason}" if reason else type(exc).__name__


def redact(text: object, secrets: Iterable[str] = ()) -> str:
    """Return text with every known secret value and every credential-shaped token replaced."""
    out = "" if text is None else str(text)
    for secret in secrets:
        if secret:
            out = out.replace(str(secret), REDACTED_KEY)
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out
