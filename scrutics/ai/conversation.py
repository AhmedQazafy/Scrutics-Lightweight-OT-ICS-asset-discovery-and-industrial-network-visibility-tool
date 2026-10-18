"""
Earlier questions and answers sent with each new question to the assistant.

The agent loop builds its message list from scratch for every question, so the CLI and the TUI
pass the earlier exchanges as text in front of the new question. What is sent is capped: at most
MAX_EXCHANGES exchanges and MAX_HISTORY_CHARS characters of question and answer text (the fixed
wrapper is not counted). The newest exchange is always sent; if it alone is over the character cap,
its question is kept and its answer keeps its start and end around an omission marker. Older
exchanges are dropped whole, oldest first, once they no longer fit.
"""

from __future__ import annotations

MAX_EXCHANGES = 5
MAX_HISTORY_CHARS = 8000
ANSWER_OMISSION_MARKER = "[middle of this answer omitted]"
QUESTION_OMISSION_MARKER = "[middle of this question omitted]"

# Share of a cut text kept from its start; follow-ups usually refer to the start of an answer
# (a list or summary), so it gets the larger part.
_HEAD_SHARE = 2 / 3


def _cut_middle(text: str, limit: int, marker: str) -> str:
    """text unchanged if it fits in limit characters, else its start and end around the marker."""
    if len(text) <= limit:
        return text
    room = limit - len(marker) - 2
    if room <= 0:
        return text[:limit]
    head = int(room * _HEAD_SHARE)
    tail = room - head
    return f"{text[:head]}\n{marker}\n{text[len(text) - tail:] if tail else ''}"


def exchanges_to_send(history: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """The exchanges to send with the next question, oldest first, within the caps."""
    if not history:
        return []
    question, answer = history[-1]
    question = _cut_middle(str(question), MAX_HISTORY_CHARS // 2, QUESTION_OMISSION_MARKER)
    answer = _cut_middle(str(answer), MAX_HISTORY_CHARS - len(question), ANSWER_OMISSION_MARKER)
    kept = [(question, answer)]
    used = len(question) + len(answer)
    for question, answer in reversed(history[-MAX_EXCHANGES:-1]):
        size = len(question) + len(answer)
        if used + size > MAX_HISTORY_CHARS:
            break
        kept.append((str(question), str(answer)))
        used += size
    kept.reverse()
    return kept


def question_with_history(history: list[tuple[str, str]], question: str) -> str:
    """The message for the agent: the capped earlier exchanges, then the new question."""
    exchanges = exchanges_to_send(history)
    if not exchanges:
        return question
    prior = "\n".join(f"User: {q}\nAssistant: {a}" for q, a in exchanges)
    return f"[Previous conversation]\n{prior}\n\n[New question]\n{question}"


def remember_exchange(history: list[tuple[str, str]], question: str, answer: str) -> None:
    """Append an exchange, keeping only the MAX_EXCHANGES most recent (no older one is ever sent)."""
    history.append((question, str(answer)))
    del history[:-MAX_EXCHANGES]
