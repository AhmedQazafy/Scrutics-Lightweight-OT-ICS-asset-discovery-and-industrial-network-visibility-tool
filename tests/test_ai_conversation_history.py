"""Earlier exchanges sent with each question: at most 5 exchanges and 8,000 characters of question
and answer text, the newest always sent (cut in the middle when it alone is over the cap), older
ones dropped whole, oldest first. The CLI and the TUI send the same capped history."""

from unittest.mock import patch

from scrutics import cli

try:
    from scrutics.ai.conversation import (
        ANSWER_OMISSION_MARKER,
        MAX_EXCHANGES,
        MAX_HISTORY_CHARS,
        exchanges_to_send,
        question_with_history,
        remember_exchange,
    )
except ImportError:  # lets the CLI tests run against a tree without the module
    ANSWER_OMISSION_MARKER, MAX_EXCHANGES, MAX_HISTORY_CHARS = "[middle of this answer omitted]", 5, 8000
    exchanges_to_send = question_with_history = remember_exchange = None


def _chars(exchanges):
    return sum(len(q) + len(a) for q, a in exchanges)


def _sent_by_cli(history, question):
    """The message the CLI hands to the agent loop for question with history before it."""
    with patch("scrutics.ai.agent.run_agent_loop", return_value="ok") as loop:
        cli._ask_one(provider=None, ctx=None, question=question, conversation_history=history)
    return loop.call_args.kwargs["user_message"]


def _long_list_answer():
    first = "1. 10.0.0.5 Siemens S7-1200, serves S7comm on 102"
    middle = "\n".join(f"{n}. 10.0.1.{n} generic device with a long description line" for n in range(2, 400))
    return first, f"{first}\n{middle}\nEnd of the device list."


# ── the caps ─────────────────────────────────────────────────────────────────

def test_the_caps_are_five_exchanges_and_8000_characters():
    assert (MAX_EXCHANGES, MAX_HISTORY_CHARS) == (5, 8000)


def test_at_most_five_exchanges_are_sent_newest_kept():
    history = [(f"question {n}", f"answer {n}") for n in range(1, 8)]
    sent = exchanges_to_send(history)
    assert sent == history[-5:]


def test_older_exchanges_are_dropped_whole_oldest_first_to_fit_8000_characters():
    history = [("q1", "a" * 3000), ("q2", "b" * 3000), ("q3", "c" * 3000)]
    sent = exchanges_to_send(history)
    assert sent == history[1:]  # 9,006 characters with q1; the oldest goes whole
    assert _chars(sent) <= MAX_HISTORY_CHARS


def test_once_an_older_exchange_does_not_fit_no_older_one_is_sent():
    history = [("q1", "small"), ("q2", "b" * 5000), ("q3", "c" * 3000)]
    assert exchanges_to_send(history) == [("q3", "c" * 3000)]


def test_the_fixed_wrapper_is_not_counted():
    # 8,000 characters of question and answer text exactly; the labels around them do not count
    history = [("q" * 1000, "a" * 3000), ("r" * 1000, "b" * 3000)]
    assert exchanges_to_send(history) == history
    assert len(question_with_history(history, "next")) > MAX_HISTORY_CHARS


# ── the newest exchange over the cap on its own ──────────────────────────────

def test_an_over_cap_newest_exchange_keeps_its_start_and_end_with_a_marker():
    first, answer = _long_list_answer()
    question = "List the devices"
    assert len(question) + len(answer) > MAX_HISTORY_CHARS
    sent = exchanges_to_send([("old question", "old answer"), (question, answer)])
    assert len(sent) == 1
    sent_question, sent_answer = sent[0]
    assert sent_question == question
    assert sent_answer.startswith(first)
    assert sent_answer.endswith("End of the device list.")
    assert ANSWER_OMISSION_MARKER in sent_answer
    assert ANSWER_OMISSION_MARKER == "[middle of this answer omitted]"
    assert len(sent_question) + len(sent_answer) <= MAX_HISTORY_CHARS
    # the start, which follow-ups usually refer to, keeps the larger part
    assert sent_answer.index(ANSWER_OMISSION_MARKER) > len(sent_answer) // 2


def test_a_follow_up_still_has_the_first_list_item_in_context():
    first, answer = _long_list_answer()
    message = question_with_history([("List the devices", answer)], "What does the first one serve?")
    assert first in message
    assert message.endswith("[New question]\nWhat does the first one serve?")


def test_an_over_cap_question_keeps_its_start_and_end_and_leaves_room_for_the_answer():
    question = "Q" * 10000
    sent_question, sent_answer = exchanges_to_send([(question, "short answer")])[0]
    assert sent_question.startswith("Q") and sent_question.endswith("Q")
    assert sent_answer == "short answer"
    assert len(sent_question) + len(sent_answer) <= MAX_HISTORY_CHARS


def test_a_newest_exchange_under_the_cap_is_sent_unchanged():
    history = [("q", "a" * 7000)]
    assert exchanges_to_send(history) == history


def test_stored_history_keeps_only_the_exchanges_that_can_be_sent():
    history = []
    for n in range(8):
        remember_exchange(history, f"q{n}", f"a{n}")
    assert history == [(f"q{n}", f"a{n}") for n in range(3, 8)]


# ── the CLI sends the capped history ─────────────────────────────────────────

def test_the_cli_sends_at_most_five_earlier_exchanges():
    history = [(f"question {n}", f"answer {n}") for n in range(1, 8)]
    message = _sent_by_cli(history, "next")
    assert "question 2\n" not in message and "answer 2\n" not in message
    for n in range(3, 8):
        assert f"User: question {n}\nAssistant: answer {n}" in message


def test_the_cli_sends_an_over_cap_answer_with_its_start_end_and_marker():
    first, answer = _long_list_answer()
    message = _sent_by_cli([("List the devices", answer)], "What does the first one serve?")
    assert first in message
    assert "End of the device list." in message
    assert ANSWER_OMISSION_MARKER in message
    assert len(message) < len(answer)


def test_the_cli_sends_no_history_block_for_a_first_question():
    assert _sent_by_cli([], "first question") == "first question"
