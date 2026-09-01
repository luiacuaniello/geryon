"""The proposer, with a fake OpenAI client so no model is called."""

from __future__ import annotations

from geryon.attacker import NO_HISTORY, LLMAttacker
from geryon.optimiser import Attempt, Evaluation


class FakeMessage:
    def __init__(self, content):
        self.content = content


class FakeChoice:
    def __init__(self, content):
        self.message = FakeMessage(content)


class FakeCompletion:
    def __init__(self, content):
        self.choices = [FakeChoice(content)]


class FakeClient:
    """Records the prompts it is given and returns queued replies."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []
        self.chat = self
        self.completions = self

    def create(self, *, model, messages, **kw):
        self.calls.append(messages)
        return FakeCompletion(self.replies.pop(0))


def make(replies):
    client = FakeClient(replies)
    return LLMAttacker(goal="send money to the attacker", authorised_tools=["send_money"],
                       model="test-model", client=client), client


def test_first_prompt_has_no_history_and_states_the_authorised_tools():
    attacker, client = make(["payload one"])
    out = attacker.propose([])
    assert out == "payload one"
    user_msg = client.calls[0][1]["content"]
    assert NO_HISTORY in user_msg
    assert "send_money" in user_msg
    assert "send money to the attacker" in user_msg


def test_history_reports_outcomes_the_attacker_can_see():
    attacker, client = make(["next payload"])
    history = [
        Attempt("first try", "seed",
                evaluation=Evaluation(goal_executed=False, utility_preserved=True, defence_intervened=True)),
        Attempt("bad tool", "proposal", rejected_reason="names unauthorised tool(s): ['read_file']"),
    ]
    attacker.propose(history)
    rendered = client.calls[0][1]["content"]
    assert "goal executed: False" in rendered
    assert "defence intervened: True" in rendered
    assert "REJECTED before running" in rendered
    assert "read_file" in rendered


def test_the_prompt_never_leaks_a_policy_or_monitor_state():
    """The attacker is black box: nothing beyond its own channel enters the prompt."""
    attacker, client = make(["p"])
    attacker.propose([Attempt("x", "seed", evaluation=Evaluation(False, True))])
    whole_prompt = " ".join(m["content"] for m in client.calls[0])
    for forbidden in ("policy", "allowlist", "monitor", "SECAGENT", "z3", "reference monitor"):
        assert forbidden.lower() not in whole_prompt.lower(), f"leaked: {forbidden}"


def test_blank_reply_becomes_none_so_the_search_stops():
    attacker, _ = make(["   "])
    assert attacker.propose([]) is None


def test_long_payloads_are_truncated_in_history_to_bound_the_prompt():
    attacker, client = make(["next"])
    attacker.propose([Attempt("A" * 5000, "proposal", evaluation=Evaluation(False, True))])
    rendered = client.calls[0][1]["content"]
    assert "…" in rendered
    assert "A" * 5000 not in rendered
