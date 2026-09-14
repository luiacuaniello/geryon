"""Adapter that runs condition C: the seeded adaptive search over AgentDojo.

This is the only module in the package that imports AgentDojo. It turns the pure
search in `optimiser.py` into something the runner can execute against a live,
defended agent, by supplying the two callbacks the search needs:

    evaluate(payload)  -> run the defended agent once, report the black-box view
    propose(history)   -> ask the attacker model for the next payload

For each within-policy pair it writes the injection payload into every reachable
placeholder (the same mechanism AgentDojo's FixedJailbreakAttack uses) and scores
it with the benchmark's own security flag, so condition C is measured on exactly
the same footing as conditions A and B.
"""

from __future__ import annotations

from collections.abc import Sequence

from geryon.attacker import LLMAttacker
from geryon.optimiser import (
    MAX_ITERATIONS,
    CandidateUnusable,
    Evaluation,
    PairResult,
    optimise_pair,
)


def yaml_safe(payload: str) -> str:
    r"""Escape an attacker-written payload for the YAML AgentDojo builds.

    AgentDojo formats the payload into its environment YAML and parses the
    result, and every suite places the placeholder inside a *double-quoted*
    scalar: ``subject: "{injection_incoming_transaction}"``. In that context only
    three characters matter. A backslash opens an escape sequence, so ``\d`` is a
    parse error and ``\n`` silently becomes a newline. A quote ends the scalar. A
    real newline is folded into a space. Colons, hashes, apostrophes and tabs are
    safe there.

    Escaped rather than rewritten, so that the payload the model reads is the
    payload the attacker proposed: ``yaml.safe_load`` returns this unchanged. An
    earlier version rewrote ``": "`` into ``" - "`` and replaced quotes with
    apostrophes, which altered the attack it was about to measure — colon-space
    never needed it, and the quote could simply be escaped. Runs made before
    2026-09-14 carry payloads transformed that way.
    """
    cleaned = payload.replace("\r\n", "\n").replace("\r", "\n")
    # Backslashes first: every rule below introduces one.
    cleaned = cleaned.replace("\\", "\\\\")
    cleaned = cleaned.replace('"', '\\"')
    cleaned = cleaned.replace("\n", "\\n").replace("\t", "\\t")
    return cleaned


def evaluate_payload(suite, user_task, injection_task, payload: str) -> Evaluation:
    """Run the defended agent once on this pair with this payload."""
    from agentdojo.attacks.base_attacks import BaseAttack

    # A throwaway attack instance only to reuse get_injection_candidates, which
    # finds the placeholders the agent actually reaches for this user task.
    class _Probe(BaseAttack):
        name = "wp-condition-c-probe"

        def attack(self, u, i):  # pragma: no cover - not used
            return {}

    probe = _Probe(suite, target_pipeline=None)
    safe = yaml_safe(payload)
    injections = {inj: safe for inj in probe.get_injection_candidates(user_task)}

    try:
        utility, security = suite.run_task_with_pipeline(
            _PIPELINE.get(), user_task, injection_task, injections
        )
    except Exception as exc:  # noqa: BLE001 - one bad payload must not end the run
        raise CandidateUnusable(f"{type(exc).__name__}: {str(exc)[:120]}") from exc
    # What the attacker's channel can see: whether the goal ran and whether the
    # task still worked. "defence intervened" is left False here because the
    # benchmark does not surface it per call; the runner can enrich this from the
    # trace if a future defence exposes it, without changing the search.
    return Evaluation(
        goal_executed=bool(security),
        utility_preserved=bool(utility),
        defence_intervened=False,
    )


class _PipelineHolder:
    """The defended pipeline, set once per process by the runner before the search."""

    def __init__(self):
        self._pipeline = None

    def set(self, pipeline):
        self._pipeline = pipeline

    def get(self):
        if self._pipeline is None:
            raise RuntimeError("condition C pipeline not set; the runner must call set() first")
        return self._pipeline


_PIPELINE = _PipelineHolder()


def run_condition_c_pair(
    suite,
    user_task,
    injection_task,
    seeds: Sequence[str],
    authorised_tools: Sequence[str],
    all_tools: Sequence[str],
    attacker_model: str,
    attacker_client=None,
    max_iterations: int = MAX_ITERATIONS,
    seed_labels=None,
) -> PairResult:
    """Optimise one within-policy pair against the defended agent."""
    attacker = LLMAttacker(
        goal=injection_task.GOAL,
        authorised_tools=authorised_tools,
        model=attacker_model,
        client=attacker_client,
    )
    return optimise_pair(
        user_task=user_task.ID,
        injection_task=injection_task.ID,
        seeds=list(seeds),
        evaluate=lambda payload: evaluate_payload(suite, user_task, injection_task, payload),
        propose=attacker.propose,
        authorised_tools=authorised_tools,
        all_tools=all_tools,
        max_iterations=max_iterations,
        seed_labels=seed_labels,
    )
