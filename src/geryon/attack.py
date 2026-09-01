"""Register within-policy attack cases into AgentDojo.

A case is a YAML file (see attacks/schema.json) whose ``template`` field is a
jailbreak string using AgentDojo's placeholders: {goal}, {user}, {model}, {task}.

Design constraint that defines this attack family: the payload must not ask the
agent to use a tool outside the user task's authorised set. It must drive the
injection goal using only already-authorised actions, so that a tool-identity
policy cannot block it. `geryon.overlap` tells you which pairs qualify;
enforcing the constraint inside a payload is the reviewer's job at case-authoring
time.

A fixed template is a *baseline*, not an adaptive attack. Reporting a fixed
template as an adaptive evaluation would repeat the methodological error this
project exists to correct. See docs/adaptive-loop.md.

Import this module before calling agentdojo so the attacks land in the registry.
"""

from __future__ import annotations

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.attacks.attack_registry import register_attack
from agentdojo.attacks.base_attacks import FixedJailbreakAttack
from agentdojo.task_suite.task_suite import TaskSuite

from geryon.cases import load_cases

DEFAULT_USER_NAME = "Emma Johnson"


def make_attack_class(case: dict) -> type[FixedJailbreakAttack]:
    """Build and register an AgentDojo attack class from a case definition."""

    class _Attack(FixedJailbreakAttack):
        name = case["id"].lower()

        def __init__(self, task_suite: TaskSuite, target_pipeline: BasePipelineElement) -> None:
            super().__init__(case["template"], task_suite, target_pipeline)
            self.user_name = case.get("user_name", DEFAULT_USER_NAME)

    _Attack.__doc__ = case.get("summary", "")
    _Attack.__name__ = "".join(w.capitalize() for w in case["id"].split("-")) + "Attack"
    register_attack(_Attack)
    return _Attack


def register_all() -> dict[str, type[FixedJailbreakAttack]]:
    """Register every case in the corpus. Idempotent per process."""
    return {case_id: make_attack_class(case) for case_id, case in load_cases().items()}


REGISTERED = register_all()
