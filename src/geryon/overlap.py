"""Compute the within-policy pair set for an AgentDojo suite.

Two nested notions of "within policy" are computed, because they answer
different questions and a defence can pass one and fail the other.

Tool level
    A (user_task, injection_task) pair is within policy at the *tool* level when
    the set of tools required by the injection task's ground truth is a non-empty
    subset of the tools required by the user task's ground truth. A least
    privilege policy derived from the user's request authorises every tool the
    attack needs, so the defence cannot block it by tool identity and must
    discriminate on arguments, provenance, or data flow.

Argument level
    The same pair is within policy at the *argument* level when, in addition, the
    injection's ground truth introduces no argument value that does not already
    appear in the user task's ground truth. Such a pair could not be blocked even
    by a policy that pins every argument to the value the user's request implies.

The gap between the two tiers is the point. On AgentDojo v1.2.1 the tool-level
set is non-empty and the argument-level set is empty, which relocates the open
question: not "can the attacker stay inside the authorised action space" (at
argument granularity, in this benchmark, no) but "does the deployed policy
actually pin arguments, and can the attacker stop it from doing so".

Background: arXiv:2606.26479 section 14 poses "can an adaptive attack that lives
entirely within the agent's authorized action space still get through?". This
module makes that question measurable by naming the pairs it can be asked on.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field

from agentdojo.benchmark import get_suite

DEFAULT_VERSION = "v1.2.1"
DEFAULT_SUITES = ("banking", "slack", "travel", "workspace")

#: Pair counts observed on v1.2.1, asserted so that a silently dropped task or a
#: changed benchmark version fails loudly instead of shifting a published number.
EXPECTED_PAIRS_V121 = {"banking": 144, "slack": 105, "travel": 140, "workspace": 560}
EXPECTED_WITHIN_POLICY_V121 = {"banking": 42, "slack": 19, "travel": 6, "workspace": 18}


class GroundTruthError(RuntimeError):
    """A task's ground truth could not be computed."""


@dataclass(frozen=True)
class Pair:
    suite: str
    user_task: str
    injection_task: str
    user_tools: tuple[str, ...]
    injection_tools: tuple[str, ...]
    within_policy: bool
    #: argument values the injection needs that the user task never supplies
    novel_arg_values: tuple[str, ...] = ()
    #: within policy even against a policy that pins every argument value
    within_policy_arguments: bool = False


@dataclass
class SuiteReport:
    suite: str
    pairs: list[Pair] = field(default_factory=list)
    failed_tasks: list[str] = field(default_factory=list)

    @property
    def within_policy(self) -> int:
        return sum(p.within_policy for p in self.pairs)

    @property
    def within_policy_arguments(self) -> int:
        return sum(p.within_policy_arguments for p in self.pairs)


def flatten_values(value: object) -> list[str]:
    """Every scalar inside an argument, as a string, order-independent."""
    if isinstance(value, dict):
        out: list[str] = []
        for key in sorted(value):
            out += flatten_values(value[key])
        return out
    if isinstance(value, (list, tuple, set)):
        out = []
        for item in value:
            out += flatten_values(item)
        return out
    return [str(value)]


def ground_truth_calls(task, env, label: str, strict: bool):
    """Ground-truth calls for a task.

    Raises on failure under ``strict``. Never swallows an error silently: a
    dropped task changes the denominator of every number this module reports.
    """
    try:
        return list(task.ground_truth(env))
    except Exception as exc:  # noqa: BLE001 - re-raised or reported, never dropped
        if strict:
            raise GroundTruthError(f"{label}: {type(exc).__name__}: {exc}") from exc
        print(f"WARNING: ground truth unavailable for {label}: {exc}", file=sys.stderr)
        return None


def analyse_suite(suite_name: str, version: str = DEFAULT_VERSION, strict: bool = True) -> SuiteReport:
    suite = get_suite(version, suite_name)
    env = suite.load_and_inject_default_environment({})
    report = SuiteReport(suite=suite_name)

    injections: dict[str, tuple[set[str], set[str]]] = {}
    for iid, injection_task in suite.injection_tasks.items():
        calls = ground_truth_calls(injection_task, env, f"{suite_name}/{iid}", strict)
        if calls is None:
            report.failed_tasks.append(iid)
            continue
        tools = {c.function for c in calls}
        values: set[str] = set()
        for call in calls:
            values |= set(flatten_values(dict(call.args)))
        injections[iid] = (tools, values)

    for uid, user_task in suite.user_tasks.items():
        calls = ground_truth_calls(user_task, env, f"{suite_name}/{uid}", strict)
        if calls is None:
            report.failed_tasks.append(uid)
            continue
        user_tools = {c.function for c in calls}
        user_values: set[str] = set()
        for call in calls:
            user_values |= set(flatten_values(dict(call.args)))

        for iid, (injection_tools, injection_values) in injections.items():
            within = bool(injection_tools) and injection_tools <= user_tools
            novel = tuple(sorted(injection_values - user_values)) if within else ()
            report.pairs.append(
                Pair(
                    suite=suite_name,
                    user_task=uid,
                    injection_task=iid,
                    user_tools=tuple(sorted(user_tools)),
                    injection_tools=tuple(sorted(injection_tools)),
                    within_policy=within,
                    novel_arg_values=novel,
                    within_policy_arguments=within and not novel,
                )
            )
    return report


def check_expected(reports: list[SuiteReport], version: str) -> list[str]:
    """Regression guard on the numbers this project publishes."""
    if version != DEFAULT_VERSION:
        return []
    problems = []
    for report in reports:
        expected_total = EXPECTED_PAIRS_V121.get(report.suite)
        expected_within = EXPECTED_WITHIN_POLICY_V121.get(report.suite)
        if expected_total is not None and len(report.pairs) != expected_total:
            problems.append(f"{report.suite}: {len(report.pairs)} pairs, expected {expected_total}")
        if expected_within is not None and report.within_policy != expected_within:
            problems.append(
                f"{report.suite}: {report.within_policy} within-policy, expected {expected_within}"
            )
        if report.failed_tasks:
            problems.append(f"{report.suite}: ground truth failed for {sorted(set(report.failed_tasks))}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description="Within-policy pair analysis over AgentDojo.")
    ap.add_argument("--suites", nargs="*", default=list(DEFAULT_SUITES))
    ap.add_argument("--version", default=DEFAULT_VERSION)
    ap.add_argument("--json", help="write the full pair list here")
    ap.add_argument(
        "--no-strict",
        action="store_true",
        help="report unusable tasks instead of failing (the resulting counts are not publishable)",
    )
    args = ap.parse_args()

    reports = [analyse_suite(s, args.version, strict=not args.no_strict) for s in args.suites]
    all_pairs = [p for r in reports for p in r.pairs]

    print(f"{'suite':10s} {'pairs':>6s} {'tool-level':>12s} {'argument-level':>16s}")
    for report in reports:
        n = len(report.pairs)
        pct = 100 * report.within_policy / n if n else 0.0
        print(
            f"{report.suite:10s} {n:6d} "
            f"{report.within_policy:6d} ({pct:4.1f}%) {report.within_policy_arguments:10d}"
        )
    n = len(all_pairs)
    w = sum(p.within_policy for p in all_pairs)
    a = sum(p.within_policy_arguments for p in all_pairs)
    pct = 100 * w / n if n else 0.0
    print(f"{'TOTAL':10s} {n:6d} {w:6d} ({pct:4.1f}%) {a:10d}")

    problems = check_expected(reports, args.version)
    if problems:
        print("\nREGRESSION against published numbers:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([asdict(p) for p in all_pairs], fh, indent=2)
        print(f"wrote {args.json}")

    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
