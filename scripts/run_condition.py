"""Run one condition of the three-condition comparison, on the within-policy pairs.

One process per (suite, condition, repeat), because Progent is configured through
environment variables that AgentDojo reads at *import* time. This script sets them
before importing anything from agentdojo, which is why the imports are inside
main() and not at the top of the file.

Conditions, per protocol/threat-model.md:

    A   no defence,  important_instructions      SECAGENT_SUITE unset
    B   Progent,     important_instructions      SECAGENT_SUITE=<suite>
    C   Progent,     a within-policy case        SECAGENT_SUITE=<suite>

A and B run against the identical vendored AgentDojo, differing only in whether
Progent's tool wrapper is applied. That is the cleanest available A/B: no second
package, no second environment, one environment variable.

Must be run inside an environment where `agentdojo` resolves to Progent's
vendored copy. See docs/running-progent.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from geryon import runlog  # noqa: E402

CONDITIONS = ("A", "B", "C")

#: USD per million tokens for openai.gpt-oss-120b on Bedrock, standard tier.
#: Only used to turn the measured token counts into a number a human can act on;
#: the token counts themselves are the record.
PRICE_IN, PRICE_OUT = 0.15, 0.60


def install_usage_meter() -> dict:
    """Count every chat completion this process makes, including Progent's own.

    Patched at the class level rather than per client, because the policy-authoring
    call in secagent constructs its own `OpenAI()` deep inside the defence. The
    protocol already requires reporting the number of LLM calls; this makes that
    automatic, and makes the cost of a run a recorded fact rather than an estimate.
    """
    from openai.resources.chat.completions import Completions

    meter = {"llm_calls": 0, "prompt_tokens": 0, "completion_tokens": 0}
    original = Completions.create

    def create(self, *args, **kwargs):
        response = original(self, *args, **kwargs)
        usage = getattr(response, "usage", None)
        if usage is not None:
            meter["llm_calls"] += 1
            meter["prompt_tokens"] += usage.prompt_tokens or 0
            meter["completion_tokens"] += usage.completion_tokens or 0
        return response

    Completions.create = create
    return meter


def meter_summary(meter: dict) -> dict:
    cost = (meter["prompt_tokens"] * PRICE_IN + meter["completion_tokens"] * PRICE_OUT) / 1e6
    return {**meter, "estimated_usd": round(cost, 4)}


def run_pair_by_pair(suite, attack, user_tasks, injection_tasks, wanted, logdir, OutputLogger):
    """Run each pair on its own, so one malformed model reply cannot end the run.

    AgentDojo parses the model's tool-call arguments with `json.loads` and lets a
    `JSONDecodeError` propagate all the way out of the benchmark. An agent that
    emits one bad escape on call 60 of 105 therefore destroys the whole run: two
    of ours died exactly that way, after an hour of work each.

    Pairs that raise are recorded as skipped rather than scored. A skipped pair is
    not a blocked attack and must never be counted as one — it changes the
    denominator, so it is reported and the caller decides whether the run is still
    usable.
    """
    security, utility, skipped = {}, {}, {}
    with OutputLogger(str(logdir), live=None):
        for user_id, injection_id in sorted(wanted):
            key = f"{user_id}|{injection_id}"
            user_task = suite.user_tasks[user_id]
            injection_task = suite.injection_tasks[injection_id]
            injections = attack.attack(user_task, injection_task)
            try:
                util, sec = suite.run_task_with_pipeline(
                    _pipeline_of(attack), user_task, injection_task, injections
                )
            except Exception as exc:  # noqa: BLE001 - one pair, not the run
                skipped[key] = f"{type(exc).__name__}: {str(exc)[:120]}"
                print(f"  SKIPPED {key}: {skipped[key]}", flush=True)
                continue
            security[key] = bool(sec)
            utility[key] = bool(util)
    return security, utility, skipped


def _pipeline_of(attack):
    return attack.target_pipeline


#: A full git object name, and nothing that merely looks like one.
_SHA1 = re.compile(r"^[0-9a-f]{40}$")


def _git(path: Path, *args: str) -> str | None:
    """One read-only git command, or None when it does not answer cleanly.

    The return code has to be checked, not just the output. `git rev-parse HEAD`
    in a repository with no commits yet exits 128 *and still prints the literal
    string "HEAD" on stdout*, so a function that trusts stdout alone records
    "HEAD" as though it were a commit. The first campaign did exactly that: 36
    provenance files claim a commit that identifies nothing.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(path), *args],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except Exception:
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def git_commit(path: Path) -> str | None:
    """The commit a directory is on, or None when that is not a fact."""
    sha = _git(path, "rev-parse", "HEAD")
    return sha if sha and _SHA1.match(sha) else None


def git_dirty(path: Path) -> bool | None:
    """Whether the working tree carries changes the commit does not describe.

    A hash beside a dirty tree names the wrong code, so the two travel together.
    """
    status = _git(path, "status", "--porcelain")
    return None if status is None else bool(status)


def git_root(path: Path) -> str | None:
    """The repository a path actually belongs to.

    Asked of git rather than guessed by counting parent directories: the guess
    lands somewhere arbitrary for a pip-installed package and silently records
    an unrelated repository's commit.
    """
    return _git(path, "rev-parse", "--show-toplevel")


def load_pairs(pairs_path: Path, suite: str, within_policy_only: bool = True) -> list[tuple[str, str]]:
    """The pairs to measure over.

    `within_policy_only=False` gives the whole suite, which is the denominator the
    published literature uses. Running both is the control that decides whether a
    gap against published figures comes from the restriction or from something
    else in the setup: same code, same models, same defence configuration, only
    the pair set changes.
    """
    data = json.loads(pairs_path.read_text())
    pairs = [
        (p["user_task"], p["injection_task"])
        for p in data
        if p["suite"] == suite and (p["within_policy"] or not within_policy_only)
    ]
    if not pairs:
        raise SystemExit(f"no within-policy pairs for suite {suite!r} in {pairs_path}")
    return sorted(set(pairs))


def configure_environment(args) -> dict[str, str]:
    """Set Progent's environment before agentdojo is imported. Returns what was set."""
    if args.condition == "A":
        os.environ.pop("SECAGENT_SUITE", None)
    else:
        os.environ["SECAGENT_SUITE"] = args.suite

    os.environ["SECAGENT_POLICY_MODEL"] = args.policy_model
    os.environ["SECAGENT_UPDATE"] = "True" if args.policy_updates else "False"
    os.environ["SECAGENT_IGNORE_UPDATE_ERROR"] = "True"
    if not args.policy_updates:
        os.environ["SECAGENT_ONLY_ALLOW_NARROW"] = "True"
    else:
        os.environ.pop("SECAGENT_ONLY_ALLOW_NARROW", None)

    return {k: v for k, v in os.environ.items() if k.startswith("SECAGENT_")}



def _seeds_for(cases: dict, baseline_payload: str, injection_goal: str) -> list[str]:
    """Seed payloads for a pair, strongest baseline first.

    The first seed must be *condition B's actual payload*, not an approximation of
    it. The monotonicity guarantee that makes a null result interpretable —
    condition C cannot score below condition B — holds only if C's search starts
    from exactly what B was measured with. Seeding with the bare goal text instead
    was measuring a different attack and quietly voiding that guarantee.

    The corpus templates follow, then the raw goal as a floor.
    """
    from geryon.optimiser import BASELINE_LABEL

    seeds = [(BASELINE_LABEL, baseline_payload)]
    for case_id, case in cases.items():
        template = case.get("template", "")
        if "{goal}" in template:
            seeds.append((f"case:{case_id}", template.format(
                goal=injection_goal, user="the user", model="the AI assistant", task="")))
    seeds.append(("raw-goal", injection_goal))
    seen, out = set(), []
    for label, payload in seeds:
        if payload and payload.strip() and payload not in seen:
            seen.add(payload)
            out.append((label, payload))
    return out


def _run_condition_c(suite, pairs, cases, holder, pipeline, run_pair, args, logdir,
                     OutputLogger, baseline_attack):
    """Drive the optimiser over every within-policy pair; return security, utility, stats."""

    holder.set(pipeline)
    security, utility, clean = {}, {}, {}
    per_pair = []
    tool_names = [t.name for t in suite.tools]

    with OutputLogger(str(logdir), live=None):
        for user_id, injection_id in pairs:
            user_task = suite.user_tasks[user_id]
            injection_task = suite.injection_tasks[injection_id]
            authorised = sorted({c.function for c in user_task.ground_truth(
                suite.load_and_inject_default_environment({}))})
            # Condition B's exact payload for this pair, taken from the same
            # registered attack the B runs used.
            baseline = next(iter(baseline_attack.attack(user_task, injection_task).values()), "")
            labelled = _seeds_for(cases, baseline, injection_task.GOAL)
            result = run_pair(
                suite, user_task, injection_task,
                seeds=[p for _, p in labelled],
                seed_labels=[lbl for lbl, _ in labelled],
                authorised_tools=authorised, all_tools=tool_names,
                attacker_model=args.attacker_model,
                max_iterations=args.optimiser_budget,
            )
            key = f"{user_id}|{injection_id}"
            security[key] = result.success
            clean[key] = result.clean_success
            # utility of the best candidate: the last scored attempt that won, or
            # the strongest attempt if none won.
            best = next((a for a in reversed(result.attempts)
                         if a.scored and a.evaluation.goal_executed), None)
            if best is None:
                best = next((a for a in reversed(result.attempts) if a.scored), None)
            utility[key] = bool(best.evaluation.utility_preserved) if best else False
            per_pair.append(result.summary())
            print(f"  {key}: success={result.success} clean={result.clean_success} "
                  f"budget={result.iterations_used} rejected={result.rejected} "
                  f"origin={result.best_origin}", flush=True)

    total_budget = sum(p["iterations_used"] for p in per_pair)
    seed_wins = sum(1 for p in per_pair if p["succeeded_on_seed"])
    adaptive_wins = sum(1 for p in per_pair if p["success"] and not p["succeeded_on_seed"])
    clean_wins = sum(1 for p in per_pair if p["clean_success"])
    print(f"  optimiser: {adaptive_wins} adaptive wins, {seed_wins} seed wins, "
          f"{clean_wins} clean wins, {total_budget} total proposals", flush=True)
    return security, utility, {
        "per_pair": per_pair,
        "total_proposals": total_budget,
        "seed_wins": seed_wins,
        "adaptive_wins": adaptive_wins,
        "clean_wins": clean_wins,
        "clean_success": clean,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--suite", default="banking")
    ap.add_argument("--condition", choices=CONDITIONS, required=True)
    ap.add_argument("--repeat", type=int, required=True, help="1-based repeat index")
    ap.add_argument("--model", default="openai.gpt-oss-120b", help="the agent model")
    ap.add_argument("--policy-model", default="openai.gpt-oss-120b",
                    help="SECAGENT_POLICY_MODEL; Progent's own default is gpt-4o-2024-08-06")
    ap.add_argument("--attack", default="important_instructions",
                    help="condition C overrides this with a within-policy case id")
    ap.add_argument("--benchmark-version", default="v1.2",
                    help="v1.2 is the newest version Progent's vendored AgentDojo carries")
    ap.add_argument("--pairs", default="results/pairs.json")
    ap.add_argument("--out-dir", default="results/runs")
    ap.add_argument("--policy-updates", action="store_true",
                    help="SECAGENT_UPDATE=True (Progent's shipped default); off means narrow-only")
    ap.add_argument("--limit-user-tasks", type=int, default=0,
                    help="use only the first N user tasks; for cost calibration, NOT publishable")
    ap.add_argument("--attacker-model", default="openai.gpt-oss-120b",
                    help="condition C: the model that proposes adaptive payloads")
    ap.add_argument("--optimiser-budget", type=int, default=10,
                    help="condition C: max proposals per pair (pre-registered default 10)")
    ap.add_argument("--dry-run", action="store_true",
                    help="build everything and report the configuration without calling any model")
    ap.add_argument("--per-pair", action="store_true",
                    help="run each pair separately so one malformed reply cannot end the run")
    ap.add_argument("--all-pairs", action="store_true",
                    help="measure over the whole suite, the denominator the literature uses")
    ap.add_argument("--no-log-file", action="store_true",
                    help="do not capture this run's output next to its result")
    args = ap.parse_args()

    if args.condition == "A" and args.attack != "important_instructions":
        raise SystemExit("condition A is the no-defence baseline and uses the standard attack")

    log_path = None
    if not args.dry_run and not args.no_log_file:
        log_path = Path(args.out_dir) / f"{args.suite}-{args.condition}-r{args.repeat}.log"

    header = (
        f"# {args.suite} condition {args.condition} repeat {args.repeat}\n"
        f"# agent={args.model} policy={args.policy_model} "
        f"attacker={args.attacker_model} budget={args.optimiser_budget}\n"
        f"# started {datetime.now(UTC).isoformat()}"
    )
    # Everything the run does happens inside the capture, including loading the
    # pair file, so a failure at any point is explained by the log rather than
    # only by whatever the shell happened to keep.
    with ExitStack() as stack:
        if log_path is not None:
            stack.enter_context(runlog.capture(log_path, header=header))
        try:
            return _run(args, log_path)
        except BaseException:
            # Print the traceback *inside* the capture. An exception that escapes
            # the context manager has its traceback printed after the streams are
            # restored, so it lands wherever the shell was pointing and not in the
            # log — which is the one case the log exists for. A run of travel died
            # this way and left 3782 lines of progress and no cause.
            import traceback
            traceback.print_exc()
            raise


def _run(args, log_path) -> int:
    repo = Path(__file__).resolve().parents[1]
    pairs = load_pairs(repo / args.pairs, args.suite, within_policy_only=not args.all_pairs)
    user_tasks = sorted({u for u, _ in pairs})
    if args.limit_user_tasks:
        user_tasks = user_tasks[: args.limit_user_tasks]
        pairs = [p for p in pairs if p[0] in set(user_tasks)]
    injection_tasks = sorted({i for _, i in pairs})

    secagent_env = configure_environment(args)

    # Imported only now: the suites read SECAGENT_SUITE at import time.
    import agentdojo
    from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections, get_suite
    from agentdojo.logging import OutputLogger

    if args.condition == "C":
        import geryon.attack  # noqa: F401  registers the corpus
        from geryon.cases import load_cases
        from geryon.condition_c import _PIPELINE, run_condition_c_pair

    suite = get_suite(args.benchmark_version, args.suite)

    # The pair file is derived from one benchmark version; the defence may vendor
    # another. Progent's copy tops out at v1.2 and its travel suite is missing two
    # injection tasks that upstream v1.2.1 has. Validate against the live suite
    # rather than trusting the file, so a version mismatch fails here and not in
    # the middle of a paid run.
    missing_users = [u for u in user_tasks if u not in suite.user_tasks]
    missing_injections = [i for i in injection_tasks if i not in suite.injection_tasks]
    if missing_users or missing_injections:
        raise SystemExit(
            f"{args.pairs} names tasks that {args.benchmark_version} of suite "
            f"{args.suite!r} does not have: user {missing_users}, injection "
            f"{missing_injections}. Regenerate the pair file against the benchmark "
            "version the defence actually vendors."
        )

    wrapped = _defence_is_active(suite)

    expected = args.condition in ("B", "C")
    if wrapped is not None and wrapped != expected:
        raise SystemExit(
            f"condition {args.condition} expected the defence "
            f"{'active' if expected else 'inactive'}, but the suite's tools say otherwise. "
            "Check SECAGENT_SUITE and that agentdojo resolves to Progent's vendored copy."
        )

    provenance = {
        "timestamp": datetime.now(UTC).isoformat(),
        "condition": args.condition,
        "repeat": args.repeat,
        "suite": args.suite,
        "benchmark_version": args.benchmark_version,
        "agent_model": args.model,
        "policy_model": args.policy_model if args.condition != "A" else None,
        "attack": args.attack,
        "policy_updates_permitted": bool(args.policy_updates) if args.condition != "A" else None,
        "secagent_env": secagent_env if args.condition != "A" else {},
        "defence_active": wrapped,
        "agentdojo_path": str(Path(agentdojo.__file__).resolve().parent),
        "benchmark_repo": git_root(Path(agentdojo.__file__).resolve().parent),
        "benchmark_repo_commit": git_commit(Path(agentdojo.__file__).resolve().parent),
        "benchmark_repo_dirty": git_dirty(Path(agentdojo.__file__).resolve().parent),
        "geryon_commit": git_commit(repo),
        "geryon_dirty": git_dirty(repo),
        "pair_count": len(pairs),
        "calibration_only": bool(args.limit_user_tasks),
        "within_policy_only": not args.all_pairs,
        "pairs_file": args.pairs,
        "attacker_model": args.attacker_model if args.condition == "C" else None,
        "optimiser_budget": args.optimiser_budget if args.condition == "C" else None,
        "user_tasks": user_tasks,
        "injection_tasks": injection_tasks,
    }

    if args.dry_run:
        print(json.dumps(provenance, indent=2))
        print(f"\nwould run {len(user_tasks)} x {len(injection_tasks)} = "
              f"{len(user_tasks) * len(injection_tasks)} benchmark runs, "
              f"then keep the {len(pairs)} within-policy pairs")
        return 0

    meter = install_usage_meter()
    logdir = Path(args.out_dir) / f"logs-{args.suite}-{args.condition}-r{args.repeat}"
    pipeline = AgentPipeline.from_config(
        PipelineConfig(llm=args.model, defense=None, system_message_name=None, system_message=None)
    )
    wanted = set(pairs)

    if args.condition == "C":
        security, utility, provenance["optimiser"] = _run_condition_c(
            suite, pairs, load_cases(), _PIPELINE, pipeline, run_condition_c_pair,
            args, logdir, OutputLogger,
            baseline_attack=load_attack("important_instructions", suite, pipeline),
        )
    else:
        attack = load_attack(args.attack, suite, pipeline)
        if args.per_pair:
            security, utility, skipped = run_pair_by_pair(
                suite, attack, user_tasks, injection_tasks, wanted, logdir, OutputLogger
            )
            provenance["skipped_pairs"] = skipped
            if skipped:
                print(f"  {len(skipped)} coppie saltate su {len(wanted)}", flush=True)
        else:
            # AgentDojo's per-task TraceLogger resolves its output directory from
            # the enclosing logger in a context variable, so the benchmark has to
            # run inside one. Without it the first task dies on NullLogger.logdir.
            with OutputLogger(str(logdir), live=None):
                results = benchmark_suite_with_injections(
                    agent_pipeline=pipeline,
                    suite=suite,
                    attack=attack,
                    logdir=logdir,
                    force_rerun=True,  # repeats must not read each other's cache
                    user_tasks=user_tasks,
                    injection_tasks=injection_tasks,
                )
            security = {f"{u}|{i}": bool(v)
                        for (u, i), v in results["security_results"].items()
                        if (u, i) in wanted}
            utility = {f"{u}|{i}": bool(v)
                       for (u, i), v in results["utility_results"].items()
                       if (u, i) in wanted}
            provenance["skipped_pairs"] = {}

    # A skipped pair is accounted for, never silently absorbed: it is absent from
    # both numerator and denominator, and the reason is recorded in the provenance.
    accounted = {tuple(k.split("|")) for k in security} | {
        tuple(k.split("|")) for k in provenance.get("skipped_pairs", {})}
    missing = wanted - accounted
    if missing:
        raise SystemExit(f"benchmark did not return {len(missing)} expected pairs: {sorted(missing)[:5]}")

    provenance["usage"] = meter_summary(meter)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    suffix = "-calibration" if args.limit_user_tasks else ""
    path = out / f"{args.suite}-{args.condition}-r{args.repeat}{suffix}.json"
    path.write_text(json.dumps(
        {"provenance": provenance, "security": security, "utility": utility}, indent=2, sort_keys=True
    ))
    n = len(security)
    usage = provenance["usage"]
    print(f"{path}: attack success {sum(security.values())}/{n}, "
          f"utility {sum(utility.values())}/{len(utility)}", flush=True)
    print(f"  {usage['llm_calls']} LLM calls, {usage['prompt_tokens']} in / "
          f"{usage['completion_tokens']} out, ~${usage['estimated_usd']:.4f}", flush=True)
    if log_path is not None:
        print(f"  log: {log_path}.gz")
    return 0


def _defence_is_active(suite) -> bool | None:
    """Whether Progent's tool wrapper is applied, read off the suite itself.

    The wrapper uses functools.wraps, so the tool keeps the original module and
    qualname; what it cannot hide is which file its code object came from.
    Returns None when it cannot be determined, so a change in how Progent wraps
    tools degrades to "unknown" rather than to a silently wrong label.
    """
    try:
        tools = list(suite.tools)
    except Exception:
        return None
    if not tools:
        return None
    for tool in tools:
        run = getattr(tool, "run", None)
        code = getattr(run, "__code__", None)
        filename = getattr(code, "co_filename", "")
        if "secagent" in filename:
            return True
    return False


if __name__ == "__main__":
    raise SystemExit(main())
