"""Apply the pre-registered analysis to the run files produced by run_condition.py.

Two analyses, because they answer different questions and only one of them has
the statistical power to answer anything.

Per suite
    Descriptive. Banking is the only suite whose within-policy pair set is large
    enough to reach the pre-registered threshold on its own; slack and workspace
    would need a third of their pairs to flip, and travel would need all of them.

Pooled
    The primary analysis. The within-policy pair sets are small individually and
    the threshold is a fixed number of discordant pairs, so pooling across suites
    is what buys power: six flips out of 85 pooled pairs is 7.1 percentage
    points, against 14.3 on banking alone. The minimum detectable effect is
    computed from the pairs actually run, never from the pairs that exist.

Refuses to report if the runs are not comparable, because a pooled number over
runs that used different models is worse than no number.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from geryon.stats import (
    MAJORITY_OF,
    majority_outcome,
    mcnemar_exact,
    minimum_detectable_discordant,
    minimum_detectable_effect,
    report_condition,
)

DEFAULT_SUITES = ("banking", "slack", "travel", "workspace")

#: Provenance that must agree across every run being compared, in one suite or
#: pooled across several. "suite" is deliberately absent: it is the thing that
#: legitimately varies when pooling, and is checked per group instead.
SHARED_PROVENANCE = ("benchmark_version", "agent_model")
#: Checked only across the defended conditions, since condition A has no defence.
DEFENCE_PROVENANCE = ("policy_model", "policy_updates_permitted")


def load_runs(run_dir: Path, suite: str) -> dict[str, list[dict]]:
    """Runs for one suite, keyed by condition. Calibration runs are excluded."""
    runs: dict[str, list[dict]] = defaultdict(list)
    for path in sorted(run_dir.glob(f"{suite}-*-r*.json")):
        data = json.loads(path.read_text())
        # Calibration runs use a truncated pair set to price the experiment. They
        # are kept for the cost record and must never enter the comparison.
        if data["provenance"].get("calibration_only"):
            print(f"skipping calibration run {path.name}")
            continue
        if data["provenance"]["suite"] != suite:
            raise SystemExit(f"{path}: file name says {suite}, provenance says "
                             f"{data['provenance']['suite']}")
        data["_path"] = str(path)
        runs[data["provenance"]["condition"]].append(data)
    return dict(runs)


def check_comparable(runs: dict[str, list[dict]], require_repeats: bool = True) -> list[str]:
    problems = []
    everything = [r for rs in runs.values() for r in rs]
    if not everything:
        return ["no runs"]

    for field in SHARED_PROVENANCE:
        values = {r["provenance"].get(field) for r in everything}
        if len(values) > 1:
            problems.append(f"runs disagree on {field}: {sorted(map(str, values))}")

    defended = [r for r in everything if r["provenance"]["condition"] in ("B", "C")]
    for field in DEFENCE_PROVENANCE:
        values = {r["provenance"].get(field) for r in defended}
        if len(values) > 1:
            problems.append(f"defended runs disagree on {field}: {sorted(map(str, values))}")

    by_suite: dict[str, set[frozenset]] = defaultdict(set)
    for r in everything:
        by_suite[r["provenance"]["suite"]].add(frozenset(r["security"]))
    for suite, pair_sets in sorted(by_suite.items()):
        if len(pair_sets) > 1:
            problems.append(f"{suite}: runs do not cover the identical pair set; "
                            "the comparison is not paired")

    for condition, rs in sorted(runs.items()):
        suites_seen = {r["provenance"]["suite"] for r in rs}
        for suite in sorted(suites_seen):
            n = sum(1 for r in rs if r["provenance"]["suite"] == suite)
            if require_repeats and n != MAJORITY_OF:
                problems.append(
                    f"{suite} condition {condition}: {n} repeats, protocol fixes {MAJORITY_OF}"
                )
        for r in rs:
            active = r["provenance"].get("defence_active")
            expected = condition in ("B", "C")
            if active is not None and active != expected:
                problems.append(f"{r['_path']}: defence_active={active} for condition {condition}")

    conditions = set(runs)
    for suite in sorted({r["provenance"]["suite"] for r in everything}):
        present = {c for c, rs in runs.items() if any(r["provenance"]["suite"] == suite for r in rs)}
        if present != conditions:
            problems.append(f"{suite}: has conditions {sorted(present)} but the set being "
                            f"analysed has {sorted(conditions)}; pooling would compare "
                            "different suites in different conditions")
    return problems


def collapse(runs: list[dict], key: str) -> dict[str, bool]:
    """Repeats to one outcome per pair, keyed so pairs from different suites cannot collide."""
    outcomes: dict[str, list[bool]] = defaultdict(list)
    for run in runs:
        suite = run["provenance"]["suite"]
        for pair, value in run[key].items():
            outcomes[f"{suite}/{pair}"].append(bool(value))
    collapsed = {}
    for pair, values in outcomes.items():
        collapsed[pair] = majority_outcome(values) if len(values) == MAJORITY_OF else any(values)
    return collapsed


def report(runs: dict[str, list[dict]], label: str) -> None:
    collapsed = {}
    print(f"\n--- {label} ---")
    for condition in ("A", "B", "C"):
        if condition not in runs:
            continue
        security = collapse(runs[condition], "security")
        utility = collapse(runs[condition], "utility")
        collapsed[condition] = security
        n = len(security)
        print(report_condition(f"condition {condition} attack success", sum(security.values()), n))
        per_run = [sum(r["security"].values()) for r in runs[condition]]
        usage = [r["provenance"].get("usage", {}).get("estimated_usd", 0) for r in runs[condition]]
        print(f"    utility {sum(utility.values())}/{len(utility)}, "
              f"per-run attack success {per_run}, cost ${sum(usage):.2f}")

    if "B" not in collapsed or "C" not in collapsed:
        print("\nno B/C comparison: condition C has not been run yet")
        return

    shared = sorted(set(collapsed["B"]) & set(collapsed["C"]))
    b = sum(1 for p in shared if not collapsed["B"][p] and collapsed["C"][p])
    c = sum(1 for p in shared if collapsed["B"][p] and not collapsed["C"][p])
    print()
    print(mcnemar_exact(b, c).describe())
    threshold = minimum_detectable_discordant()
    mde = minimum_detectable_effect(len(shared))
    print(f"threshold fixed in advance: {threshold} discordant pairs in one direction, "
          f"which on these {len(shared)} pairs is {mde:.1f} percentage points")
    if threshold > len(shared):
        print("  NOTE: fewer pairs than required flips; no claim is reachable on this set")
    elif mde >= 50:
        print("  NOTE: would require most of the pair set to flip; treat as descriptive only")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--suite", help="analyse a single suite")
    ap.add_argument("--suites", nargs="*", help="pool across these suites (the primary analysis)")
    ap.add_argument("--run-dir", default="results/runs")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="print what is there and label it as not publishable")
    args = ap.parse_args()

    if args.suite and args.suites:
        raise SystemExit("use --suite or --suites, not both")
    suites = [args.suite] if args.suite else (args.suites or list(DEFAULT_SUITES))

    run_dir = Path(args.run_dir)
    per_suite = {}
    for suite in suites:
        runs = load_runs(run_dir, suite)
        if runs:
            per_suite[suite] = runs
        elif args.suite:
            raise SystemExit(f"no run files for suite {suite!r} in {run_dir}")
    if not per_suite:
        raise SystemExit(f"no run files for {suites} in {run_dir}")

    pooled: dict[str, list[dict]] = defaultdict(list)
    for runs in per_suite.values():
        for condition, rs in runs.items():
            pooled[condition].extend(rs)
    pooled = dict(pooled)

    problems = check_comparable(pooled, require_repeats=True)
    if problems and not args.allow_incomplete:
        print("NOT PUBLISHABLE. The runs are not comparable:")
        for problem in problems:
            print(f"  - {problem}")
        print("\nRe-run what is missing, or pass --allow-incomplete to look anyway.")
        return 1
    if problems:
        print("WARNING, these numbers are not publishable:")
        for problem in problems:
            print(f"  - {problem}")

    sample = next(iter(pooled.values()))[0]["provenance"]
    print(f"\nbenchmark {sample['benchmark_version']}, agent {sample['agent_model']}")
    for r in (r for rs in pooled.values() for r in rs):
        if r["provenance"]["condition"] in ("B", "C"):
            print(f"defence: policy model {r['provenance']['policy_model']}, "
                  f"policy updates permitted: {r['provenance']['policy_updates_permitted']}")
            break

    for suite, runs in sorted(per_suite.items()):
        report(runs, f"{suite} (descriptive)")

    if len(per_suite) > 1:
        report(pooled, f"POOLED over {', '.join(sorted(per_suite))} (primary analysis)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
