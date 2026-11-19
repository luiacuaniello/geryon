"""Exploratory, not pre-registered: what the generic policy's stopped attacks cost the user.

    python scripts/explore_fair_test.py

docs/generic-policy.md fixed the analysis of the generic-policy runs before any
run, and scripts/analyse_fair_test.py applies it. This script is not part of
that plan. It was written on 19 November 2026, after the results had been read,
and everything it prints is exploratory.

It asks two things of the runs in results/runs-fair-test/. On the 42
within-policy pairs, how do the attacks that only the generic policy stopped
relate to the five user tasks whose reference solution it refuses? And in how
many pairs does each configuration both complete the user's task and defeat the
attack? Outcomes are the majority of three repeats, with attack success scored
as agentdojo#240 intends, as in the primary analysis. No test is applied.

The figures are those first computed on 2026-11-19 and quoted in
docs/generic-policy.md; the script exits 1 if they change.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import analyse_fair_test as plan
from analyse_runs import collapse

#: Figures as first computed, 2026-11-19.
EXPECTED = {
    "within-policy pairs": 42,
    "within-policy pairs in the five refused user tasks": 27,
    "attacks only the generic policy stopped, within policy": 18,
    "of those, in the five refused user tasks": 13,
    "of those, task completed under the generic policy": 4,
    "of those, task completed under Auto-Approve": 11,
    "A: utility, within policy, refused user tasks": 15,
    "A: utility, within policy, other user tasks": 9,
    "A: task completed and attack failed, within policy": 4,
    "A: task completed and attack failed, all pairs": 22,
    "auto-approve: utility, within policy, refused user tasks": 12,
    "auto-approve: utility, within policy, other user tasks": 5,
    "auto-approve: task completed and attack failed, within policy": 6,
    "auto-approve: task completed and attack failed, all pairs": 59,
    "generic: utility, within policy, refused user tasks": 6,
    "generic: utility, within policy, other user tasks": 1,
    "generic: task completed and attack failed, within policy": 7,
    "generic: task completed and attack failed, all pairs": 63,
    "auto-deny: utility, within policy, refused user tasks": 11,
    "auto-deny: utility, within policy, other user tasks": 9,
    "auto-deny: task completed and attack failed, within policy": 12,
    "auto-deny: task completed and attack failed, all pairs": 63,
}


def figures(root: Path, pairs_file: Path) -> dict[str, int]:
    """The exploratory figures, from runs the pre-registered analysis would accept."""
    sets = plan.pair_sets(pairs_file)
    configurations = plan.load(root)
    found = plan.problems(configurations, sets["all pairs"])
    if found:
        raise SystemExit("these runs cannot be reported:\n  " + "\n  ".join(found))
    skipped = plan.left_out(configurations)
    sets = {name: pairs - skipped for name, pairs in sets.items()}
    within, everything = sets["within policy"], sets["all pairs"]
    refused = {p for p in everything if p.split("/")[1].split("|")[0] in plan.REFUSED_USER_TASKS}

    attack = {name: collapse(plan.scored(runs, "intended"), "security")
              for name, runs in configurations.items()}
    task = {name: collapse(runs, "utility") for name, runs in configurations.items()}
    only_generic = {p for p in within if attack["auto-approve"][p] and not attack["generic"][p]}

    out = {
        "within-policy pairs": len(within),
        "within-policy pairs in the five refused user tasks": len(within & refused),
        "attacks only the generic policy stopped, within policy": len(only_generic),
        "of those, in the five refused user tasks": len(only_generic & refused),
        "of those, task completed under the generic policy": sum(task["generic"][p] for p in only_generic),
        "of those, task completed under Auto-Approve": sum(task["auto-approve"][p] for p in only_generic),
    }
    for name in plan.CONFIGURATIONS:
        done, succeeded = task[name], attack[name]
        out[f"{name}: utility, within policy, refused user tasks"] = sum(done[p] for p in within & refused)
        out[f"{name}: utility, within policy, other user tasks"] = sum(done[p] for p in within - refused)
        for set_name, pairs in (("within policy", within), ("all pairs", everything)):
            out[f"{name}: task completed and attack failed, {set_name}"] = sum(
                done[p] and not succeeded[p] for p in pairs)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=plan.RESULTS / "runs-fair-test")
    ap.add_argument("--pairs", type=Path, default=plan.RESULTS / "pairs-fork-v1.2.json")
    args = ap.parse_args()
    found = figures(args.root, args.pairs)

    print("EXPLORATORY, not part of the pre-registered analysis of docs/generic-policy.md\n")
    for key in list(found)[:6]:
        print(f"  {found[key]:3d}  {key}")
    refused_n = found["within-policy pairs in the five refused user tasks"]
    other_n = found["within-policy pairs"] - refused_n
    print(f"\n{'':15s}{'utility, within policy':>34s}   {'task completed and attack failed':>34s}")
    print(f"{'':15s}{f'refused tasks ({refused_n})':>17s}{f'other tasks ({other_n})':>17s}   "
          f"{'within policy':>17s}{'all pairs':>17s}")
    for name in plan.CONFIGURATIONS:
        cells = (found[f"{name}: utility, within policy, refused user tasks"],
                 found[f"{name}: utility, within policy, other user tasks"],
                 found[f"{name}: task completed and attack failed, within policy"],
                 found[f"{name}: task completed and attack failed, all pairs"])
        print(f"  {name:13s}{cells[0]:17d}{cells[1]:17d}   {cells[2]:17d}{cells[3]:17d}")

    drift = {k: (found.get(k), v) for k, v in EXPECTED.items() if found.get(k) != v}
    if drift:
        print(f"THE FIGURES QUOTED IN docs/generic-policy.md NO LONGER HOLD (found, expected): {drift}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
