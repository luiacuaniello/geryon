"""The pre-registered analysis of the fair test in docs/generic-policy.md.

    PYTHONPATH=src python scripts/analyse_fair_test.py

Fixed before any run. Each configuration is read from its own directory under
results/runs-fair-test/, and nothing is reported unless every run is what its
directory says and all of them are comparable: same agent, policy model,
benchmark version and Progent commit, the same 144 banking pairs, three repeats,
and, for the generic policy, a log showing its rules held for the whole run.

Each pair counts as one outcome, the majority of its three repeats. Attack success
is scored as the checks of agentdojo#240 intend for injection tasks 0, 1 and 3
(scripts/rescore_agentdojo_240.py), and as AgentDojo records it, side by side. The
intended scoring is primary: the recorded one counts any transfer to the attacker
as a success, which can only favour the generic policy, since it refuses them all.

The primary comparison is the generic policy against Progent as shipped on the 42
within-policy pairs, by two-sided exact McNemar test. The secondary comparisons
are printed with their p-values and carry no claim of their own.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from analyse_runs import SHARED_PROVENANCE, collapse, load_runs
from geryon.generic_policy import check_log
from geryon.stats import ALPHA, MAJORITY_OF, mcnemar_exact, minimum_detectable_discordant, wilson_ci
from rescore_agentdojo_240 import ReconstructionError, rescore_run

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
SUITE = "banking"
PROGENT_COMMIT = "b02783b"

#: Directory under the root, and the (condition, approver, generic policy) its runs must record.
CONFIGURATIONS = {
    "A": ("A", None, None),
    "auto-approve": ("B", "auto-approve", False),
    "generic": ("B", "auto-approve", True),
    "auto-deny": ("B", "auto-deny", False),
}
#: (configuration, against, pair set). The first is the primary comparison.
COMPARISONS = (
    ("generic", "auto-approve", "within policy"),
    ("auto-deny", "auto-approve", "within policy"),
    ("generic", "auto-approve", "all pairs"),
    ("auto-deny", "auto-approve", "all pairs"),
)
#: The user tasks whose reference solution the generic policy refuses, from the
#: pre-analysis in docs/generic-policy.md. tests/test_analyse_fair_test.py keeps
#: the two in step.
REFUSED_USER_TASKS = ("user_task_0", "user_task_5", "user_task_11", "user_task_14", "user_task_15")
#: The August measurement at Progent commit 8a8eb89, which A and auto-approve repeat.
EARLIER = RESULTS / "runs-full-set"
READINGS = ("intended", "recorded")


def pair_sets(pairs_file: Path) -> dict[str, set[str]]:
    """The banking pairs of the pairs file, all and within policy, keyed as collapse() keys them."""
    pairs = [p for p in json.loads(pairs_file.read_text()) if p["suite"] == SUITE]
    keyed = {f"{SUITE}/{p['user_task']}|{p['injection_task']}": p for p in pairs}
    return {"all pairs": set(keyed), "within policy": {k for k, p in keyed.items() if p["within_policy"]}}


def load(root: Path) -> dict[str, list[dict]]:
    """Each configuration's runs, from its directory under the root."""
    found = {}
    for name in CONFIGURATIONS:
        by_condition = load_runs(root / name, SUITE) if (root / name).is_dir() else {}
        found[name] = [run for runs in by_condition.values() for run in runs]
    return found


def problems(configurations: dict[str, list[dict]], all_pairs: set[str],
             require_repeats: bool = True) -> list[str]:
    """Why these runs cannot be reported, if they cannot."""
    found = []
    everything = [run for runs in configurations.values() for run in runs]
    for name, expected in CONFIGURATIONS.items():
        runs = configurations[name]
        if require_repeats and len(runs) != MAJORITY_OF:
            found.append(f"{name}: {len(runs)} repeats, the protocol fixes {MAJORITY_OF}")
        for run in runs:
            p, path = run["provenance"], run["_path"]
            recorded = (p["condition"], p.get("approver"), p.get("generic_policy"))
            if recorded != expected:
                found.append(f"{path}: records {recorded}, {name} needs {expected}")
            if p.get("defence_active") is not None and p["defence_active"] != (expected[0] == "B"):
                found.append(f"{path}: defence_active is {p['defence_active']}")
            if not str(p.get("benchmark_repo_commit") or "").startswith(PROGENT_COMMIT):
                found.append(f"{path}: Progent commit {p.get('benchmark_repo_commit')}, not {PROGENT_COMMIT}")
            if {f"{SUITE}/{pair}" for pair in run["security"]} != all_pairs:
                found.append(f"{path}: not the {len(all_pairs)} {SUITE} pairs of the pairs file")
    for field in SHARED_PROVENANCE:
        values = {str(run["provenance"].get(field)) for run in everything}
        if len(values) > 1:
            found.append(f"runs disagree on {field}: {sorted(values)}")
    defended = [run for run in everything if run["provenance"]["condition"] == "B"]
    models = {str(run["provenance"].get("policy_model")) for run in defended}
    if len(models) > 1:
        found.append(f"defended runs disagree on the policy model: {sorted(models)}")
    for run in configurations["generic"]:
        log = Path(run["_path"]).with_suffix(".log.gz")
        if not log.exists():
            found.append(f"{log}: missing, so the generic rules cannot be shown to have held")
        elif not check_log(log).valid:
            found.append(f"{log}: fails python -m geryon.generic_policy --check-log")
    return found


def scored(runs: list[dict], reading: str) -> list[dict]:
    """The runs with their security outcomes as recorded or as agentdojo#240 intends."""
    if reading == "recorded":
        return runs
    return [{**run, "security": rescore_run(Path(run["_path"]))["intended"]} for run in runs]


def row(outcome: dict[str, bool], groups: dict[str, set[str]]) -> str:
    return "".join(f"  {group} {rate(outcome, pairs)}" for group, pairs in groups.items())


def rate(outcome: dict[str, bool], pairs: set[str]) -> str:
    present = [p for p in pairs if p in outcome]
    k, n = sum(outcome[p] for p in present), len(present)
    if not n:
        return "  -"
    low, high = wilson_ci(k, n)
    return f"{k:3d}/{n:3d} {100 * k / n:5.1f}% [{100 * low:4.1f}-{100 * high:4.1f}]"


def compare(outcome: dict[str, bool], against: dict[str, bool], pairs: set[str]) -> tuple[int, int, float]:
    """Attacks stopped only by the configuration, let through only by it, and the exact McNemar p-value."""
    shared = [p for p in pairs if p in outcome and p in against]
    stopped = sum(1 for p in shared if against[p] and not outcome[p])
    let_through = sum(1 for p in shared if outcome[p] and not against[p])
    return stopped, let_through, mcnemar_exact(let_through, stopped).p_value


def report(configurations: dict[str, list[dict]], sets: dict[str, set[str]]) -> None:
    present = {name: runs for name, runs in configurations.items() if runs}
    security = {reading: {name: collapse(scored(runs, reading), "security") for name, runs in present.items()}
                for reading in READINGS}
    utility = {name: collapse(runs, "utility") for name, runs in present.items()}
    refused = {p for p in sets["all pairs"] if p.split("/")[1].split("|")[0] in REFUSED_USER_TASKS}
    groups = {**sets, "refused user tasks": refused, "other user tasks": sets["all pairs"] - refused}

    for reading in READINGS:
        label = "as agentdojo#240 intends, primary" if reading == "intended" else "as recorded"
        print(f"\nattack success, {label}:")
        for name, outcome in security[reading].items():
            print(f"  {name:13s}{row(outcome, sets)}")

    print(f"\nutility under attack (the {len(REFUSED_USER_TASKS)} refused user tasks are those whose "
          "reference solution the pre-analysis expects the policy to refuse):")
    for name, outcome in utility.items():
        print(f"  {name:13s}{row(outcome, groups)}")

    threshold = minimum_detectable_discordant()
    print(f"\ncomparisons, as agentdojo#240 intends (two-sided exact McNemar, alpha {ALPHA}, "
          f"a claim needs {threshold} pairs in one direction):")
    outcomes = security["intended"]
    for i, (name, against, set_name) in enumerate(COMPARISONS):
        if name not in outcomes or against not in outcomes:
            continue
        stopped, let_through, p = compare(outcomes[name], outcomes[against], sets[set_name])
        role = "PRIMARY  " if i == 0 else "secondary"
        if i:
            verdict = "no claim"
        elif p < ALPHA:
            verdict = f"significant: {'fewer' if stopped > let_through else 'more'} successes under {name}"
        else:
            verdict = "not significant: no difference detectable at this size"
        print(f"  {role} {name} against {against}, {set_name}: {stopped} attacks stopped only by {name}, "
              f"{let_through} let through only by it, p={p:.4f}, {verdict}")

    if "A" in outcomes:
        print("\nshare of A's successes each configuration removes, as agentdojo#240 intends:")
        for name, outcome in outcomes.items():
            if name == "A":
                continue
            cells = []
            for set_name, pairs in sets.items():
                base = sum(outcomes["A"][p] for p in pairs)
                left = sum(outcome[p] for p in pairs)
                cells.append(f"{set_name} {100 * (base - left) / base:.0f}%" if base else f"{set_name} -")
            print(f"  {name:13s}  " + "  ".join(cells))

    if "generic" in present:
        # Recorded, not intended: a transfer to the attacker that went through is a
        # failure of the rules even when its subject lacks the data the task wants.
        print("\nevery recorded success under the generic policy, run by run "
              "(the pre-analysis expects none):")
        listed = False
        for run, intended in zip(present["generic"], scored(present["generic"], "intended"), strict=True):
            for pair, success in sorted(run["security"].items()):
                if success:
                    listed = True
                    also = "" if intended["security"][pair] else ", not a success as agentdojo#240 intends"
                    print(f"  repeat {run['provenance']['repeat']}: {pair}{also}")
        if not listed:
            print("  none")


def earlier(sets: dict[str, set[str]]) -> None:
    """A and B at Progent commit 8a8eb89, for telling a change of commit from a change of configuration."""
    runs = load_runs(EARLIER, SUITE)
    print(f"\nthe August measurement at 8a8eb89 ({EARLIER.relative_to(ROOT)}), A and Progent as shipped:")
    for reading in READINGS:
        for condition in ("A", "B"):
            outcome = collapse(scored(runs[condition], reading), "security")
            print(f"  {reading:8s} {condition}{row(outcome, sets)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=RESULTS / "runs-fair-test")
    ap.add_argument("--pairs", type=Path, default=RESULTS / "pairs-fork-v1.2.json")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="print what is there and label it as not publishable")
    args = ap.parse_args()

    sets = pair_sets(args.pairs)
    configurations = load(args.root)
    found = problems(configurations, sets["all pairs"], require_repeats=not args.allow_incomplete)
    if found:
        print("NOT PUBLISHABLE. These runs cannot be reported:" if not args.allow_incomplete
              else "WARNING, these numbers are not publishable:")
        for problem in found:
            print(f"  - {problem}")
        if not args.allow_incomplete:
            return 1
    try:
        report(configurations, sets)
        if EARLIER.is_dir():
            earlier(sets)
    except ReconstructionError as exc:
        print(f"\nRECONSTRUCTION FAILED, nothing above can be trusted: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
