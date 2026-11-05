"""Draw the paper's Figure 1 from the run files, so that it can be checked like any other number.

    python scripts/make_figure1.py [--out results/figures/figure1.pdf]

Needs matplotlib (``pip install -e ".[figures]"``). Every value is computed here
from ``results/runs-full-set/`` and ``results/pairs-fork-v1.2.json`` under the
benchmark's own scoring, the same scoring the paper's text uses; the corrections
for agentdojo#240 and slack injection_task_5 are reported separately
(``scripts/rescore_agentdojo_240.py``, ``scripts/rescore_slack_task5.py``).

(a) Attack success with and without Progent, on the out-of-policy and the
    within-policy pairs of banking, slack and travel, majority of three repeats,
    on the pairs every repeat of both conditions ran, with 95% Wilson intervals.
(b) Per suite, the within-policy share of its pairs against the attack success
    that survives the defence, with the line y = x for reference.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from geryon.stats import majority_outcome, wilson_ci

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "results" / "runs-full-set"
SUITES = ("banking", "slack", "travel")


def collapse(suite: str, condition: str) -> dict[str, bool]:
    runs = [json.loads((RUNS / f"{suite}-{condition}-r{i}.json").read_text())["security"] for i in (1, 2, 3)]
    pairs = set.intersection(*(set(r) for r in runs))
    return {p: majority_outcome([bool(r[p]) for r in runs]) for p in pairs}


def figure_data() -> dict:
    pairs = json.loads((ROOT / "results" / "pairs-fork-v1.2.json").read_text())
    within = {(p["suite"], f"{p['user_task']}|{p['injection_task']}"): p["within_policy"] for p in pairs}
    a = {s: collapse(s, "A") for s in SUITES}
    b = {s: collapse(s, "B") for s in SUITES}

    groups = {}
    for name, flag in (("out-of-policy", False), ("within-policy", True)):
        keys = [(s, p) for s in SUITES for p in set(a[s]) & set(b[s]) if within[(s, p)] is flag]
        n = len(keys)
        ka = sum(a[s][p] for s, p in keys)
        kb = sum(b[s][p] for s, p in keys)
        groups[name] = {"n": n, "A": (ka, n), "B": (kb, n)}

    suites = {}
    for s in SUITES:
        suite_pairs = [k for k in within if k[0] == s]
        share = sum(within[k] for k in suite_pairs) / len(suite_pairs)
        defended = sum(b[s].values()) / len(b[s])
        suites[s] = (100 * share, 100 * defended)
    return {"groups": groups, "suites": suites}


def draw(data: dict, out: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        "font.family": "serif", "font.serif": ["cmr10"], "mathtext.fontset": "cm",
        "axes.formatter.use_mathtext": True, "axes.unicode_minus": False, "font.size": 9,
        "axes.spines.top": False, "axes.spines.right": False, "pdf.fonttype": 42,
    })
    fig, (left, right) = plt.subplots(1, 2, figsize=(7.2, 2.6), gridspec_kw={"wspace": 0.32})
    red, width = "#b03030", 0.36

    names = list(data["groups"])
    for i, name in enumerate(names):
        g = data["groups"][name]
        for j, (condition, colour) in enumerate((("A", "white"), ("B", red))):
            k, n = g[condition]
            rate = 100 * k / n
            lo, hi = (100 * x for x in wilson_ci(k, n))
            x = i + (j - 0.5) * width
            left.bar(x, rate, width, color=colour, edgecolor="black", linewidth=0.8,
                     label=("no defence" if condition == "A" else "Progent") if i == 0 else None)
            left.errorbar(x, rate, yerr=[[rate - lo], [hi - rate]], color="black", capsize=3, linewidth=0.9)
        (ka, n), (kb, _) = g["A"], g["B"]
        removed = 100 * (ka - kb) / ka
        left.text(i, 93, f"$-{removed:.0f}\\%$", ha="center", va="bottom", fontsize=10)
    left.set_xticks(range(len(names)))
    left.set_xticklabels([f"{name}\n({data['groups'][name]['n']} pairs)" for name in names])
    left.set_ylim(0, 108)
    left.set_yticks(range(0, 101, 20))
    left.set_ylabel("attack success (%)")
    left.set_title("(a) the same defence, two subsets", fontsize=9)
    left.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.24), ncol=2)

    limit = 35
    right.plot([0, limit], [0, limit], linestyle=":", color="grey", linewidth=1)
    for suite, (share, defended) in data["suites"].items():
        right.scatter(share, defended, s=36, color=red, edgecolor="black", linewidth=0.7, zorder=3)
        right.annotate(suite, (share, defended), textcoords="offset points", xytext=(6, -3), fontsize=9)
    right.set_xlim(-1, limit)
    right.set_ylim(-1, limit)
    right.set_xlabel("within-policy share of the suite (%)")
    right.set_ylabel("attack success, defended (%)")
    right.set_title("(b) what survives rises with what is within policy", fontsize=9)

    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, bbox_inches="tight")


def main() -> int:
    ap = argparse.ArgumentParser(description="Draw Figure 1 from the run files.")
    ap.add_argument("--out", type=Path, default=ROOT / "results" / "figures" / "figure1.pdf")
    args = ap.parse_args()
    data = figure_data()
    for name, g in data["groups"].items():
        (ka, n), (kb, _) = g["A"], g["B"]
        print(f"{name:14s} n={n:3d}  no defence {ka}/{n} = {100 * ka / n:.1f}%  "
              f"Progent {kb}/{n} = {100 * kb / n:.1f}%  removed {100 * (ka - kb) / ka:.1f}%")
    for suite, (share, defended) in data["suites"].items():
        print(f"{suite:8s} within-policy share {share:.1f}%  defended {defended:.1f}%")
    draw(data, args.out)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
