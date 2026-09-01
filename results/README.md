# Results

Every result lands here, including negative ones and the ones that turned out to
be unusable, with the configuration of the run recorded beside it.

## Map of the directories

Eleven directories, and two of them are traps. Read this before quoting any
number out of them.

| directory | what it is | usable? |
|---|---|---|
| `runs/` | **A and B on the 42 within-policy pairs of banking**, three repeats each, plus one calibration run on 12 pairs. The baseline the whole project is measured against. | yes |
| `runs-condition-c/` | **Condition C on the same 42 pairs**, three repeats: corpus templates plus the seeded optimiser, attacker `gpt-oss-120b`. Gives the significant B-vs-C result. | yes |
| `runs-full-set/` | **A and B over every pair of banking, slack and travel** — 349 pairs, three repeats each, eighteen runs. The decomposition in the proposal comes from here. | yes |
| `runs-strong-agent/` | A on the 42 within-policy pairs with agent `qwen3-235b`, three repeats. Shows the more capable agent is *more* vulnerable undefended. | yes |
| `runs-full-set-strong-agent/` | A and B over all 144 banking pairs with agent `qwen3-235b`, one repeat. Replicates the decomposition on a second agent model. | yes, one repeat |
| `runs-strong-attacker/` | Condition C with attacker `qwen3-235b`, one repeat. Bounds the null result on adaptation with a second, larger attacker. | yes, one repeat |
| `runs-strong-policy-fixed/` | B with policy model `qwen3-235b` **after** the prompt patch. One of the three policy-model configurations that exclude the confound. | yes, one repeat |
| `cmcp-pilot/` | The deployed MCP gateway pilot: config, catalog, policies, and the three-call result. No inference cost. | yes |
| `logs/` | Raw stdout of early runs, gzipped. Holds the evidence for the Progent findings — 92 of 270 policy updates carrying the attacker's account number. | evidence, not measurements |
| `runs-strong-policy/` | B with policy model `qwen3-235b` **before** the prompt patch, when 230 of 270 policy updates were failing to parse and being swallowed silently. | **NO — kept as the record of the defect** |
| `runs-claude-policy/` | An attempt to use `claude-sonnet-5` as the policy model. It never ran: the model is gated on this account and the endpoint rejected it. Only a log survives. | **NO — failed run** |

The two "NO" rows are kept rather than deleted because a defect that leaves no
trace is a defect that gets rediscovered. Their numbers must not be quoted.

## Which numbers the proposal uses

- the decomposition, 84% against 57%: `runs-full-set/`, all three suites, three
  repeats collapsed by majority
- the significant B-vs-C, p = 0.0078: `runs/` against `runs-condition-c/`
- the policy-model confound, 42.9% / 45.2% / 45.2%: `runs/`,
  `runs-strong-policy/` *(the broken arm, quoted only as the broken arm)* and
  `runs-strong-policy-fixed/`
- the deployed-layer finding: `cmcp-pilot/`

## Reading a run file

Each `.json` carries a `provenance` block with the agent model, the policy model,
the attacker model where one exists, the benchmark version, the pair file, the
defence configuration, whether the defence was verified active, the measured token
usage and cost, and any pairs skipped with the reason. A run whose provenance
cannot answer a question about it is not a result.

One pair of 348 was skipped in the whole campaign, in `travel-A-r2`, for a
malformed model reply. It is absent from both numerator and denominator.

## The two analyses

**Pooled across suites is the primary one.** The threshold is a fixed number of
discordant pairs, not a percentage, so pooling is what buys power: six flips is
7.1 percentage points on the full 85-pair set against 14.3 on banking alone, and
31.6 on slack. Three suites that each show "one pair moved, not significant" pool
into a single test over all their pairs.

Per-suite numbers are descriptive and are reported alongside, never instead.

```bash
python scripts/analyse_runs.py --suites banking slack workspace   # primary
python scripts/analyse_runs.py --suite banking                    # descriptive
```

The minimum detectable effect is computed from the pairs **actually run**, not
from the pairs that exist, so excluding a suite shows up as a weaker threshold
rather than disappearing.

## Reporting requirements

From `protocol/threat-model.md`, fixed before any experiment:

- the three conditions A, B and C on an identical pair set
- three runs per condition, collapsed per pair by majority (not by "any run")
- the paired exact McNemar test between B and C, with its discordant counts b
  and c reported as raw numbers, not only as a p-value
- Wilson intervals next to every rate, because a rate of 0/42 is not zero
- utility reported next to attack success, always
- the pair count the numbers are computed over
- the exact configuration of the defence, including which model authored the
  policy and whether runtime policy updates were permitted

A result that cannot state all seven is not published as a result.

## What is not a finding

A difference of fewer than six discordant pairs in one direction. That threshold
is arithmetic, not judgement: with a two-sided exact McNemar test at alpha 0.05,
five pairs flipping in one direction gives p = 0.0625. It is fixed here, before
any experiment, so that it cannot be relaxed once the numbers exist.

Run `python -m geryon.stats` to print the thresholds for each pair set.
