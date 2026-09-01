# Geryon

> *"La faccia sua era faccia d'uom giusto,*
> *tanto benigna avea di fuor la pelle,*
> *e d'un serpente tutto l'altro fusto"*
>
> — Dante, *Inferno* XVII, on Geryon, the beast of fraud

Geryon wears the face of a just man. So does an attack that reaches the
attacker's goal using only actions the agent was already authorised to take: it
asks for no new tool, so a least-privilege policy sees nothing out of place.

Those attacks are **9% of the standard benchmark**, and nobody reports a number
on them. This is the instrument that does.

## The question

A second generation of defences moved enforcement outside the model: CaMeL,
FIDES, Progent, RTBAS, DRIFT, FORGE. They report near-elimination of prompt
injection on AgentDojo. Most of those numbers come from a static benchmark whose
attacks were fixed before the defence existed.

That methodology already failed once. Twelve published in-band defences reported
near-zero attack success and were later broken above 90 percent by adaptive,
defence-aware attackers (arXiv:2510.09023).

Two adaptive evaluations of the action-level class now exist — AutoDojo
(arXiv:2606.15057) and LaunchSafe (arXiv:2606.26479) — and in both, the
action-level defences held. **This project does not claim they are broken.**
It claims something narrower and checkable: both measured over a pair set
dominated by attacks that a tool-identity policy blocks for free, and neither
attacked the components on which argument-level enforcement actually rests.

`docs/related-work.md` states the claim, and its limits, in full.

## Two findings, before any experiment

Run `python -m geryon.overlap` and reproduce both in under a minute.

**85 of 949 AgentDojo pairs are within policy at the tool level.** The injection's
required tools are a subset of the user task's, so a least-privilege policy
authorises everything the attack needs. Evaluations averaged over all 949 pairs
are dominated by the other 864, which any tool-identity policy blocks for free.

**0 of 85 are within policy at the argument level.** Every one of them needs at
least one argument value the user's request never supplies — between one and five,
median four. A policy that pins arguments has a clean signal to refuse on for
every attack in this benchmark.

The second finding is the more useful one, because it relocates the question. It
is not "can the attacker stay inside the authorised action space" — at argument
granularity, in AgentDojo, they cannot. It is **"does the deployed policy actually
pin arguments, and can the attacker stop it from doing so"**, which points at the
model that writes the policy and at the boundary where a value stops being
labelled untrusted. Neither has been measured.

See `results/within-policy-pairs.md`.

## Status

A working pilot. The protocol, the statistics, the corpus, the three-condition
harness and its adaptive optimiser all exist and are tested; the first
measurements are in `results/`, on one suite against one defence.

What it does not have yet: more than one suite, more than one defence, and more
than one repeat of the decisive condition. See `ROADMAP.md` for the boundary
between what is done and what is not.

## What is here

- `protocol/` the threat model, the pre-registered analysis, and the attack
  taxonomy, all written before any experiment is run
- `src/geryon/overlap.py` computes which AgentDojo pairs are within policy,
  at tool and at argument granularity
- `src/geryon/stats.py` the pre-registered test, with no dependency beyond
  the standard library so every published number can be recomputed by hand
- `attacks/` attack cases as data, one directory per case, schema-validated in CI
- `docs/related-work.md` what already exists and what is genuinely left
- `docs/what-went-wrong.md` every wrong conclusion reached while building this,
  and the mechanism that caught it
- `docs/adaptive-loop.md` what "adaptive" is allowed to mean here, and its budget
- `docs/running-progent.md` how to run the three-condition comparison, with the
  environment traps found by actually cloning Progent
- `scripts/run_condition.py` runs one condition and records its full provenance;
  `scripts/analyse_runs.py` applies the pre-registered test and refuses to report
  if the runs are not comparable; `scripts/check_bedrock.py` is the preflight that
  proves tool calling works before anything is spent
- `results/` findings, including negative ones

## The environment the experiments run in

The defence under test vendors its own fork of the benchmark and needs two source
patches to accept Bedrock-named models. `scripts/setup_env.sh` builds all of it
from nothing and then verifies that the pair counts still come out right:

```bash
./scripts/setup_env.sh            # into ~/.geryon-env by default
```

It is idempotent, and it ends by re-deriving the published pair counts. If they
differ, the fork moved and every number here needs re-deriving — which is the
point of checking rather than merely importing.

## Install and check

```bash
pip install -e ".[dev]"
python -m geryon.overlap     # the two findings
python -m geryon.cases       # validate the attack corpus
python -m geryon.stats       # the pre-registered thresholds
pytest
```

`geryon.cases` and `geryon.stats` need only `pyyaml` and
`jsonschema`; AgentDojo is required for the pair analysis alone.

The corpus lives in a top-level `attacks/` directory rather than inside the
package, because it is data meant to be read and argued with. An editable install
finds it by walking up from the package; a non-editable install cannot, and says
so with the fix rather than failing obscurely. Set `GERYON_CASES` to point
at a corpus directory anywhere.

## The threshold, fixed in advance

With 85 pairs, a difference of one or two is several percentage points, so the
test is a two-sided exact McNemar on paired outcomes and the bar is **six pairs
flipping in one direction** (five gives p = 0.0625). On travel's six within-policy
pairs no claim is reachable at all; travel is reported and never used as evidence.
Fixed in `protocol/threat-model.md` before any run, so it cannot be relaxed later.

## What this is built on

The benchmark, the defences under test, and the two evaluations this work sits
next to. `docs/related-work.md` says what each one leaves open and why that
matters here.

**The benchmark**
- [AgentDojo](https://github.com/ethz-spylab/agentdojo) — Debenedetti et al.,
  ETH Zurich, NeurIPS 2024. Every pair count here is computed on it, and M1
  contributes tasks back to it.

**The defences**
- [Progent](https://arxiv.org/abs/2504.11703) — Shi, He, Wang, Li, Wu, Guo, Song
  (Berkeley), April 2025. The one measured here; code at
  [sunblaze-ucb/progent](https://github.com/sunblaze-ucb/progent).
- [CaMeL](https://arxiv.org/abs/2503.18813) — Debenedetti et al., ETH Zurich and
  Google DeepMind, March 2025. Planned second defence.
- [FIDES](https://arxiv.org/abs/2505.23643) — Costa, Köpf et al., Microsoft,
  May 2025. Surveyed; no runnable benchmark integration located.

**The methodological precedent**
- [The Attacker Moves Second](https://arxiv.org/abs/2510.09023) — Nasr, Carlini,
  Tramèr et al., October 2025. Twelve published defences, each reporting near-zero
  attack success, broken above 90% by adaptive attackers. The reason evaluating
  the next generation adaptively is worth doing at all.

**The two adaptive evaluations that already exist**
- [AutoDojo](https://arxiv.org/abs/2606.15057) — Ma et al., June 2026, code
  public. A stronger attacker than the one here, over nine defences. Its
  system-level results barely move, it reports no restricted denominator, and its
  finding about under-specified tasks is stated for prompt-level and filter-based
  defences rather than the action-level class. Those gaps are what this project
  takes.
- [LaunchSafe](https://arxiv.org/abs/2606.26479) — Narisetty et al., June 2026.
  Systematises the out-of-band defences and runs one Progent experiment, which
  the authors themselves call "one small-scale data point on a weak model with a
  single black-box attack template". Its closing line announces this exact study
  as their next one.

**The deployed layer**
- [cMCP](https://github.com/agentrust-io/cmcp) — MCP gateway with a Cedar policy
  engine. Measured by execution; see `results/cmcp-pilot/`.
- [mcp-gateway-registry](https://github.com/agentic-community/mcp-gateway-registry)
  — the most widely used open-source MCP gateway. Read, not run.

## Scope

In: black-box attacks within the authorised action space; the policy-authoring
step; provenance assignment boundaries; open-source defences with a runnable
implementation.

Out: white-box gradient attacks such as GCG. They require a different skill set
and are named here so nobody assumes coverage that does not exist. Also out:
human-subject work, which the endorsement-targeting family would require.

## Licence

Apache-2.0.
