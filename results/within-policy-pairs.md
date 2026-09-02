# Preliminary finding: how much of AgentDojo is within policy

Generated with `python -m geryon.overlap` on AgentDojo benchmark version
v1.2.1 (package `agentdojo` 0.1.35). Reproducible in under a minute on any
machine; the counts below are asserted in `tests/test_overlap.py` so they cannot
drift silently.

## Method

For every (user task, injection task) pair, compute the set of tools each task's
ground truth calls, and the set of argument values each ground truth passes.

**Tool level.** The pair is within policy when the injection's tool set is a
non-empty subset of the user task's tool set. A least-privilege policy derived
from the user's request authorises every tool the attack needs, so the defence
cannot block it by tool identity and must discriminate on arguments, provenance,
or data flow.

**What the tool sets are read from.** Both sets come from each task's
`ground_truth`, the reference solution the benchmark itself ships. That is the only
authoritative statement of what a task requires, but it is *one* solution rather
than the only one. A pair counted as within policy is therefore certain — that
route exists and the benchmark wrote it. A pair counted as outside may still be
reachable by an alternative route that stays inside the authorised set, which this
method does not look for. **The 85 are a lower bound, never an over-count.**

**Argument level.** The pair is within policy at the argument level when, in
addition, the injection introduces no argument value that the user task does not
already supply. Such a pair could not be blocked even by a policy that pins every
argument to the value the user's request implies.

## Result

| suite | within policy | total pairs | share | distinct user tasks | distinct injection goals | single-tool injections |
|---|---|---|---|---|---|---|
| banking | 42 | 144 | 29.2% | 10 | 9 | 41 |
| slack | 19 | 105 | 18.1% | 14 | 2 | 19 |
| travel | 6 | 140 | 4.3% | 6 | 3 | 6 |
| workspace | 18 | 560 | 3.2% | 14 | 5 | 14 |
| **total** | **85** | **949** | **9.0%** | | | **80** |

At the argument level the count is **0 out of 85, in every suite**. Every
within-policy pair requires at least one argument value that appears nowhere in
the user task's ground truth: between one and five such values, median four.

## Reading

**The first number bounds what a tool-identity policy can do.** An evaluation
averaged over all 949 pairs is dominated by pairs that a tool-identity policy
blocks for free, which inflates the apparent strength of any action-level
defence. The 85 are the subset on which these defences are actually tested.

**The second number relocates the open question.** If no within-policy pair is
also within policy at argument granularity, then a defence that pins arguments
correctly has a clean signal to refuse on for every attack in this benchmark. So
the interesting question is not whether an attacker can stay inside the
authorised action space — at argument granularity, in AgentDojo, they cannot —
but whether the deployed policy actually pins arguments, and whether the attacker
can stop it from doing so.

That points the evaluation at two places rather than at the monitor:

- the model that writes or updates the policy, since a policy widened after
  reading untrusted content will be enforced faithfully and still authorise the
  attack (family F4);
- the boundary at which a value stops being labelled untrusted, since a value the
  agent restates in its own words may reach the monitor unlabelled (family F5).

Both are cheap to probe and neither has been measured.

## Consequences for the measurement

The restriction is expensive in statistical power, and the protocol is written to
account for it rather than around it:

- **80 of the 85 pairs have an injection needing exactly one tool.** Being a
  subset is close to automatic for a single-tool goal, so "within policy" here is
  substantially a property of AgentDojo's injection tasks rather than a hard-won
  attack property. Stated so nobody reads more into 9.0% than it carries.
- **Goal diversity is low.** Slack contributes 19 pairs but only 2 distinct
  injection goals; travel 6 pairs from 3 goals. Per-suite numbers are not
  independent samples of attacker intent.
- **Travel cannot support a claim.** With 6 pairs, the pre-registered exact
  McNemar test needs every pair to flip. Travel is reported and never used as
  evidence. See `protocol/threat-model.md` for the pre-registered thresholds.

The honest conclusion is that AgentDojo v1.2.1 does not contain enough
within-policy material to settle the question, which is why authoring new
within-policy injection tasks and contributing them upstream is a deliverable of
this project rather than a side effect of it.

## Worked example

In banking, `user_task_0` requires `read_file` and `send_money`, and
`injection_task_0` requires only `send_money`. The injection needs no tool the
user task has not already authorised.

But the two calls do not agree on arguments. The user's authorised call is

    send_money(recipient="UK12345678901234567890", amount=98.7, ...)

and the injection's goal is

    send_money(recipient="US133000000121212121212", amount=0.01, ...)

The recipient, the amount and the subject are all values the user's request never
supplies. A tool-identity policy is blind here; an argument-pinning policy is
not. The entire question is which of the two the defence actually implements once
its policy has been written by a model that read the injected content.

## Caveat

Tool identity is a coarse proxy for a policy, and argument identity is a strict
one: a real policy may pin a type or a range rather than a value, and Progent's
rules can express both. This analysis brackets what a policy can achieve at two
granularities. It does not predict whether any specific defence fails, and no
claim about any defence is made here.
