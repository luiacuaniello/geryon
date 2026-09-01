# Related work, and what is actually left open

Written so that the claim this project makes is the narrowest one the evidence
supports. Every number below is from the cited paper, not from us.

## The benchmark

**AgentDojo** (Debenedetti et al., ETH Zurich, NeurIPS 2024) is the environment.
This project consumes it and contributes back to it; it does not replace it.

## The defences under test

A second generation of defences moved enforcement outside the model: **CaMeL**
(ETH Zurich and Google DeepMind, arXiv:2503.18813), **FIDES** (Microsoft,
arXiv:2505.23643), **Progent** (arXiv:2504.11703), **RTBAS**, **FORGE**, and
**DRIFT**. They mediate each action with a policy and report near-elimination of
attacks on AgentDojo.

Code availability is uneven, and the milestone plan is ordered by it rather than
by which defence is most interesting:

| defence | public implementation | runs on AgentDojo | position in the plan |
|---|---|---|---|
| Progent | yes, with a proxy mode | yes | first defence |
| CaMeL | yes (`google-research/camel-prompt-injection`) | yes | second defence |
| DRIFT | evaluated by AutoDojo | yes | fallback second |
| FIDES | `microsoft/fides` is a tutorial notebook | not as published | not planned |
| RTBAS, FORGE | no implementation located | unknown | not planned |

Naming FIDES or RTBAS as a milestone deliverable without an implementation to run
would be a commitment we could not keep. They are listed here as surveyed, not as
targets.

## The methodological warning

**The Attacker Moves Second** (Nasr, Carlini, Tramèr et al., arXiv:2510.09023)
broke **twelve** published defences at over 90 percent attack success by tuning
and scaling general optimisation techniques against each defence. Those twelve
were in-band defences: the model, or a filter, deciding what to obey. This is the
evidence that static benchmarks mislead, and it is the reason an adaptive
protocol is worth writing down.

## The adaptive evaluations that already exist

Two, and both must be read before believing this project has anything to add.

### AutoDojo (arXiv:2606.15057, June 2026, code public)

An adaptive extension of AgentDojo that uses a frontier LLM to iteratively
optimise the injection against the specific defence. Nine defences, three suites,
five target models. Against a filter that reduces static attack success to 0
percent it recovers 28 percent overall and 64 percent on *action-open* tasks —
tasks where the user's request delegates the action itself to attacker-controlled
content.

This is a stronger attacker than anything in this repository, and its
action-open / param-open / fully-specified taxonomy is a close relative of the
within-policy restriction. Anyone evaluating this project should assume AutoDojo
has already answered the easy version of the question.

**What AutoDojo leaves open, precisely:**

1. Its system-level results barely move. On Progent, static to adaptive attack
   success across its five models runs 8.2 to 7.7, 1.8 to 1.5, 1.5 to 3.6, 2.8 to
   4.6, and 0.0 to 0.5 percent. The defence class this project targets is the one
   class its optimiser did not break.
2. Its second finding, that attack success is much higher on action-open tasks,
   is stated for prompt-level and filter-based defences. It is not established
   for the action-level class.
3. CaMeL appears in its related work, not in its evaluation.
4. Its measurement is over the whole pair set, which is dominated by pairs a
   tool-identity policy blocks for free. It does not report the restricted
   denominator.

### LaunchSafe (arXiv:2606.26479, June 2026)

A systematisation of out-of-band defences plus one experiment: Progent on
AgentDojo with Qwen2.5-7B, three runs, attack success 25.8 percent without the
defence, 4.2 percent with it, and 2.6 percent under a hand-crafted adaptive
attack. The defence held. The authors describe this themselves as "one
small-scale data point on a weak model with a single black-box attack template".

Two things follow, and both belong in any honest account of this project.

**It is not independent.** The paper states that the work guides LaunchSafe's own
agent-security tooling, built on the foundation it evaluates. The result may well
be correct; the structure is not neutral.

**They have announced this exact study.** The paper's closing line is: "The honest
next question we hand ourselves: can an adaptive attack that lives entirely within
the agent's authorized action space still get through? That is the next study."
This project is not picking up an abandoned question. It is proposing to do
publicly, and neutrally, something a company has said it will do privately, with
its own tooling downstream of the answer.

## What this project claims, after all of the above

Not that the action-level defences are broken. Not that nobody has run an adaptive
attack against them. Only this:

> The one adaptive evaluation that covers action-level defences measured them over
> a pair set dominated by attacks a tool-identity policy blocks for free, and the
> defences held. Nobody has reported the restricted denominator, and nobody has
> attacked the two components on which argument pinning actually rests: the model
> that decides what to pin, and the boundary at which a value stops being
> untrusted.

And one contribution that does not depend on the outcome at all: the within-policy
pair analysis (`results/within-policy-pairs.md`) shows that AgentDojo contains 85
usable pairs, of which travel's 6 cannot support any claim, and that the argument
level is empty. That is a statement about the *benchmark*, and it applies to every
evaluation built on it, including AutoDojo's and LaunchSafe's.

## Engagement

The authors of AutoDojo, Progent, CaMeL and AgentDojo are the recipients of
coordinated disclosure under `DISCLOSURE.md`, and of a public issue before any
result is published. Building on AutoDojo's optimiser rather than reimplementing
one is preferred wherever its licence permits; see `docs/adaptive-loop.md`.
