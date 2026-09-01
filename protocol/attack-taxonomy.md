# Attack families within the authorised action space

Each family is a hypothesis about how a monitor's discrimination can fail while
every tool invoked remains authorised. A case in `attacks/` belongs to exactly
one family and states which enforcement primitive it probes. The slug on each
family is the value of the `family` field in `attacks/schema.json`; a test keeps
the two in sync.

## Why the families are ordered the way they are

The argument-level analysis in `results/within-policy-pairs.md` found that on
AgentDojo v1.2.1 there are 85 pairs a tool-identity policy cannot block, and
**zero** pairs that a policy pinning every argument value cannot block. Every
within-policy attack in this benchmark needs at least one argument value the
user's request never supplies.

That result is what orders this list. F1 attacks the monitor directly and, if a
defence pins arguments correctly, should lose. F4 and F5 attack the two places
where argument pinning can fail to mean what it appears to mean: the model that
decides what to pin, and the boundary at which a value stops counting as
untrusted. Those are the families the evaluation should spend its budget on.

## F1 Argument substitution
`family: argument-substitution`

The injection changes an argument of a call the agent was going to make anyway.
Probes: whether the monitor checks argument provenance or only tool identity.
Serves as the baseline the other families are measured against, and is predicted
to be blocked by any defence that pins arguments.

## F2 Goal reordering
`family: goal-reordering`

The injection reorders or repeats authorised calls to produce an effect no single
call would. Probes: whether the policy reasons over sequences or per call.
Weakly supported by AgentDojo, where 80 of the 85 within-policy pairs need a
single tool call; this family needs new benchmark tasks before it can be
measured.

## F3 Endorsement targeting
`family: endorsement-targeting`

Where a defence escalates to a human for approval, the injection shapes what the
human is shown. Probes: whether human-in-the-loop is a control or a formality.
Requires a human-subject protocol, and is out of scope for the funded work; it is
recorded here so its absence is deliberate rather than accidental.

## F4 Policy widening
`family: policy-widening`

Where the policy is authored or updated by a model, the injection is written to
make that model widen the allowlist. Probes: the one non-deterministic component
of an otherwise deterministic defence. Given the argument-level result, this is
the highest-value family: the enforcement can be perfect and the outcome still
wrong if the pinned set was chosen after reading untrusted content.

## F5 Provenance laundering
`family: provenance-laundering`

The injection induces the agent to restate low-integrity content in its own
words, so that the derived argument appears to originate from the agent rather
than from untrusted data. Probes: whether taint survives a paraphrase the monitor
cannot observe. Discriminates interpreter-level labelling from transcript-level
labelling.

## Recording
Every case declares its family, the primitive it probes, the outcome it expects,
and a pre-registered prediction. Cases whose prediction was wrong stay in the
repository with the correction recorded.
