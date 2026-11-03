# Roadmap

Milestones mirror the funding proposal, so that a reviewer reading both sees the
same plan and the same boundary between what exists and what is being asked for.

## Pilot — done, not funded

Built before any application and at no cost to any funder. It is the evidence
that the question is real and answerable, not a milestone to invoice.

- `protocol/` — threat model, the within-policy definition at tool and argument
  granularity, and the statistical test with its threshold fixed before any
  experiment was run
- `src/geryon/` — the pair analysis, the pre-registered statistics, the
  corpus loader, the seeded adaptive optimiser and its AgentDojo adapter, the
  run logger; 55 tests, CI on every push
- `scripts/` — the three-condition runner with full per-run provenance and cost
  metering, and an analysis that refuses to report incomparable runs
- `results/` — the pair counts (85 of the 609 classifiable pairs at tool level, 0
  at argument level) and the first measurements on the banking suite, including
  the raw logs

What the pilot does not have: more than one suite, more than one defence, and
more than one repeat of the decisive condition. That is where the funding starts.

## M1 Attack corpus, and new within-policy benchmark tasks

Attack cases as machine-readable data with a schema, a taxonomy, a written
rationale per case, and a pre-registered prediction, validated in CI.

Plus the part that outlasts the project: **new within-policy injection tasks
contributed upstream to AgentDojo**. The benchmark yields 85 usable pairs, 80 of
which need a single tool call, and slack contributes 19 pairs from only 2 distinct
injection goals. That is not enough material to settle the question, and fixing it
benefits every evaluation built on AgentDojo rather than only this one.

## M2 The first defence, properly

Progent in **both** of its policy-update configurations, all four suites, three
repeats each, with the pooled cross-suite analysis that the pair counts require:
six discordant pairs is 7.1 percentage points pooled against 14.3 on banking
alone, so pooling is what buys the power.

The pilot covers one suite, one configuration, and one repeat of condition C.
This is what turns it into a result.

## M3 The same measurement against a permission layer people actually run

The research prototypes are where the question was first posed. The pattern they
formalise is already deployed: MCP gateways and agent frameworks that mediate tool
calls against an allowlist, self-hosted today.

Two things make the finding transfer rather than merely analogise. The published
guidance for those systems converges on the same design as the prototypes — a
deterministic layer that checks identity, scope, target and **argument values** —
and argument values are exactly where the within-policy attacks live. And the pair
analysis needs no port: the restriction is defined over tool sets, which every one
of these layers has.

**A pilot was run, and its first reading was wrong.** One such gateway uses
Cedar, a policy language that can express conditions on arguments. Its shipped
schema and, at the time, its specification described a Cedar context without the
call's arguments, and the pilot concluded that no policy could condition on them.
The code passed them all along: re-tested on 2026-11-03, one added rule refuses
the payment to the attacker's account and lets the legitimate one through, on the
version the pilot ran and on the current one (`results/cmcp-pilot/`). What
survives is narrow. The example policy does not look at arguments, so a gateway
configured from it refuses tools by name and nothing more.

A second gateway, the most widely used in this space, was read rather than run:
its 626-line access-control specification has no construct for constraining a
permitted tool's arguments. After the first pilot, a reading of a specification
counts as unverified until it is tested on a running gateway.

The milestone is therefore to measure rather than read: several layers, each run
with a policy that tries to constrain arguments, the pair restriction ported, the
pre-registered analysis applied, and each result reported to its maintainers
before it is published.

Target selection follows the same discipline as the defences in
`docs/related-work.md`: chosen by implementation availability and declared in
advance. What is measured is the gap between what a policy can express, what the
integration passes to it, and what the policies people actually deploy say. None
of it is a criticism of any one project.

This is the milestone that makes the work a testing tool for software that is
running, rather than an evaluation of research artefacts. Anything found goes to
the maintainers under `DISCLOSURE.md`, unchanged.

## M4 Second research defence, and the boundaries the evidence points at

CaMeL as the second defence, with DRIFT as the declared fallback. FIDES and RTBAS
are not planned: no runnable AgentDojo implementation was located, and promising
one would be a commitment that could not be kept (`docs/related-work.md`).

Then the two analyses the pilot's evidence points at:

- the **policy-authoring step**, the one non-deterministic component of an
  otherwise deterministic defence — in one arm, 91 of 270 installed policies
  named the attacker's account as a permitted recipient, read structurally
  (family F4);
- **initial provenance assignment**, the trusted base of every labelling scheme,
  under-specified in all systems surveyed (family F5).

## M5 Report, disclosure, release

Coordinated disclosure to the defence authors, then the public report whatever
the results are, plus documentation and archival release. Negative results are
published on the same schedule as positive ones.

## Explicit non-goals

White-box optimised attacks. Building a new defence. Producing a product.
Human-subject studies, which the endorsement-targeting family would require.
Reimplementing an adaptive search that already exists in public.

## Known risks

The field moves fast and the LaunchSafe authors have publicly stated this exact
study is their next one. The durable artefacts are therefore the protocol, the
restricted-denominator analysis, the corpus and the upstream benchmark tasks —
none of which is invalidated by someone else publishing numbers first.
