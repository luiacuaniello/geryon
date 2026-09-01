# What went wrong, and how it was caught

A project that measures whether other people's numbers mean what they appear to
mean owes an account of its own. This is the register: every wrong conclusion
reached while building the pilot, what it would have cost, and what caught it.

It is here rather than in a footnote because it is the honest answer to *"why
should we believe your numbers?"*. Not because the process was clean — it was
not — but because each error was found by a mechanism that is still in the
repository and still running.

---

## 1. A denominator error, in a project about denominator errors

**The claim.** Our defended attack success over the full banking suite was 29.2%
where the literature reports 0-8.2% for the same defence. Three to six times
worse. We wrote it into the proposal as an unexplained gap and started listing
candidate causes.

**What was wrong.** AutoDojo aggregates over *three* suites; we were quoting
banking alone, which is the suite most favourable to the attacker. Their own text
says so: attack success on one defence goes from 56.3% on banking to 15.2% on
slack and 8.6% on travel.

**Caught by** reading the paper before running anything else. Measured properly
over the same three suites the figure is 15.2% [11.8-19.4] — still above 8.2%,
but under a factor of two rather than six.

**Cost if missed.** The proposal would have led with a discrepancy that a reviewer
could dissolve in one sentence, in a project whose entire thesis is that averaging
over the wrong denominator misleads.

---

## 2. Three wrong diagnoses of the same bug, in a row

Progent's policy updates were failing. Finding out why took four attempts, three
of them wrong.

**First:** "it is the missing format instruction on the initial-generation prompt."
Tested with a two-tool prompt; both models scored 6/6 and the hypothesis looked
dead.

**Second:** "the models are fine, the hypothesis is dead." That measurement
counted `extract_json` returning `None` as a failure. `None` also means the model
correctly declined to update the policy — a legitimate outcome. Refusal and error
had been merged into one bucket.

**Third:** "found it, the update path." True, but the test that established it
still used a toy prompt. Only replaying a real prompt extracted from a saved log —
eleven tools, full schemas, 4128 characters — reproduced the failure: 5/5 parse
errors bare, 5/5 valid with the hint.

**Fourth:** the patch itself. It changed *both* prompt paths although only one had
been measured. The initial-generation path had been fine at 5/5 and went to 0/5.
The run died immediately, which was luck: a path that failed intermittently would
have produced plausible, wrong numbers.

**Caught by** replaying real inputs instead of synthetic ones, and by classifying
outcomes three ways instead of two. The lesson is now a comment in the patch
script: *patch what you measured, and nothing next to it.*

---

## 3. The log did not record the one thing logs are for

A condition-B run on travel died after 3782 lines of progress with no traceback.
The exception escaped the logging context manager, so Python printed it *after*
the streams were restored — into a shell whose output went to `/dev/null`.

The log existed precisely to explain failures, and for fatal ones it was the only
case where it could not.

**Caught by** noticing that a compressed log implies the context manager exited
cleanly, which an uncaught kill would not. The runner now prints the traceback
inside the capture, with a test that pins it. The next two failures were diagnosed
in seconds: `json.decoder.JSONDecodeError` on a malformed tool-call argument.

---

## 4. A guard that caused the failure it guarded against

A chained run had a safety condition — stop waiting if no run process exists, so a
dead upstream chain cannot hang the wait forever. Between one run finishing and
the next starting there is an instant when no such process exists. The guard read
that as "the chain is done", started early, and the run it started was killed by
contention.

**Caught by** the missing result file. The wait now keys on the artefact, not on
process liveness, which is not stable state.

---

## 5. One malformed reply destroying an hour of work

AgentDojo parses tool-call arguments with `json.loads` and lets a `JSONDecodeError`
propagate out of the benchmark. An agent that emits one bad escape on call 60 of
105 therefore ends the run. Two runs died this way.

**Fixed** with a per-pair mode: a pair that raises is recorded as skipped, with the
reason, and the run continues. A skipped pair is absent from both numerator and
denominator — never counted as a blocked attack. One pair of 348 was skipped in
the whole campaign.

---

## 6. An environment that deleted itself mid-campaign

The virtualenv, the vendored fork of the benchmark and both applied patches lived
in a system-managed temporary directory. It was cleaned while the work was in
progress: `pip list` came back holding two packages, and the fork's source was
partially gone.

**Recovery took two minutes**, because both patches were committed as scripts
rather than applied by hand. Rebuilding reproduced the published pair counts
exactly: 909 pairs, 81 within policy.

`scripts/setup_env.sh` now does that rebuild in one command and ends by
re-deriving those counts, so that a silently different environment fails loudly
instead of producing plausible numbers.

---

## What this list is not

It is not a claim that the results are shaky. Every number the proposal quotes
survived these corrections, and several exist *because* of them — the three-suite
aggregate, the policy-model confound control, the per-pair accounting.

It is a claim about method. Four of these six were caught by a mechanism built
before it was needed: provenance on every run, a log that survives the process, a
guard that refuses to compare runs that are not comparable, a setup script that
verifies rather than installs. The other two were caught by preferring a real
input to a convenient one.

That is the discipline this project proposes to apply to other people's
evaluations. It seemed only fair to show it applied to our own.
