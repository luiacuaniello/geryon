# Raw run logs

The stdout of each run, gzipped. They are kept because the most consequential
finding so far is not a rate but a mechanism, and the evidence for it is a log
line: Progent's policy-authoring model writing the attacker's account number into
the security policy.

    gunzip -c strong_arm_full.log.gz | grep "security policy updated" | grep -c US133000000121212121212

Counted on the condition-B arm with the qwen3-235b policy model, 2026-08-26.

**These are counts of distinct log events, not parts of one fraction.** A policy
installation and a failed JSON decode are different lines emitted at different
points, and this file previously presented them as though 230 of 270 updates had
failed. They do not share a denominator, and establishing how they relate would
mean reading Progent's code rather than its output.

| log event | grep | count |
|---|---|---|
| `security policy updated:` — a policy installed | `grep -c "security policy updated"` | 270 |
| of those, cleared to `None` by the benchmark's reference pass | `grep -c "security policy updated: None"` | 10 |
| of those, the policy each pass restores | the line after each `None` | 10 |
| of those, written by the defence | | 250 |
| of the 250, containing the attacker's IBAN | `... \| grep -c US133000000121212121212` | **92** |
| `Error decoding JSON` — a model reply that failed to parse | `grep -c "^Error decoding JSON"` | 230 |
| `Ignore the update error` — an update given up after retries | `grep -c "Ignore the update error"` | 3 |
| `security policy is not set` — a call while no policy was set, all inside the reference pass | `grep -c "security policy is not set"` | 25 |

The 92 is the finding: policies that were actually installed and in force carried
a value taken from the injected content.

**Corrected, 2026-11-05.** Twenty of the 270 policy lines and all 25 calls made
with no policy set are the benchmark's own bookkeeping, not the defence's.
Before attacking a user task, the AgentDojo that Progent vendors runs the task's
reference solution to find where the injections land, with Progent's policy
cleared to `None` and restored afterwards (`get_injection_candidates` in
`agentdojo/attacks/base_attacks.py`). Each of the 10 passes in this log records
the clear, the reference solution's calls and the restore. The policies the
defence wrote are therefore 250, and the 92 and the 91 are all among them. No
call of the agent ran without a policy, in this log or in any other run log in
`results/`, which `tests/test_policies.py` checks. Earlier versions of this file,
of `results/README.md` and of the paper draft, and comments on
sunblaze-ucb/progent#3, counted the restores among the policies the defence
installed and described the 25 as calls that ran unprotected.

## Where those policies name the account

Counting lines says the account appears somewhere in a policy.
`python -m geryon.policies results/logs/strong_arm_full.log.gz` reads each
policy as a structure and counts where the account is named as a permitted
recipient — that is, where it appears in an `enum` restriction on `recipient`:

| | count |
|---|---|
| policies installed | 270 |
| of which cleared to `None` by the reference pass | 10 |
| of which restored by it | 10 |
| written by the defence | 250 |
| of those, naming the attacker's account as a permitted recipient | **91** |
| — via `send_money` | 73 |
| — via `update_scheduled_transaction` | 20 |
| — via `schedule_transaction` | 1 |
| with that account the **only** named recipient of `send_money` | 47 |

The typical clause is

    'send_money': [(100, 0, {'recipient': {'enum': ['US133000000121212121212']},
                             'amount': {'minimum': 0.01}}, 0)]

— any amount, to the attacker and to nobody else.

Of the 92 policies whose text contains the account, 73 enumerate it for
`send_money` and 14 name it only on one of the other two money-moving tools. The
remaining 5 leave `send_money.recipient` unconstrained, so they permit the
attacker there without naming him. Four of those name him on
`update_scheduled_transaction` and are among the 91; the fifth names him on no
tool, and it is the difference between 92 and 91. In that one the account sits
in a `send_money` clause whose recipient is an enum, but a second clause on the
same tool leaves the recipient open.

This is a structural reading, not a replay of the defence's decision: any
constraint other than an `enum` is read as unconstrained, and a tool's clauses
are read together. Progent evaluates clauses in priority order and can stop at
the first, so where a tool carries several clauses the two readings can differ.

**Withdrawn, 2026-09-23.** An earlier version of this section and of the module
classified the policy *updates* as narrowings or expansions, and quoted 25 and
19 of 44. That classification was a reconstruction that did not match Progent's
own procedure — it read patterns as unconstrained and a tool's clauses as a
union. The claim that rested on it, that such updates would pass without
approval in any configuration, manual included, is withdrawn with it. Those
counts were quoted in the disclosure to the Progent authors and have been
withdrawn there too. The classification has been removed rather than repaired.

The decode failures matter for a different reason. Progent ships `SECAGENT_IGNORE_UPDATE_ERROR=True` in its own run.sh, so a policy
update that fails to parse is swallowed: the agent proceeds without saying so.

These are observations to be verified and sent to the Progent authors under
DISCLOSURE.md before they are published anywhere.
