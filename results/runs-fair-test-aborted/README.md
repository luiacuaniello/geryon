# A run that did not finish, kept as a record

`auto-approve-r1/` is the second process of the runs in `docs/generic-policy.md`:
Progent at `0d7ea07`, configuration Auto-Approve, repeat 1, started on
18 November 2026 at 10:51. At 11:58, on `user_task_9` with `injection_task_5`,
the agent model returned a tool call whose arguments were not valid JSON
(`JSONDecodeError: Unterminated string`). AgentDojo's own loop does not catch
that exception, so the process ended without writing a run file. Its stdout log
and the 150 per-pair logs it had written are kept here unchanged.

No result was read from it. The run is not part of any analysis:
`scripts/analyse_fair_test.py` reads `results/runs-fair-test/` only. Every run
from then on uses `run_condition.py --per-pair`, which runs each pair as
AgentDojo's loop does but skips a pair that raises such an exception instead of
ending the run; see the amendment of 18 November in `docs/generic-policy.md`.
