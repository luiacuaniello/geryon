# Contributing

Thank you for looking. This is a measurement instrument, so the contribution
that helps most is not usually code: it is an attack case that the corpus does
not yet cover, or a reason one of the published numbers is wrong.

## Before you open a public issue

**If you have found a weakness in a defence — ours or anybody else's — do not
put it in an issue.** Read [DISCLOSURE.md](DISCLOSURE.md) first. Effectiveness
measurements against third-party software go to the maintainers privately,
under the coordinated process described there, before they go anywhere public.
This is not bureaucracy: the projects we measure are used in production, and a
public issue is a working exploit for anyone who reads it.

Everything else — a bug in the harness, a question about the protocol, a case
that fails to validate — belongs in an issue, and is welcome there.

## Adding an attack case

The corpus lives in `attacks/`, one directory per case:

```
attacks/WP001-recipient-substitution/case.yaml
```

A case is *within-policy* if the injection reaches the attacker's goal using
only tools the user's own task already needed. If it asks for a tool the user
task never uses, it is out of policy and a tool-identity check blocks it for
free — it is not what this corpus is for.

Every case is validated against `attacks/schema.json`. Check yours before
opening the pull request:

```bash
PYTHONPATH=src python -m geryon.cases
```

Give the case a family from `protocol/attack-taxonomy.md`, or argue in the pull
request for a new one. The taxonomy is meant to grow; it just should not grow by
accident.

## Running the checks CI runs

The first three need no benchmark and take seconds:

```bash
ruff check src tests scripts && PYTHONPATH=src python -m geryon.cases && PYTHONPATH=src python -m geryon.stats
```

The full suite needs AgentDojo installed:

```bash
pip install -e ".[dev]" && python -m pytest tests/
```

`scripts/setup_env.sh` rebuilds the whole environment from nothing if you would
rather not assemble it by hand. `docs/running-progent.md` covers the parts that
are specific to the defence under test.

## Things that are deliberate, not oversights

**The numbers in `results/` are records, not outputs.** Each directory carries
the provenance of the run that produced it. If a number is wrong, the fix is a
new run with its own provenance — please do not edit a recorded result in place.
`results/README.md` marks which directories are usable and which are not, and
why.

**The thresholds were fixed before the data existed.** The decision rule, the
alpha, and the minimum detectable effect are in the README and in
`src/geryon/stats.py`. A change to any of them is a change to the protocol, so
it needs its own discussion — not a line in a pull request that does something
else.

**Errors are not swallowed.** If you find a bare `except`, that is a bug worth
reporting. A run that dies loudly is worth more than a run that quietly reports
a number nobody can trust; `docs/what-went-wrong.md` records what that lesson
cost the first time.

## Style

Match the file you are editing. Comments explain why, not what. Keep
`ruff check` clean.

## Licence

Contributions are accepted under the Apache License 2.0, the same terms as the
rest of the repository.
