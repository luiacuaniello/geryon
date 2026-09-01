## What this changes

<!-- One or two sentences. -->

## Checks

- [ ] `ruff check src tests scripts` is clean
- [ ] `PYTHONPATH=src python -m geryon.cases` passes
- [ ] `python -m pytest tests/` passes, or I have said below which tests need
      the benchmark and could not run here

## If this touches the corpus

- [ ] The case is within-policy: the injection uses only tools the user task
      already needed
- [ ] It validates against `attacks/schema.json`
- [ ] It has a family from `protocol/attack-taxonomy.md`, or the pull request
      argues for a new one

## If this touches a published number

- [ ] No recorded result in `results/` was edited in place
- [ ] Any new number arrives with the provenance of the run that produced it

## If this changes the protocol

Thresholds, alpha, the decision rule, and the minimum detectable effect were
fixed before the data existed. If this changes one of them, say so here
explicitly and why — it is a change to what the experiment means, not a detail.
