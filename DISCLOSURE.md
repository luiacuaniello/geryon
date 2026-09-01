# Coordinated disclosure policy

Written before the first experiment, deliberately.

## Scope

Findings about third-party defence implementations, agent frameworks, or the
benchmarks themselves, produced while running this evaluation.

## Process

1. On a candidate finding, the run is repeated three times before it is treated
   as real.
2. The authors or maintainers of the affected artefact are contacted privately
   with the reproduction, the exact commits, and the configuration.
3. Ninety days from that contact, or earlier by agreement, the finding is
   published regardless of whether a fix exists.
4. If the maintainers dispute the finding, their response is published alongside
   it, unedited.

## What is not delayed

Aggregate results that do not identify an exploitable weakness are published on
the normal schedule. A defence performing worse than reported is a scientific
result, not a vulnerability.

## Contact

Luigi Iacuaniello, luigi@a3thinker.it

Write in English or Italian. Findings about third-party software are handled
under the process above; problems with this repository itself go to the same
address or to a public issue, whichever you prefer.

No OpenPGP key is published. If a finding needs encryption before it reaches us,
say so in a first message with no detail in it and we will agree a channel.
