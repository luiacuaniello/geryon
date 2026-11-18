#!/usr/bin/env bash
#
# Run the configurations of docs/generic-policy.md, with every check it states.
#
#   ./scripts/setup_env.sh ~/.geryon-env-0d7ea07
#   export OPENAI_API_KEY="$(cat ~/.bedrock-key)"
#   export OPENAI_BASE_URL="https://bedrock-mantle.eu-west-1.api.aws/v1"
#   ./scripts/run_fair_test.sh ~/.geryon-env-0d7ea07 [--check-only]
#
# --check-only stops after the checks and the dry runs, having spent nothing.
#
# Before anything is spent it checks the Progent commit, installs the
# generic-policy hook, lets Progent decide its six test calls, and dry-runs all
# four configurations. Then it runs repeat 1 of every configuration, then repeat
# 2, then repeat 3, so that a drift over the day does not fall on one
# configuration alone. A run whose file already exists is skipped, so an
# interrupted session resumes where it stopped. Last, it checks from their logs
# that the generic rules held, and applies the pre-registered analysis.
#
# About 8 dollars and 14 hours in all, judging by the August runs: a run of A
# takes 25 to 40 minutes, a run of B 60 to 100.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:?usage: run_fair_test.sh ENVIRONMENT-DIRECTORY (built by setup_env.sh)}"
PY="$TARGET/pgvenv/bin/python"
COMMIT=0d7ea07
OUT="results/runs-fair-test"
CONFIGURATIONS="A auto-approve generic auto-deny"
COMMON="--suite banking --all-pairs --pairs results/pairs-fork-v1.2.json"
: "${OPENAI_API_KEY:?export OPENAI_API_KEY first}"
: "${OPENAI_BASE_URL:?export OPENAI_BASE_URL first}"

say() { printf '\n== %s\n' "$*"; }

flags() {
  case "$1" in
    A) echo "--condition A" ;;
    auto-approve) echo "--condition B --approver auto-approve" ;;
    generic) echo "--condition B --approver auto-approve --generic-policy" ;;
    auto-deny) echo "--condition B --approver auto-deny" ;;
  esac
}

condition() { if [ "$1" = A ]; then echo A; else echo B; fi; }

cd "$REPO"

say "checking the environment"
ACTUAL="$(git -C "$TARGET/progent" rev-parse --short=7 HEAD)"
if [ "$ACTUAL" != "$COMMIT" ]; then
  echo "Progent is at $ACTUAL, not $COMMIT: build the environment with scripts/setup_env.sh" >&2
  exit 1
fi
"$PY" scripts/patch_progent_generic_policy.py
"$PY" scripts/check_generic_policy.py

say "dry-running every configuration (no model is called)"
for name in $CONFIGURATIONS; do
  # shellcheck disable=SC2046,SC2086
  if ! output="$("$PY" scripts/run_condition.py $COMMON --repeat 1 $(flags "$name") \
      --out-dir "$OUT/$name" --dry-run 2>&1)"; then
    echo "$output" >&2
    echo "  $name: the dry run failed, nothing was spent" >&2
    exit 1
  fi
  echo "  $name: ok"
done
if [ "${2:-}" = "--check-only" ]; then
  say "checks passed; nothing was run"
  exit 0
fi

for repeat in 1 2 3; do
  for name in $CONFIGURATIONS; do
    if [ -f "$OUT/$name/banking-$(condition "$name")-r$repeat.json" ]; then
      echo "  $name, repeat $repeat: already done"
      continue
    fi
    say "$name, repeat $repeat ($(date '+%H:%M'))"
    # shellcheck disable=SC2046,SC2086
    "$PY" scripts/run_condition.py $COMMON --repeat "$repeat" $(flags "$name") --out-dir "$OUT/$name"
  done
done

say "checking that the generic rules held in every run of that configuration"
for repeat in 1 2 3; do
  "$PY" -m geryon.generic_policy --check-log "$OUT/generic/banking-B-r$repeat.log.gz" || true
done

say "the pre-registered analysis"
"$PY" scripts/analyse_fair_test.py
