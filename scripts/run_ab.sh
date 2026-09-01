#!/usr/bin/env bash
# Conditions A and B on the within-policy pairs of one suite, three repeats each.
#
# Run inside an environment where `agentdojo` resolves to Progent's vendored copy
# (see docs/running-progent.md). Each condition is its own process because
# Progent is configured through environment variables read at import time.
set -euo pipefail

SUITE="${SUITE:-banking}"
VERSION="${VERSION:-v1.2}"
REPEATS="${REPEATS:-3}"
# Progent's shipped run.sh sets SECAGENT_UPDATE=True. Run both settings; a number
# from only one of them describes that setting, not the defence.
UPDATES="${UPDATES:---policy-updates}"

# Default to Amazon Bedrock's OpenAI-compatible endpoint with an open-weight
# model. Open weights are not a detail: an evaluation nobody else can rerun is
# not an evaluation. Override MODEL/OPENAI_BASE_URL for any other provider.
MODEL="${MODEL:-openai.gpt-oss-120b}"
POLICY_MODEL="${POLICY_MODEL:-$MODEL}"

if [ -n "${AWS_BEARER_TOKEN_BEDROCK:-}" ]; then
  export OPENAI_API_KEY="$AWS_BEARER_TOKEN_BEDROCK"
  export OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://bedrock-mantle.${AWS_REGION:-eu-west-1}.api.aws/v1}"
  echo "using Bedrock at $OPENAI_BASE_URL"
fi
: "${OPENAI_API_KEY:?set AWS_BEARER_TOKEN_BEDROCK (Bedrock) or OPENAI_API_KEY}"

echo "== preflight =="
python scripts/patch_progent_bedrock.py
python scripts/check_bedrock.py --model "$MODEL"

for repeat in $(seq 1 "$REPEATS"); do
  echo "== condition A, repeat $repeat =="
  python scripts/run_condition.py --suite "$SUITE" --condition A --repeat "$repeat" \
    --model "$MODEL" --benchmark-version "$VERSION"

  echo "== condition B, repeat $repeat =="
  # shellcheck disable=SC2086
  python scripts/run_condition.py --suite "$SUITE" --condition B --repeat "$repeat" \
    --model "$MODEL" --policy-model "$POLICY_MODEL" --benchmark-version "$VERSION" $UPDATES
done

python scripts/analyse_runs.py --suite "$SUITE" --allow-incomplete
