#!/usr/bin/env bash
#
# Build the environment the experiments run in, from nothing.
#
# The defence under test ships a fork of the benchmark and is configured through
# environment variables and two source patches. That is four moving parts, and
# while this project was being built the directory holding them was cleaned up by
# the system mid-experiment: the virtualenv was emptied and the fork's source
# partially deleted. Recovery took two minutes only because both patches were
# committed as scripts rather than applied by hand.
#
# This script exists so that recovery does not depend on anyone remembering. It is
# idempotent: run it again and it reuses what is already there.
#
#   ./scripts/setup_env.sh [target-directory]
#
# Then, for every run:
#   export OPENAI_API_KEY="$(cat ~/.bedrock-key)"
#   export OPENAI_BASE_URL="https://bedrock-mantle.eu-west-1.api.aws/v1"
#   "$TARGET/pgvenv/bin/python" scripts/run_condition.py --condition A ...
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-${GERYON_ENV:-$HOME/.geryon-env}}"
PROGENT_URL="https://github.com/sunblaze-ucb/progent.git"

say() { printf '\n== %s\n' "$*"; }

say "target: $TARGET"
mkdir -p "$TARGET"

# 1. The defence, which vendors its own copy of the benchmark. Pinned by nothing
#    upstream: the repository carries no tags and no LICENSE, so the commit that
#    was used is recorded in results/ alongside every run instead.
if [ -f "$TARGET/progent/agentdojo/src/agentdojo/__init__.py" ]; then
  echo "  progent already present"
else
  say "cloning progent"
  rm -rf "$TARGET/progent"
  git clone --depth 1 "$PROGENT_URL" "$TARGET/progent"
fi
echo "  commit: $(git -C "$TARGET/progent" rev-parse --short HEAD 2>/dev/null || echo unknown)"

# 2. A virtualenv holding the fork, the defence, and this package. Python 3.11:
#    the fork does not build on 3.12+.
if [ -x "$TARGET/pgvenv/bin/python" ]; then
  echo "  virtualenv already present"
else
  say "creating virtualenv"
  python3.11 -m venv "$TARGET/pgvenv"
fi
PY="$TARGET/pgvenv/bin/python"

say "installing"
"$PY" -m pip install -q --upgrade pip
(cd "$TARGET/progent/agentdojo" && "$PY" -m pip install -q -e .)
(cd "$TARGET/progent" && "$PY" -m pip install -q -e .)
(cd "$REPO" && "$PY" -m pip install -q --no-deps -e .)

# 3. The two patches. Both are needed to run this defence against models named the
#    way Bedrock names them, and both are meant to go upstream rather than be
#    carried here forever. Each keeps a .orig beside the file it edits.
say "patching progent"
(cd "$REPO" && "$PY" scripts/patch_progent_bedrock.py)
(cd "$REPO" && "$PY" scripts/patch_progent_prompts.py)

# 4. Prove the environment produces the numbers this project publishes, rather
#    than merely importing. A silent environment drift is the failure this whole
#    script exists to make impossible.
say "verifying"
(cd "$REPO" && "$PY" -m geryon.overlap --version v1.2 2>&1 | grep -v "Policy Model" | tail -6)
cat <<TXT

Expected, on Progent's vendored benchmark v1.2:
  banking 42/144   slack 19/105   travel 2/100   workspace 18/560   TOTAL 81/909

If those differ, the fork moved and every published number needs re-deriving.

Ready. Point runs at:
  $PY
TXT
