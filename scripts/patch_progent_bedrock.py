"""Teach Progent's vendored AgentDojo about Amazon Bedrock's open-weight models.

Why a patch is needed at all: AgentDojo validates `--model` against an enum, and
Progent's fork carries only hosted-API models plus one hardwired SecAlign entry.
Nothing about the *request path* needs changing, because both AgentDojo's `openai`
provider and Progent's own policy-model call construct a bare `openai.OpenAI()`,
which reads `OPENAI_BASE_URL` and `OPENAI_API_KEY` from the environment. Point
those at Bedrock's OpenAI-compatible endpoint and both the agent and the
policy-authoring model go to Bedrock.

So this only registers model ids. It is idempotent, and it prints the equivalent
change so it can be sent to Progent as a patch rather than carried privately.

    python scripts/patch_progent_bedrock.py            # apply
    python scripts/patch_progent_bedrock.py --check    # report only
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

# Open-weight models on Bedrock, served over the OpenAI-compatible endpoint.
# Open weights matter here: the evaluation has to be rerunnable by someone who
# does not have this AWS account.
NEW_MODELS = {
    "GPT_OSS_120B": "openai.gpt-oss-120b",
    "GPT_OSS_20B": "openai.gpt-oss-20b",
    # Larger open-weight models, used to answer "your agent model was too weak"
    # without giving up reproducibility. Each one was checked for tool calling
    # with check_bedrock.py before being added: AgentDojo drives the agent
    # entirely through function calls, and a model that answers in prose is
    # useless here however capable it is otherwise.
    "QWEN3_235B": "qwen.qwen3-235b-a22b-2507",
    "NEMOTRON_SUPER_120B": "nvidia.nemotron-super-3-120b",
    "MINIMAX_M25": "minimax.minimax-m2.5",
}
DISPLAY_NAME = "AI assistant"


def find_models_module() -> Path:
    spec = importlib.util.find_spec("agentdojo.models")
    if spec is None or not spec.origin:
        raise SystemExit("agentdojo is not importable; activate the environment first")
    return Path(spec.origin)


def missing_models(text: str) -> dict[str, str]:
    """Only the models not already registered, so the patch can be extended later."""
    return {name: mid for name, mid in NEW_MODELS.items() if mid not in text}


def already_patched(text: str) -> bool:
    return not missing_models(text)


def patch(text: str) -> str:
    todo = missing_models(text)
    enum_block = "".join(
        f'    {name} = "{model_id}"\n    """{model_id} on Amazon Bedrock"""\n'
        for name, model_id in todo.items()
    )
    text, n = re.subn(
        r"(\n    LOCAL = |\n    VLLM_PARSED = |\nMODEL_PROVIDERS)",
        "\n" + enum_block + r"\1",
        text,
        count=1,
    )
    if n != 1:
        raise SystemExit("could not find the end of ModelsEnum; patch by hand")

    providers = "".join(f'    ModelsEnum.{name}: "openai",\n' for name in todo)
    text, n = re.subn(
        r"(\nMODEL_PROVIDERS = \{(?:[^}]*))\}",
        r"\1" + providers + "}",
        text,
        count=1,
    )
    if n != 1:
        raise SystemExit("could not find MODEL_PROVIDERS; patch by hand")

    names = "".join(f'    "{model_id}": "{DISPLAY_NAME}",\n' for model_id in todo.values())
    text, n = re.subn(
        r"(\nMODEL_NAMES = \{(?:[^}]*))\}",
        r"\1" + names + "}",
        text,
        count=1,
    )
    if n != 1:
        raise SystemExit("could not find MODEL_NAMES; patch by hand")
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="report without writing")
    args = ap.parse_args()

    path = find_models_module()
    text = path.read_text()

    if already_patched(text):
        print(f"already patched: {path}")
        return 0
    if args.check:
        print(f"NOT patched: {path}")
        print("models that would be added: " + ", ".join(NEW_MODELS.values()))
        return 1

    backup = path.with_suffix(".py.orig")
    if not backup.exists():
        backup.write_text(text)
    path.write_text(patch(text))
    print(f"patched {path} (original kept at {backup.name})")
    print("added: " + ", ".join(missing_models(text).values()))
    print(
        "\nNothing else changes: AgentDojo's `openai` provider and Progent's\n"
        "policy-model call both build a bare openai.OpenAI(), so set\n"
        "  OPENAI_BASE_URL=https://bedrock-runtime.<region>.amazonaws.com/openai/v1\n"
        "  OPENAI_API_KEY=$AWS_BEARER_TOKEN_BEDROCK\n"
        "and both the agent and the policy model go to Bedrock."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
