"""Make Progent's model-specific prompt hints reach Bedrock model ids.

Progent adapts its policy prompts per model, checking the model name's prefix:
`Qwen/`, `meta-llama/`, `gemini`, `claude`, `gpt-4o-mini`, `o1`, `o3`, `gpt-4.1`.
Open-weight models get an explicit instruction to wrap the policy in a json code
block, because without it they emit the restriction objects comma-separated with
no enclosing array and the parser fails on the second one.

This applies to the policy *update* path only. Measured on the real banking
prompt, 2026-08-26/27:

    update path,  bare      parse error 5/5      <- the defect
    update path,  hinted    valid JSON  5/5      <- what this patch fixes
    initial path, bare      valid JSON  5/5      <- already fine
    initial path, hinted    parse error 5/5      <- adding the hint here breaks it

The initial path is therefore left alone. The first version of this patch changed
both and killed a run outright.

Bedrock names the same models differently — `qwen.qwen3-235b-a22b-2507`,
`openai.gpt-oss-120b` — so none of those prefixes match and the hint is never
added. Measured on the real banking prompt, 2026-08-26:

    qwen3-235b, bare prompt        parse error 5/5
    qwen3-235b, with the hint      valid JSON  5/5

and in a full condition-B arm that ran without it the log carries 227 JSON decode
failures, alongside 270 installed policies and 25 tool calls made with no policy
set. Those are counts of distinct log events, not one fraction: see
results/logs/README.md. Progent's shipped configuration sets
SECAGENT_IGNORE_UPDATE_ERROR=True, so every decode failure was silent.

This is a defect in Progent, not in the models: its own code anticipates that
open-weight models need the hint. The patch belongs upstream; see
outreach/02-progent.md.

    python scripts/patch_progent_prompts.py           # apply
    python scripts/patch_progent_prompts.py --check   # report only
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

MARKER = "    # within-policy: Bedrock ids do not match Progent's prefix checks"

#: Inserted into both get_SYS_PROMPT and get_SYS_PROMPT_2. Deliberately reuses the
#: exact wording Progent already applies to Qwen and Llama rather than inventing a
#: better one: the point is to give Bedrock-named models the treatment Progent
#: already decided they need, not to improve the defence while measuring it.
_FMT = '[{{\\"name\\": tool_name, \\"args\\": restrictions}}, ...]'
_PREFIXES = '("qwen.", "openai.gpt-oss", "nvidia.", "minimax.", "mistral.", "zai.")'

PATCH_1 = f'''{{marker}}
    if policy_model.startswith({_PREFIXES}):
        output_formater = (
            "\\nOutput format: ```json " + "{_FMT}" + " ```"
        )
'''

PATCH_2 = f'''{{marker}}
    if policy_model.startswith({_PREFIXES}):
        sys_prompt = sys_prompt[:-1]
        output_formater = (
            " with json code block. It should be an array of dictionaries like "
            + "{{{{\\"name\\": tool_name, \\"args\\": restrictions}}}}."
        )
'''

#: Only the *update* path. The initial-generation path was measured on the real
#: banking prompt and already produced valid JSON 5 times out of 5 without any
#: hint; adding one broke it 5 times out of 5. Patch what you measured, and
#: nothing next to it.
TARGETS = [
    ("def get_SYS_PROMPT_2()", PATCH_2),
]


def find_tool_module() -> Path:
    spec = importlib.util.find_spec("secagent.tool")
    if spec is None or not spec.origin:
        raise SystemExit("secagent is not importable; activate the environment first")
    return Path(spec.origin)


def patch(text: str) -> tuple[str, int]:
    """Insert the hook just before each function's return.

    The anchor is the *whole return line including its indentation*. Anchoring on
    the bare `return` leaves its leading spaces attached to the inserted block and
    dedents the return itself to column zero, which is a SyntaxError rather than a
    subtly wrong patch — but only once the module is imported.
    """
    applied = 0
    anchor = "    return sys_prompt+output_formater"
    for func, snippet in TARGETS:
        start = text.index(func)
        end = text.index(anchor, start)
        if MARKER in text[start:end]:
            continue
        block = snippet.format(marker=MARKER)
        text = text[:end] + block + text[end:]
        applied += 1
    return text, applied


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    path = find_tool_module()
    text = path.read_text()
    already = text.count(MARKER)

    if already >= len(TARGETS):
        print(f"already patched: {path}")
        return 0
    if args.check:
        print(f"NOT patched ({already}/{len(TARGETS)} hooks present): {path}")
        return 1

    backup = path.with_suffix(".py.orig")
    if not backup.exists():
        backup.write_text(text)
    new, applied = patch(text)
    path.write_text(new)
    print(f"patched {path}: {applied} prompt hook(s) added (original at {backup.name})")
    print("Bedrock-named open-weight models now get the json-code-block instruction "
          "that Progent already gives to Qwen/ and meta-llama/ ids.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
