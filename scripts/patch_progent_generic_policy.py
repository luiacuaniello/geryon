"""Let a run install the generic banking policy into Progent's AgentDojo suite.

The generic policy is stated in docs/generic-policy.md and defined in
src/geryon/generic_policy.py. This script adds a hook to the banking suite of
Progent's vendored AgentDojo, right after the suite allows its read-only tools:

    if os.getenv("GERYON_GENERIC_POLICY", "False") == "True":
        from geryon.generic_policy import install_into_progent
        install_into_progent()

The hook does nothing unless the variable is set, so runs that do not ask for the
generic policy are unaffected by the patch. ``run_condition.py --generic-policy``
sets it before AgentDojo is imported, which is when the suite reads it, and refuses
to start unless the rules are then in Progent's policy.

    python scripts/patch_progent_generic_policy.py           # apply
    python scripts/patch_progent_generic_policy.py --check   # report only
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path

MARKER = "    # within-policy: generic policy hook (docs/generic-policy.md)"
ANCHOR = '    update_always_allowed_tools(["get_most_recent_transactions"], allow_all_no_arg_tools=True)\n'
HOOK = f'''{MARKER}
    if os.getenv("GERYON_GENERIC_POLICY", "False") == "True":
        from geryon.generic_policy import install_into_progent
        install_into_progent()
'''
SUITE_FILE = Path("default_suites") / "v1" / "banking" / "task_suite.py"


def find_suite_file() -> Path:
    spec = importlib.util.find_spec("agentdojo")
    if spec is None or not spec.submodule_search_locations:
        raise SystemExit("agentdojo is not importable; activate Progent's environment first")
    path = Path(next(iter(spec.submodule_search_locations))) / SUITE_FILE
    if not path.exists():
        raise SystemExit(f"{path} not found; is this Progent's vendored AgentDojo?")
    return path


def patch(text: str) -> tuple[str, bool]:
    """Insert the hook after the line that allows the read-only tools. Idempotent."""
    if MARKER in text:
        return text, False
    if text.count(ANCHOR) != 1:
        raise ValueError("the anchor line is missing or not unique; the suite has changed")
    if "import os" not in text:
        raise ValueError("the suite no longer imports os, which the hook needs")
    return text.replace(ANCHOR, ANCHOR + HOOK), True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="report whether the hook is present, change nothing")
    args = ap.parse_args()

    path = find_suite_file()
    text = path.read_text()
    if MARKER in text:
        print(f"already patched: {path}")
        return 0
    if args.check:
        print(f"NOT patched: {path}")
        return 1

    patched, _ = patch(text)
    compile(patched, str(path), "exec")
    backup = path.with_suffix(".py.orig")
    if not backup.exists():
        backup.write_text(text)
    path.write_text(patched)
    print(f"patched: {path} (original kept as {backup.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
