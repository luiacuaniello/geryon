"""The hook that lets a run install the generic policy into Progent's banking suite."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "patch_progent_generic_policy", ROOT / "scripts" / "patch_progent_generic_policy.py")
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)

#: The end of the vendored banking task_suite.py at Progent commits 8a8eb89 and b02783b.
SUITE_TAIL = '''import os

suite = os.getenv('SECAGENT_SUITE', None)
if suite != "banking":
    task_suite = TaskSuite("banking", BankingEnvironment, [])
else:
    task_suite = TaskSuite("banking", BankingEnvironment, [])
    update_always_allowed_tools(["get_most_recent_transactions"], allow_all_no_arg_tools=True)
'''


def test_hook_goes_after_the_read_only_tools_and_compiles():
    patched, changed = patcher.patch(SUITE_TAIL)
    assert changed
    assert patched.index("allow_all_no_arg_tools=True") < patched.index("install_into_progent()")
    assert 'os.getenv("GERYON_GENERIC_POLICY", "False") == "True"' in patched
    compile(patched, "task_suite.py", "exec")


def test_patching_twice_changes_nothing():
    once, _ = patcher.patch(SUITE_TAIL)
    twice, changed = patcher.patch(once)
    assert not changed and twice == once


def test_a_changed_suite_is_refused_rather_than_guessed():
    with pytest.raises(ValueError):
        patcher.patch(SUITE_TAIL.replace("allow_all_no_arg_tools=True", "allow_all_no_arg_tools=False"))
