"""The runner sets the environment each of Progent's approver configurations needs.

In the vendored AgentDojo the policy update runs only when SECAGENT_UPDATE is
"True", so Auto-Deny needs it as well as SECAGENT_ONLY_ALLOW_NARROW; with updates
off the configuration is Disable Update, whatever the narrow-only variable says.
"""

from __future__ import annotations

import importlib.util
from argparse import Namespace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _runner():
    spec = importlib.util.spec_from_file_location("run_condition", ROOT / "scripts" / "run_condition.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run_condition = _runner()
VARIABLES = ("SECAGENT_SUITE", "SECAGENT_UPDATE", "SECAGENT_ONLY_ALLOW_NARROW", "GERYON_GENERIC_POLICY")


def _configure(monkeypatch, approver, generic=False):
    for name in VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SECAGENT_ONLY_ALLOW_NARROW", "True")  # a stale value must not leak through
    args = Namespace(condition="B", suite="banking", policy_model="m", approver=approver,
                     generic_policy=generic)
    return run_condition.configure_environment(args)


@pytest.mark.parametrize(
    ("approver", "update", "narrow"),
    [("auto-approve", "True", None), ("auto-deny", "True", "True"), ("disable-update", "False", None)],
)
def test_each_approver_sets_what_it_needs(monkeypatch, approver, update, narrow):
    env = _configure(monkeypatch, approver)
    assert env["SECAGENT_UPDATE"] == update
    assert env.get("SECAGENT_ONLY_ALLOW_NARROW") == narrow
    assert "GERYON_GENERIC_POLICY" not in env


def test_generic_policy_variable_is_set_only_when_asked(monkeypatch):
    assert _configure(monkeypatch, "auto-approve", generic=True)["GERYON_GENERIC_POLICY"] == "True"
    assert "GERYON_GENERIC_POLICY" not in _configure(monkeypatch, "auto-approve")


def test_policy_updates_flag_is_the_older_spelling_of_auto_approve():
    resolve = run_condition.resolve_approver
    assert resolve(Namespace(approver=None, policy_updates=True)) == "auto-approve"
    assert resolve(Namespace(approver=None, policy_updates=False)) == "disable-update"
    assert resolve(Namespace(approver="auto-deny", policy_updates=False)) == "auto-deny"
    with pytest.raises(SystemExit):
        resolve(Namespace(approver="disable-update", policy_updates=True))
