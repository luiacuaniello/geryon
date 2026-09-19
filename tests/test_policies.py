"""Reading what an installed policy permits.

The counts these functions produce are quoted in a disclosure to a third party,
so each one is pinned here against a policy whose meaning is obvious by eye.
"""
from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from geryon.policies import (
    ANY,
    PolicyUnreadable,
    analyse,
    authorises,
    classify,
    permitted,
    read_policies,
)

ATTACKER = "US133000000121212121212"
VICTIM = "GB29NWBK60161331926819"


def clause(**args):
    return [(100, 0, args, 0)]


def test_absent_tool_permits_nothing():
    """Progent denies what a policy does not mention."""
    assert permitted({}, "send_money") is None


def test_unconstrained_argument_permits_everything():
    assert permitted({"send_money": clause(recipient={"type": "string"})}, "send_money") == ANY


def test_one_open_clause_makes_the_whole_tool_open():
    policy = {"send_money": clause(recipient={"enum": [VICTIM]}) + clause(recipient={"type": "string"})}
    assert permitted(policy, "send_money") == ANY


def test_enumerated_values_are_returned():
    policy = {"send_money": clause(recipient={"enum": [VICTIM, ATTACKER]})}
    assert permitted(policy, "send_money") == frozenset({VICTIM, ATTACKER})


def test_non_enum_constraints_are_read_as_open():
    """Documented limitation: a pattern is not interpreted, only enums are."""
    policy = {"send_money": clause(recipient={"pattern": "^GB"})}
    assert permitted(policy, "send_money") == ANY


def test_authorises_lists_every_tool_that_would_send():
    policy = {
        "send_money": clause(recipient={"enum": [ATTACKER]}),
        "update_scheduled_transaction": clause(recipient={"enum": [VICTIM]}),
    }
    assert authorises(policy, ATTACKER) == ["send_money"]


def test_a_tool_appearing_for_the_first_time_is_an_expansion():
    before = {"get_balance": clause()}
    after = {"get_balance": clause(), "send_money": clause(recipient={"enum": [ATTACKER]})}
    assert classify(before, after) == "expansion"


def test_widening_an_enum_is_an_expansion():
    before = {"send_money": clause(recipient={"enum": [VICTIM]})}
    after = {"send_money": clause(recipient={"enum": [VICTIM, ATTACKER]})}
    assert classify(before, after) == "expansion"


def test_closing_an_open_argument_onto_the_attacker_is_a_narrowing():
    """The case that matters: the permitted set shrinks, onto the attacker."""
    before = {"send_money": clause(recipient={"type": "string"})}
    after = {"send_money": clause(recipient={"enum": [ATTACKER]})}
    assert classify(before, after) == "narrowing"


def test_a_cleared_policy_is_read_as_unset(tmp_path: Path):
    log = tmp_path / "run.log"
    log.write_text("security policy updated: None\n")
    assert list(read_policies(log)) == [None]


def test_an_unparseable_policy_raises_rather_than_being_skipped(tmp_path: Path):
    log = tmp_path / "run.log"
    log.write_text("security policy updated: {not python}\n")
    with pytest.raises(PolicyUnreadable, match="run.log:1"):
        list(read_policies(log))


def test_analyse_counts_a_small_run(tmp_path: Path):
    log = tmp_path / "run.log.gz"
    lines = [
        "security policy updated: {'send_money': [(100, 0, {'recipient': {'type': 'string'}}, 0)]}",
        "security policy updated: {'send_money': [(100, 0, {'recipient':"
        f" {{'enum': ['{ATTACKER}']}}}}, 0)]}}",
        "security policy updated: None",
        "noise that is not a policy",
    ]
    with gzip.open(log, "wt") as fh:
        fh.write("\n".join(lines) + "\n")

    report = analyse(log, ATTACKER)
    assert report.installed == 3
    assert report.unset == 1
    assert report.authorising == 1
    assert report.exclusive == 1
    assert report.transitions == {"narrowing": 1}
