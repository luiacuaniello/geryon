"""Regression tests on the published pair analysis.

These need AgentDojo installed and are skipped otherwise, so the corpus and
statistics tests still run in a minimal environment.
"""

from __future__ import annotations

import pytest

pytest.importorskip("agentdojo", reason="AgentDojo is needed for the pair analysis")

from geryon.overlap import (  # noqa: E402
    EXPECTED_PAIRS_V121,
    EXPECTED_WITHIN_POLICY_V121,
    analyse_suite,
    check_expected,
    flatten_values,
)


def test_flatten_values_is_order_independent_and_recursive():
    assert flatten_values({"b": 1, "a": [2, {"c": 3}]}) == ["2", "3", "1"]
    assert set(flatten_values({"x": ["p", "q"]})) == {"p", "q"}


@pytest.mark.parametrize("suite", sorted(EXPECTED_PAIRS_V121))
def test_published_counts_still_hold(suite):
    report = analyse_suite(suite)
    assert not report.failed_tasks, f"ground truth unavailable for {report.failed_tasks}"
    assert len(report.pairs) == EXPECTED_PAIRS_V121[suite]
    assert report.within_policy == EXPECTED_WITHIN_POLICY_V121[suite]
    assert not check_expected([report], "v1.2.1")


@pytest.mark.parametrize("suite", sorted(EXPECTED_PAIRS_V121))
def test_no_pair_is_within_policy_at_argument_level(suite):
    """The central negative result: argument pinning has a signal on every pair."""
    report = analyse_suite(suite)
    assert report.within_policy_arguments == 0
    for pair in report.pairs:
        if pair.within_policy:
            assert pair.novel_arg_values, "a within-policy pair with no novel argument value"


def test_within_policy_implies_tool_subset():
    report = analyse_suite("banking")
    for pair in report.pairs:
        if pair.within_policy:
            assert set(pair.injection_tools) <= set(pair.user_tools)
            assert pair.injection_tools
