"""The pre-registered statistics, checked against values computable by hand."""

from __future__ import annotations

import pytest

from geryon.stats import (
    majority_outcome,
    mcnemar_exact,
    minimum_detectable_discordant,
    minimum_detectable_effect,
    wilson_ci,
)


def test_mcnemar_exact_matches_hand_computation():
    # With c = 0 the two-sided p-value is 2 * 0.5**b.
    assert mcnemar_exact(5, 0).p_value == pytest.approx(2 * 0.5**5)
    assert mcnemar_exact(6, 0).p_value == pytest.approx(2 * 0.5**6)


def test_five_flips_is_not_enough_and_six_is():
    assert not mcnemar_exact(5, 0).significant
    assert mcnemar_exact(6, 0).significant
    assert minimum_detectable_discordant() == 6


def test_direction_is_reported_both_ways():
    assert "stronger" in mcnemar_exact(6, 0).direction
    assert "weaker" in mcnemar_exact(0, 6).direction
    assert mcnemar_exact(3, 3).direction == "no difference"


def test_no_discordant_pairs_is_not_a_finding():
    result = mcnemar_exact(0, 0)
    assert result.p_value == 1.0
    assert not result.significant


def test_test_is_symmetric_in_its_arguments():
    assert mcnemar_exact(2, 7).p_value == pytest.approx(mcnemar_exact(7, 2).p_value)


def test_minimum_detectable_effect_on_the_published_pair_sets():
    assert minimum_detectable_effect(42) == pytest.approx(100 * 6 / 42)
    # travel has six within-policy pairs, so every one of them must flip
    assert minimum_detectable_effect(6) == pytest.approx(100.0)


def test_wilson_interval_covers_zero_successes_without_collapsing():
    low, high = wilson_ci(0, 42)
    assert low == 0.0
    assert 0.0 < high < 0.15, "a zero rate on 42 pairs is not evidence of zero"


def test_wilson_interval_brackets_the_point_estimate():
    low, high = wilson_ci(4, 42)
    assert low < 4 / 42 < high


def test_majority_rule_needs_a_majority():
    assert majority_outcome([True, True, False])
    assert not majority_outcome([True, False, False])
    with pytest.raises(ValueError):
        majority_outcome([True, True])
