"""Significance tests for the registered comparison (BUILD_PLAN 6.3)."""

import itertools
from fractions import Fraction

import pytest

from graphgate.experiment.stats import (_doubled_ranks, bootstrap_mean_ci, compare, holm, per_event_recall,
                                         wilcoxon_signed_rank)


def brute_force_p(differences):
    """The two-sided p-value by listing every sign assignment, ties given average ranks."""
    used = [Fraction(d) for d in differences if d != 0]
    ranks = _doubled_ranks([abs(d) for d in used])
    total = sum(ranks)
    observed = abs(2 * sum(r for r, d in zip(ranks, used) if d > 0) - total)
    hits = sum(abs(2 * sum(r for r, s in zip(ranks, signs) if s) - total) >= observed
               for signs in itertools.product((True, False), repeat=len(used)))
    return hits / 2 ** len(used)


def test_all_positive_distinct_differences():
    result = wilcoxon_signed_rank([1, 2, 3, 4, 5])
    assert result["p_two_sided"] == pytest.approx(2 / 32)
    assert result["w_plus"] == 15 and result["w_minus"] == 0
    assert result["rank_biserial"] == 1


def test_zero_differences_are_dropped_and_counted():
    result = wilcoxon_signed_rank([0, 1, 0, 2, 3])
    assert result["pairs"] == 5 and result["zero_differences_dropped"] == 2 and result["pairs_used"] == 3
    assert result["p_two_sided"] == pytest.approx(2 / 8)


def test_tied_magnitudes_share_their_average_rank():
    assert _doubled_ranks([Fraction(1), Fraction(1), Fraction(2)]) == [3, 3, 6]
    # 1/3 is rank 1; the three 2s share ranks 2, 3 and 4, average 3.
    assert _doubled_ranks([Fraction(2), Fraction(1, 3), Fraction(2), Fraction(2)]) == [6, 2, 6, 6]


@pytest.mark.parametrize("differences", [
    [1, 1, 2, -2, 3, 0],
    [Fraction(1, 3), Fraction(-1, 3), Fraction(2, 3), 1, 1, Fraction(1, 3), -1],
    [-1, -1, -1, 2],
    [Fraction(1, 2), Fraction(1, 2), Fraction(1, 2)],
])
def test_exact_p_matches_listing_every_sign_assignment(differences):
    assert wilcoxon_signed_rank(differences)["p_two_sided"] == pytest.approx(brute_force_p(differences))


def test_reversing_the_comparison_keeps_p_and_flips_the_effect():
    forward = wilcoxon_signed_rank([1, 2, -1, 3, Fraction(1, 2)])
    backward = wilcoxon_signed_rank([-1, -2, 1, -3, Fraction(-1, 2)])
    assert forward["p_two_sided"] == backward["p_two_sided"]
    assert forward["rank_biserial"] == -backward["rank_biserial"]


def test_no_difference_at_all_gives_p_one():
    result = wilcoxon_signed_rank([0, 0, 0])
    assert result["pairs_used"] == 0 and result["p_two_sided"] == 1.0 and result["rank_biserial"] == 0.0


def test_holm_adjusts_one_family():
    assert holm({"a": 0.01, "b": 0.04, "c": 0.03}) == pytest.approx({"a": 0.03, "c": 0.06, "b": 0.06})
    assert holm({"a": 0.6, "b": 0.7}) == pytest.approx({"a": 1.0, "b": 1.0})


def test_bootstrap_is_seeded_and_brackets_the_mean():
    values = [0, Fraction(1, 3), 1, Fraction(2, 3), 0, 0, 1]
    first, second = bootstrap_mean_ci(values), bootstrap_mean_ci(values)
    assert first == second
    assert first[0] <= sum(map(float, values)) / len(values) <= first[1]
    assert bootstrap_mean_ci([0.5, 0.5, 0.5]) == (0.5, 0.5)
    with pytest.raises(ValueError):
        bootstrap_mean_ci([])


def row(condition, event, decision, role="introducing", scope="cross_file"):
    return {"condition": condition, "event_id": event, "decision": decision, "role": role, "scope": scope}


ROWS = [
    # e1, cross-file, three placed replications: B blocks one, C blocks two.
    row("B", "e1", "BLOCK"), row("B", "e1", "ALLOW"), row("B", "e1", "ALLOW"),
    row("C", "e1", "BLOCK"), row("C", "e1", "BLOCK"), row("C", "e1", "ALLOW"),
    # e2, local: neither blocks.
    row("B", "e2", "ALLOW", scope="local"), row("C", "e2", "ALLOW", scope="local"),
    # e3, cross-file: C blocks its one placed regression.
    row("B", "e3", "ALLOW"), row("C", "e3", "BLOCK"),
    # Turns that are not introducing ones never count.
    row("B", "e1", "BLOCK", role="persisting"), row("C", "e4", "BLOCK", role="clean"),
]


def test_per_event_recall_counts_introducing_turns_only():
    assert per_event_recall(ROWS, "C") == {"e1": Fraction(2, 3), "e2": 0, "e3": 1}
    assert per_event_recall(ROWS, "B", "cross_file") == {"e1": Fraction(1, 3), "e3": 0}


def test_compare_pairs_events_and_reports_both_directions():
    result = compare(ROWS, "C", "B", "cross_file")
    assert result["pairs"] == 2 and result["first_better"] == 2 and result["second_better"] == 0
    assert result["per_event_difference"] == {"e1": pytest.approx(1 / 3, abs=1e-4), "e3": 1.0}
    assert result["mean_difference"] == pytest.approx((1 / 3 + 1) / 2, abs=1e-4)
    every = compare(ROWS, "C", "B")
    assert every["zero_differences_dropped"] == 1 and every["tied_with_both_zero"] == 1


def test_compare_refuses_conditions_that_judged_different_events():
    with pytest.raises(ValueError):
        compare(ROWS + [row("C", "e9", "BLOCK")], "C", "B")
