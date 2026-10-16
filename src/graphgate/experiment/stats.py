"""Significance tests for the registered comparison (BUILD_PLAN 6.3, proposal 7.2).

The plan below was fixed on 2026-10-16, after the per-condition counts of the
first run were known (``data/results/summary.json``) and before any test was
computed. The proposal fixes the test: paired Wilcoxon signed-rank tests on
per-trace recall, effect sizes beside p-values, means with confidence
intervals. The owner fixed the two points it left open, taking the
recommended choices: the test is two-sided, and pairs with no difference are
dropped and counted. The rest completes the plan in the conventional way. Do
not change any of it after the tests have been computed.

- **Unit: one event** (one trace). Its recall is the share of its replications
  with a placed regression in which the condition blocked the introducing turn:
  recall at introduction, the study's main recall figure. Events in which no
  regression was placed have no recall and are left out, and counted.
- **Primary test: C against B over the cross-file events.** Two-sided exact
  Wilcoxon signed-rank test. Pairs whose difference is zero are dropped
  (Wilcoxon's own treatment); tied absolute differences share their average
  rank; the p-value is counted exactly over every assignment of signs, so it
  holds with ties and needs no normal approximation. Significance level 0.05.
- **Effect sizes:** the matched-pairs rank-biserial correlation,
  ``(W+ - W-) / (W+ + W-)``, from -1 to 1; and the mean difference in
  per-event recall with a 95% percentile bootstrap interval over events
  (10,000 resamples, seed 0).
- **Secondary tests**, the same method, Holm-adjusted together as one family:
  C against B over all events, and C against B+ over the cross-file events and
  over all events. They are reported beside the primary test, never in its
  place. C against S1 is added when Pysa runs.
- **Per condition:** the mean per-event recall with the same bootstrap
  interval.

Recalls are kept as exact fractions until they are reported, so that equal
differences are recognised as ties.
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from fractions import Fraction
from typing import Any, Iterable, Mapping

from graphgate.experiment.runner import ROLE_INTRODUCING
from graphgate.gate.local import BLOCK

ALPHA = 0.05
LEVEL = 0.95
RESAMPLES = 10_000
SEED = 0


def per_event_recall(rows: Iterable[Mapping[str, Any]], condition: str,
                     scope: str | None = None) -> dict[str, Fraction]:
    """Recall at introduction per event, for one condition and optionally one scope."""
    blocked: dict[str, int] = defaultdict(int)
    introduced: dict[str, int] = defaultdict(int)
    for row in rows:
        if row["condition"] != condition or row["role"] != ROLE_INTRODUCING:
            continue
        if scope is not None and row["scope"] != scope:
            continue
        introduced[row["event_id"]] += 1
        blocked[row["event_id"]] += row["decision"] == BLOCK
    return {event: Fraction(blocked[event], n) for event, n in sorted(introduced.items())}


def _doubled_ranks(magnitudes: list[Fraction]) -> list[int]:
    """Twice the average rank of each value, so that tied ranks stay whole numbers."""
    order = sorted(range(len(magnitudes)), key=lambda i: magnitudes[i])
    ranks = [0] * len(magnitudes)
    start = 0
    while start < len(order):
        end = start
        while end + 1 < len(order) and magnitudes[order[end + 1]] == magnitudes[order[start]]:
            end += 1
        for position in range(start, end + 1):
            ranks[order[position]] = (start + 1) + (end + 1)
        start = end + 1
    return ranks


def wilcoxon_signed_rank(differences: Iterable[Fraction | int | float]) -> dict[str, Any]:
    """Two-sided exact Wilcoxon signed-rank test; zero differences dropped and counted."""
    values = [Fraction(d) for d in differences]
    used = [d for d in values if d != 0]
    ranks = _doubled_ranks([abs(d) for d in used])
    total = sum(ranks)
    positive = sum(r for r, d in zip(ranks, used) if d > 0)
    # How many of the 2**n equally likely sign assignments give each positive rank sum.
    counts = {0: 1}
    for rank in ranks:
        shifted: dict[int, int] = defaultdict(int)
        for value, count in counts.items():
            shifted[value] += count
            shifted[value + rank] += count
        counts = dict(shifted)
    observed = abs(2 * positive - total)
    extreme = sum(count for value, count in counts.items() if abs(2 * value - total) >= observed)
    p = extreme / 2 ** len(used) if used else 1.0
    return {"pairs": len(values), "zero_differences_dropped": len(values) - len(used), "pairs_used": len(used),
            "w_plus": positive / 2, "w_minus": (total - positive) / 2, "p_two_sided": p,
            "rank_biserial": (2 * positive - total) / total if total else 0.0}


def bootstrap_mean_ci(values: Iterable[Fraction | float], *, resamples: int = RESAMPLES, seed: int = SEED,
                      level: float = LEVEL) -> tuple[float, float]:
    """Percentile bootstrap interval for the mean, resampling the values with replacement."""
    data = [float(v) for v in values]
    if not data:
        raise ValueError("no values to resample")
    rng = random.Random(seed)
    means = sorted(sum(data[rng.randrange(len(data))] for _ in data) / len(data) for _ in range(resamples))
    lower = means[math.floor((1 - level) / 2 * resamples)]
    upper = means[math.ceil((1 + level) / 2 * resamples) - 1]
    return lower, upper


def holm(p_values: Mapping[str, float]) -> dict[str, float]:
    """Holm-adjusted p-values for one family of tests."""
    ordered = sorted(p_values.items(), key=lambda item: item[1])
    adjusted, running = {}, 0.0
    for k, (name, p) in enumerate(ordered):
        running = max(running, min(1.0, (len(ordered) - k) * p))
        adjusted[name] = running
    return adjusted


def describe(recalls: Mapping[str, Fraction]) -> dict[str, Any]:
    """Mean per-event recall with its bootstrap interval."""
    low, high = bootstrap_mean_ci(recalls.values())
    return {"events": len(recalls), "mean_recall": round(float(sum(recalls.values()) / len(recalls)), 4),
            "ci95": [round(low, 4), round(high, 4)]}


def compare(rows: list[Mapping[str, Any]], first: str, second: str, scope: str | None = None) -> dict[str, Any]:
    """Paired test of ``first`` against ``second`` over the events both have a recall for."""
    a, b = per_event_recall(rows, first, scope), per_event_recall(rows, second, scope)
    events = sorted(set(a) & set(b))
    if set(a) != set(b):
        raise ValueError(f"{first} and {second} judged different events: {sorted(set(a) ^ set(b))}")
    differences = [a[e] - b[e] for e in events]
    test = wilcoxon_signed_rank(differences)
    low, high = bootstrap_mean_ci(differences)
    return {"first": first, "second": second, "scope": scope or "all", **test,
            "first_better": sum(d > 0 for d in differences), "second_better": sum(d < 0 for d in differences),
            "tied_with_both_zero": sum(a[e] == 0 and b[e] == 0 for e in events),
            "mean_difference": round(float(sum(differences) / len(differences)), 4),
            "mean_difference_ci95": [round(low, 4), round(high, 4)],
            "per_event_difference": {e: round(float(d), 4) for e, d in zip(events, differences)}}
