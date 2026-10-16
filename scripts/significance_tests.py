"""Significance tests on the dataset run of the gate conditions (BUILD_PLAN 6.3).

    python scripts/significance_tests.py

Reads data/results/turns.csv and data/results/summary.json and writes
data/significance_tests.json. The plan (unit, test, sidedness, ties, effect
sizes, intervals, the secondary family) was fixed before any test was computed
and lives in the docstring of graphgate.experiment.stats; this script applies
it and nothing else. A pilot or an unfinished run is refused.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from graphgate.experiment import stats
from graphgate.experiment.metrics import read_rows
from graphgate.experiment.runner import ROLE_INTRODUCING

SCHEMA_VERSION = 1
CROSS_FILE = "cross_file"
PRIMARY = ("C", "B", CROSS_FILE)
SECONDARY = (("C", "B", None), ("C", "B+", CROSS_FILE), ("C", "B+", None))


def analyse(rows: list[dict], summary: dict) -> dict:
    conditions = list(dict.fromkeys(r["condition"] for r in rows))
    every_event = sorted({r["event_id"] for r in rows})
    placed = sorted({r["event_id"] for r in rows if r["role"] == ROLE_INTRODUCING})
    scope = {r["event_id"]: r["scope"] for r in rows}
    primary = stats.compare(rows, *PRIMARY)
    primary["significant"] = primary["p_two_sided"] < stats.ALPHA
    secondary = [stats.compare(rows, *spec) for spec in SECONDARY]
    adjusted = stats.holm({f"{s['first']} vs {s['second']}, {s['scope']}": s["p_two_sided"] for s in secondary})
    for s in secondary:
        s["p_holm"] = adjusted[f"{s['first']} vs {s['second']}, {s['scope']}"]
        s["significant_after_holm"] = s["p_holm"] < stats.ALPHA
    return {
        "schema_version": SCHEMA_VERSION,
        "note": "Paired tests on per-event recall at introduction. The plan was fixed before the tests were "
                "computed (graphgate.experiment.stats); secondary tests are Holm-adjusted together and "
                "never stand in for the primary one.",
        "plan": {"module": "graphgate.experiment.stats", "alpha": stats.ALPHA, "sided": "two-sided",
                 "zero_differences": "dropped and counted", "ties": "average ranks, exact p over all sign "
                 "assignments", "ci_level": stats.LEVEL, "bootstrap_resamples": stats.RESAMPLES,
                 "bootstrap_seed": stats.SEED},
        "source": {"results": "data/results", "triage_model": summary["triage"]["model"],
                   "conditions": conditions},
        "events": {"in_run": len(every_event), "with_a_placed_regression": len(placed),
                   "cross_file_with_a_placed_regression": sum(scope[e] == CROSS_FILE for e in placed),
                   "without_a_placed_regression": sorted(set(every_event) - set(placed))},
        "per_condition": {c: {"all": stats.describe(stats.per_event_recall(rows, c)),
                              CROSS_FILE: stats.describe(stats.per_event_recall(rows, c, CROSS_FILE))}
                          for c in conditions},
        "primary": primary,
        "secondary": secondary,
    }


def report(result: dict) -> None:
    events = result["events"]
    print(f"{events['with_a_placed_regression']} of {events['in_run']} events have a placed regression "
          f"({events['cross_file_with_a_placed_regression']} cross-file); left out: "
          f"{', '.join(events['without_a_placed_regression']) or 'none'}")
    print("\nmean per-event recall at introduction [95% CI]      all events            cross-file")
    for name, d in result["per_condition"].items():
        print(f"  {name:8} {d['all']['mean_recall']:.3f} {d['all']['ci95']}"
              f"     {d['cross_file']['mean_recall']:.3f} {d['cross_file']['ci95']}")
    for title, tests in (("primary", [result["primary"]]), ("secondary (Holm)", result["secondary"])):
        print(f"\n{title}")
        for t in tests:
            holm = f", Holm p = {t['p_holm']:.4f}" if "p_holm" in t else ""
            print(f"  {t['first']} vs {t['second']}, {t['scope']}: {t['pairs']} events, "
                  f"{t['zero_differences_dropped']} without a difference, {t['first']} higher in "
                  f"{t['first_better']}, {t['second']} higher in {t['second_better']}; "
                  f"p = {t['p_two_sided']:.4f}{holm}; rank-biserial {t['rank_biserial']:.2f}; "
                  f"mean difference {t['mean_difference']:.3f} {t['mean_difference_ci95']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--results-dir", type=Path, default=Path("data/results"))
    parser.add_argument("--out", type=Path, default=Path("data/significance_tests.json"))
    args = parser.parse_args(argv)
    summary = json.loads((args.results_dir / "summary.json").read_text(encoding="utf-8"))
    if summary["pilot"] or not summary["complete"]:
        raise SystemExit(f"{args.results_dir} holds a pilot or an unfinished run; it is never tested")
    result = analyse(read_rows(args.results_dir / "turns.csv"), summary)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    report(result)
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
