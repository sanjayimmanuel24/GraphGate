"""Find what in each event's repository would give its regression away (BUILD_PLAN 2.6).

    python scripts/check_leakage.py
    python scripts/check_leakage.py piccolo-xq59 mako-2h4p

Without event ids it scans every validated event and writes
data/leakage_exclusions.json, the exclusion list the retrieval layer reads.
With event ids it only prints what it finds, so a partial run cannot replace
the full list.

It reads the local repository clones and makes no network or API call. If a
clone lacks a file the scan stops with an error instead of fetching it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from graphgate.dataset.leakage import (
    MIN_TOKENS,
    THRESHOLD,
    UnitCache,
    build_report,
    scan_event,
)
from graphgate.dataset.traceplan import select_events


def load_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("events", nargs="*", help="event ids to preview (nothing is written)")
    parser.add_argument("--events-dir", type=Path, default=Path("data/events"))
    parser.add_argument("--repos", type=Path, default=Path("data/interim/repos"))
    parser.add_argument("--signoff", type=Path, default=Path("data/validation_signoff.json"))
    parser.add_argument("--ai-review", type=Path, default=Path("data/validation_ai_review.json"))
    parser.add_argument("--out", type=Path, default=Path("data/leakage_exclusions.json"))
    parser.add_argument("--threshold", type=float, default=THRESHOLD,
                        help="similarity at or above which a unit is a near-duplicate (default: %(default)s)")
    parser.add_argument("--min-tokens", type=int, default=MIN_TOKENS,
                        help="units shorter than this are listed as not compared (default: %(default)s)")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    ai_review = {r["event_id"]: r for r in load_json(args.ai_review, {"results": []})["results"]}
    decisions = load_json(args.signoff, {"decisions": {}})["decisions"]
    validated = select_events(args.events_dir, ai_review, decisions).events
    selected = tuple(args.events) or validated
    if not selected:
        print(f"no validated event: the scan covers events accepted in {args.signoff.as_posix()}")
        return 1

    cache = UnitCache()
    results = {}
    for event_id in selected:
        event_dir = args.events_dir / event_id
        repo = json.loads((event_dir / "event.json").read_text(encoding="utf-8"))["repo"]
        result = scan_event(event_dir, args.repos / repo.replace("/", "__"),
                            threshold=args.threshold, min_tokens=args.min_tokens, cache=cache)
        results[event_id] = result
        tests = sum(f["excluded"] for f in result["fix_files"])
        print(f"{event_id}: {result['scanned']['files']} files, {result['scanned']['units']} units scanned; "
              f"{len(result['near_duplicates'])} near-duplicate(s), {tests} test file(s) of the fix, "
              f"{len(result['fix_files']) - tests} other file(s) of the fix left in scope")
        for d in result["near_duplicates"]:
            print(f"    {d['similarity']:.2f}  {d['path']}::{d['symbol']}  ~  {d['of']} ({d['version']})")
        for unit in result["regression_units"]:
            if not unit["compared"]:
                print(f"    not compared: {unit['path']}::{unit['symbol']} ({unit['note']})")

    report = build_report(results, threshold=args.threshold, min_tokens=args.min_tokens)
    summary = report["summary"]
    print(f"\n{summary['events']} event(s): {summary['near_duplicates']} near-duplicate unit(s) in "
          f"{summary['events_with_near_duplicates']} event(s), {summary['fix_tests_excluded']} test file(s) "
          f"changed by a fix; {summary['exclusions']} exclusion(s) across "
          f"{summary['events_with_exclusions']} event(s)")
    print(f"{summary['fix_sources_left_in_scope']} source file(s) changed by a fix outside its slice are "
          "listed and left in scope")
    if summary["regression_units_not_compared"]:
        print(f"{summary['regression_units_not_compared']} of {summary['regression_units']} regression "
              "unit(s) were too short to compare")
    if args.events:
        print("preview only: nothing written")
        return 0
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8", newline="\n")
    print(f"wrote {args.out.as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
