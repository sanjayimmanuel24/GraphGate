"""Record the independent review of the 2.2 commit pairs.

Takes the review workflow's result (confirm + refute reviewers per pair, plus
recovery searches) and writes:

- ``data/fix_review.json`` — every reviewer verdict and pre-screen note, with
  an outcome per advisory. This is the evidence BUILD_PLAN 2.3's manual
  validation works from; it does not replace that validation.
- ``data/recovered_fix_commits.json`` — fix commits found for advisories that
  link none, **only where both reviewers confirmed the recovered commit**.
  scripts/resolve_fix_pairs.py reads this file.

Outcomes: ``confirmed`` (both reviewers: correct, same commit), ``contested``
(they disagree), ``rejected`` (both: wrong), ``needs-human`` (anything else,
including a reviewer that failed to return), ``not-recovered``.

    python scripts/apply_fix_review.py data/interim/review/results.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("results", type=Path)
    parser.add_argument("--review-out", type=Path, default=Path("data/fix_review.json"))
    parser.add_argument("--recovered-out", type=Path, default=Path("data/recovered_fix_commits.json"))
    args = parser.parse_args(argv)

    raw = json.loads(args.results.read_text(encoding="utf-8"))
    results = raw["results"] if isinstance(raw, dict) else raw
    today = date.today().isoformat()

    recovered = {}
    for r in results:
        if r.get("kind") == "recover" and r.get("outcome") == "confirmed":
            recovered[r["advisory"]] = {
                "repo": r["repo"],
                "fix_commits": r["recovery"]["fix_commits"],
                "evidence": r["recovery"]["evidence"],
                "recovery_confidence": r["recovery"]["confidence"],
                "confirmed_by": ["confirm reviewer", "refute reviewer"],
                "reviewed_on": today,
            }

    review = {
        "schema_version": 1,
        "reviewed_on": today,
        "method": "two independent reviewers per commit pair: one establishing the link, "
                  "one instructed to refute it and to default to not confirming; recovery "
                  "searches for advisories linking no fix, each recovered commit then reviewed "
                  "the same way. Pre-screen fields are evidence for BUILD_PLAN 2.3, not its result.",
        "tally": dict(Counter(r.get("outcome", "needs-human") for r in results)),
        "advisories": sorted(results, key=lambda r: (r["repo"], r["advisory"])),
    }
    args.review_out.write_text(json.dumps(review, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                               encoding="utf-8", newline="\n")
    args.recovered_out.write_text(json.dumps({
        "schema_version": 1,
        "note": "Fix commits for advisories that link none, found by review and confirmed by "
                "both reviewers. Not from the advisory data; audit before relying on them.",
        "advisories": dict(sorted(recovered.items())),
    }, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")

    print(f"wrote {args.review_out}: {review['tally']}")
    print(f"wrote {args.recovered_out}: {len(recovered)} recovered advisories")
    return 0


if __name__ == "__main__":
    sys.exit(main())
