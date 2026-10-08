"""Save the project owner's sign-off on the regression events (BUILD_PLAN 2.3).

The owner decides each event on the sign-off page (scripts/build_signoff_page.py),
which stores one document per event in its `decisions` collection. Export
that collection to a directory of <event_id>.json files, then:

    python scripts/save_signoff.py data/interim/signoff_export/decisions

writes data/validation_signoff.json. Only an `accept` made on the dossier as it
stands now counts as validation; this script reports decisions made on an older
dossier and events without a decision, and changes none of them.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from graphgate.dataset.events import dossier_version

SCHEMA_VERSION = 1
DECISIONS = ("accept", "reject", "revise")
FIELDS = ("decision", "note", "decided_at", "dossier")


def read_export(directory: Path) -> dict[str, dict]:
    decisions = {}
    for path in sorted(directory.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        missing = [f for f in FIELDS if f not in doc]
        if missing:
            raise SystemExit(f"{path}: missing {', '.join(missing)}")
        if doc["decision"] not in DECISIONS:
            raise SystemExit(f"{path}: unknown decision {doc['decision']!r}")
        if doc["decision"] != "accept" and not doc["note"].strip():
            raise SystemExit(f"{path}: a {doc['decision']} decision needs a note saying why")
        decisions[path.stem] = {f: doc[f] for f in FIELDS}
    if not decisions:
        raise SystemExit(f"no decision found in {directory}")
    return decisions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("export", type=Path, help="directory of exported <event_id>.json decisions")
    parser.add_argument("--ai-review", type=Path, default=Path("data/validation_ai_review.json"))
    parser.add_argument("--events", type=Path, default=Path("data/events"))
    parser.add_argument("--out", type=Path, default=Path("data/validation_signoff.json"))
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    decisions = read_export(args.export)
    ai_review = {r["event_id"]: r for r in
                 json.loads(args.ai_review.read_text(encoding="utf-8"))["results"]}
    unknown = sorted(set(decisions) - set(ai_review))
    if unknown:
        raise SystemExit(f"decisions for events that were never prepared: {', '.join(unknown)}")

    tally = Counter(d["decision"] for d in decisions.values())
    args.out.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "note": "The project owner's sign-off for BUILD_PLAN 2.3, exported from the sign-off page. "
                "An event is validated only by an accept made on the current version of its dossier "
                "(`dossier`); the AI review is evidence for these decisions, not a substitute.",
        "tally": {d: tally.get(d, 0) for d in DECISIONS},
        "decisions": decisions,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")

    stale = sorted(e for e, d in decisions.items()
                   if d["dossier"] != dossier_version(args.events / e, ai_review[e]))
    undecided = sorted(set(ai_review) - set(decisions))
    current_accepts = sum(d["decision"] == "accept" for e, d in decisions.items() if e not in stale)
    print(f"wrote {args.out.as_posix()}: " + ", ".join(f"{tally.get(d, 0)} {d}" for d in DECISIONS))
    print(f"validated (accepted on the current dossier): {current_accepts}")
    if stale:
        print(f"decided on a dossier that has changed since, so not counted: {', '.join(stale)}")
    if undecided:
        print(f"no decision yet: {', '.join(undecided)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
