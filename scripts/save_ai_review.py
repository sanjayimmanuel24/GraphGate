"""Save the BUILD_PLAN 2.3 AI review (analyst + adversarial checker per event).

Reads the validation workflow's journal (one line per finished agent) and
writes ``data/validation_ai_review.json``. Safe to rerun while the workflow
is still going: events it has not reached yet are listed as pending.

    python scripts/save_ai_review.py <path/to/journal.jsonl>
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import Counter
from pathlib import Path


def status(r: dict) -> str:
    if not r.get("analyst"):
        return "pending"
    if r.get("exclusion"):
        return "excluded" if r["exclusion"].get("exclusion_justified") else "exclusion-disputed"
    if r.get("fix") and r["fix"].get("verdict") == "exclude":
        return "excluded-after-fix"
    last = r.get("recheck") or r.get("check")
    if not last:
        return "unchecked"
    if last.get("verdict") == "sound":
        return "sound-after-fix" if r.get("fix") else "sound"
    return "defects-remain"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("journal", type=Path)
    parser.add_argument("--worklist", type=Path, default=Path("data/interim/validation/worklist.json"))
    parser.add_argument("--out", type=Path, default=Path("data/validation_ai_review.json"))
    parser.add_argument("--followups", type=Path, default=Path("data/validation_followups.json"))
    args = parser.parse_args(argv)

    rows = [json.loads(line) for line in args.journal.read_text(encoding="utf-8").splitlines() if line.strip()]
    label = {r["key"]: r["label"] for r in rows if r.get("type") == "started"}
    found: dict[str, dict] = {}
    for r in rows:
        if r.get("type") != "result" or r["key"] not in label:
            continue
        value = r["result"]
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = ast.literal_eval(value)
        kind, event_id = label[r["key"]].split(":", 1)
        role = {"analyse": "analyst"}.get(kind, kind)
        found.setdefault(event_id, {})[role] = value

    order = [w["event_id"] for w in json.loads(args.worklist.read_text(encoding="utf-8"))]
    followups = {}
    if args.followups.exists():
        followups = json.loads(args.followups.read_text(encoding="utf-8"))["followups"]
    results = []
    for event_id in order:
        r = {"event_id": event_id, **found.get(event_id, {})}
        r["status"] = status(r)
        if event_id in followups:
            # Recorded by hand after the run, e.g. a dossier rebuilt after a tool fix.
            r["followup"] = followups[event_id]
            r["status"] = followups[event_id].get("status", r["status"])
        results.append(r)
    tally = dict(Counter(r["status"] for r in results))
    args.out.write_text(json.dumps({
        "schema_version": 1,
        "note": "AI preparation for BUILD_PLAN 2.3: one analyst and one adversarial checker per "
                "event (plus a fix round on blocking defects). Evidence for the owner's sign-off, "
                "not the sign-off itself.",
        "tally": tally,
        "results": results,
    }, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.out}: {tally}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
