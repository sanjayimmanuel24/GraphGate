"""Build the sign-off page for BUILD_PLAN 2.3 from the event dossiers.

The page embeds every dossier (flow facts, regression diff, both slices, the
AI analysis and adversarial check) and records the project owner's
accept / reject / revise decision per event in the artifact's database.
Each decision stores the dossier version it was made on, so a dossier
rebuilt afterwards shows as needing review again.

    python scripts/build_signoff_page.py --out <page.html>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

TEMPLATE = Path(__file__).with_name("signoff_page.html")
PLACEHOLDER = '/*__DATA__*/{"generated_at": "", "events": []}'


def dossier_version(event_dir: Path, ai: dict) -> str:
    """A short hash over everything the reviewer sees for this event."""
    h = hashlib.sha256()
    for path in sorted(p for p in event_dir.rglob("*") if p.is_file() and p.name != "spec.json"):
        h.update(path.relative_to(event_dir).as_posix().encode())
        h.update(path.read_bytes())
    h.update(json.dumps(ai, sort_keys=True).encode())
    return h.hexdigest()[:12]


def read_tree(root: Path) -> dict[str, str]:
    if not root.is_dir():
        return {}
    return {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8")
            for p in sorted(root.rglob("*.py"))}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--worklist", type=Path, default=Path("data/interim/validation/worklist.json"))
    parser.add_argument("--ai-review", type=Path, default=Path("data/validation_ai_review.json"))
    parser.add_argument("--events", type=Path, default=Path("data/events"))
    args = parser.parse_args(argv)

    worklist = json.loads(args.worklist.read_text(encoding="utf-8"))
    ai_review = {r["event_id"]: r for r in
                 json.loads(args.ai_review.read_text(encoding="utf-8"))["results"]}
    events = []
    for item in worklist:
        eid = item["event_id"]
        d = args.events / eid
        event_path = d / "event.json"
        event = json.loads(event_path.read_text(encoding="utf-8")) if event_path.exists() else {}
        ai = ai_review.get(eid, {})
        diff = (d / "regression.diff").read_text(encoding="utf-8") if (d / "regression.diff").exists() else ""
        events.append({
            "event_id": eid,
            "advisories": item["advisories"],
            "cves": item["cves"],
            "repo": item["repo"],
            "advisory_classes": item["classes"],
            "clean_commit": item["clean_commit"],
            "regressed_commit": item["regressed_commit"],
            "vulnerability_class": event.get("vulnerability_class")
                                   or (ai.get("analyst") or {}).get("vulnerability_class"),
            "scope": event.get("scope"),
            "flow": event.get("flow"),
            "flow_files": event.get("flow_files"),
            "regression_files": event.get("regression_files"),
            "totals": event.get("totals"),
            "checks": event.get("checks"),
            "scrubbed": event.get("scrubbed"),
            "flagged_strings": event.get("flagged_strings"),
            "diff": diff,
            "clean_files": read_tree(d / "clean"),
            "regressed_files": read_tree(d / "regressed"),
            "ai": ai,
            "dossier_version": dossier_version(d, ai),
        })

    data = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "events": events}
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    template = TEMPLATE.read_text(encoding="utf-8")
    if PLACEHOLDER not in template:
        raise SystemExit(f"{TEMPLATE}: data placeholder not found")
    args.out.write_text(template.replace(PLACEHOLDER, blob), encoding="utf-8", newline="\n")
    print(f"wrote {args.out}: {len(events)} events, {args.out.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
