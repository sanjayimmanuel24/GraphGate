"""Build regression-event dossiers from their specs (BUILD_PLAN 2.3).

    python scripts/build_event.py data/events/<event_id>/spec.json [...]
    python scripts/build_event.py --all

Writes clean/, regressed/, regression.diff and event.json next to each spec
and prints a summary. Exits non-zero if any check fails.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from graphgate.dataset.events import HARD_LIMIT_BYTES, SOFT_LIMIT_BYTES, build_event, load_spec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("specs", nargs="*", type=Path)
    parser.add_argument("--all", action="store_true", help="every data/events/*/spec.json")
    parser.add_argument("--repos", type=Path, default=Path("data/interim/repos"))
    parser.add_argument("--soft-limit", type=int, default=SOFT_LIMIT_BYTES,
                        help="clean-slice bytes above which the size check warns")
    parser.add_argument("--hard-limit", type=int, default=HARD_LIMIT_BYTES,
                        help="clean-slice bytes above which the size check fails")
    parser.add_argument("--json", action="store_true", help="print the full event.json")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    specs = sorted(Path("data/events").glob("*/spec.json")) if args.all else args.specs
    if not specs:
        parser.error("give spec paths or --all")
    failed = 0
    for spec in specs:
        repo = load_spec(spec)["repo"]
        event = build_event(spec, args.repos / repo.replace("/", "__"),
                            soft_limit=args.soft_limit, hard_limit=args.hard_limit)
        if args.json:
            print(json.dumps(event, indent=2, ensure_ascii=False))
            continue
        bad = [c for c in event["checks"] if c["status"] != "ok"]
        failed += any(c["status"] == "fail" for c in bad)
        sizes = ", ".join(f"{p} {f['clean']['lines'] if f['clean'] else '-'}/"
                          f"{f['regressed']['lines'] if f['regressed'] else '-'} lines"
                          for p, f in event["files"].items())
        print(f"{event['event_id']}: scope={event['scope']} "
              f"clean~{event['totals']['clean']['approx_tokens']} tokens; {sizes}")
        print(f"  regression changes: {', '.join(event['regression_files']) or 'nothing'}; "
              f"scrubbed {len(event['scrubbed']['clean'])}+{len(event['scrubbed']['regressed'])} "
              f"comment(s)")
        for c in bad:
            print(f"  {c['status'].upper()} {c['name']}: {c['detail']}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
