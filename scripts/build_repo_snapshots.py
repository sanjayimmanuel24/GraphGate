"""Store each validated event's repository at its fix commit, for Condition C (BUILD_PLAN 5.2).

    python scripts/build_repo_snapshots.py

Condition C's registered view lays the rest of the repository around an
event's slice. This script reads every Python file of the repository at the
event's fix commit from the local clones (data/interim/repos/) and writes it
to data/interim/repo_snapshots/: one index per event, the texts stored once
per git blob. The directory is ignored by git, because it is other projects'
code; scripts/make_notebook_bundle.py packs it for the notebook.

It reads local clones only and makes no network call. If a clone lacks a
commit or a file, it stops with an error instead of fetching it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from graphgate.dataset.leakage import read_tree
from graphgate.dataset.traceplan import select_events
from graphgate.graph.overlay import write_snapshot


def load_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("events", nargs="*", help="event ids (default: every validated event)")
    parser.add_argument("--events-dir", type=Path, default=Path("data/events"))
    parser.add_argument("--repos", type=Path, default=Path("data/interim/repos"))
    parser.add_argument("--signoff", type=Path, default=Path("data/validation_signoff.json"))
    parser.add_argument("--ai-review", type=Path, default=Path("data/validation_ai_review.json"))
    parser.add_argument("--out", type=Path, default=Path("data/interim/repo_snapshots"))
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    ai_review = {r["event_id"]: r for r in load_json(args.ai_review, {"results": []})["results"]}
    decisions = load_json(args.signoff, {"decisions": {}})["decisions"]
    selected = tuple(args.events) or select_events(args.events_dir, ai_review, decisions).events
    if not selected:
        print(f"no validated event in {args.signoff.as_posix()}")
        return 1

    total = 0
    for event_id in selected:
        facts = json.loads((args.events_dir / event_id / "event.json").read_text(encoding="utf-8"))
        clone = args.repos / facts["repo"].replace("/", "__")
        if not clone.is_dir():
            raise SystemExit(f"{event_id}: no clone of {facts['repo']} at {clone.as_posix()}")
        count = write_snapshot(args.out, event_id, facts["repo"], facts["clean_commit"],
                               read_tree(clone, facts["clean_commit"]))
        total += count
        print(f"{event_id:<20} {facts['repo']:<34} {facts['clean_commit'][:10]}  {count:>4} file(s)")
    blobs = list((args.out / "blobs").glob("*.py"))
    print(f"\n{len(selected)} event(s), {total} file entries, {len(blobs)} distinct file(s), "
          f"{sum(b.stat().st_size for b in blobs) / 1e6:.1f} MB in {args.out.as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
