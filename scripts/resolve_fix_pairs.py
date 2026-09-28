"""Build data/fix_pairs.json from data/seed_repos.json (BUILD_PLAN 2.2).

Resolves each advisory's fix commits to a vulnerable/fixed pair, records the
changed files, and re-checks licence and size at the vulnerable commit.

    python scripts/resolve_fix_pairs.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path

from graphgate.dataset.fix_pairs import ensure_clone, resolve_advisory
from graphgate.dataset.seed_repos import LOC_MAX, LOC_MIN


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=Path("data/seed_repos.json"))
    parser.add_argument("--out", type=Path, default=Path("data/fix_pairs.json"))
    parser.add_argument("--repos", type=Path, default=Path("data/interim/repos"))
    parser.add_argument("--recovered", type=Path, default=Path("data/recovered_fix_commits.json"))
    parser.add_argument("--corrections", type=Path, default=Path("data/fix_pair_corrections.json"))
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    # Commits not taken from the advisory itself come from two files, kept
    # apart from the manifest so each one is auditable:
    # - recovered: fixes for advisories that link none, found and confirmed by
    #   the independent review (scripts/apply_fix_review.py);
    # - corrections: hand-curated pairs where both reviewers agreed the
    #   advisory's linked commit gives the wrong pair.
    recovered = _load_advisories(args.recovered)
    corrections = _load_advisories(args.corrections)
    events = []
    for repo in manifest["repos"]:
        clone = ensure_clone(repo["url"] + ".git", args.repos / repo["repo"].replace("/", "__"))
        for adv in repo["advisories"]:
            linked = adv["fix_commits"]
            correction = corrections.get(adv["id"])
            recovered_entry = None if linked else recovered.get(adv["id"])
            vulnerable = None
            if correction:
                adv = {**adv, "fix_commits": [correction["fix_commit"]]}
                vulnerable = correction["vulnerable_commit"]
            elif recovered_entry:
                adv = {**adv, "fix_commits": recovered_entry["fix_commits"]}
            result = resolve_advisory(clone, adv, repo["licence"], vulnerable_commit=vulnerable)
            result["linked_fix_commits"] = linked
            if correction:
                result["flags"].append(
                    f"pair corrected by review (data/fix_pair_corrections.json): {correction['reason']}"
                )
            elif recovered_entry:
                result["flags"].append(
                    "fix commit recovered by review (data/recovered_fix_commits.json); "
                    "the advisory links none"
                )
            loc = result.get("loc_at_vulnerable")
            if loc and not LOC_MIN <= loc["source"] <= LOC_MAX:
                result["flags"].append(
                    f"{loc['source']} source LOC at vulnerable commit, outside {LOC_MIN}-{LOC_MAX}"
                )
            events.append({"repo": repo["repo"], "role": repo["role"], **result})
            print(f"{repo['repo']:32s} {adv['id']:22s} "
                  f"{'pair' if result['vulnerable_commit'] else 'NO PAIR':7s} "
                  f"flags={len(result['flags'])}", flush=True)

    out = {
        "schema_version": 1,
        "status": "automatic resolution — every flag needs a human decision in BUILD_PLAN 2.3",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "events": events,
    }
    args.out.write_text(json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                        encoding="utf-8", newline="\n")

    paired = [e for e in events if e["vulnerable_commit"]]
    flag_counts = Counter(re.split(r"[;:,(]", f)[0].strip() for e in events for f in e["flags"])
    print(f"\nwrote {args.out}: {len(paired)}/{len(events)} advisories resolved to a pair")
    for flag, n in flag_counts.most_common():
        print(f"  {n:3d}  {flag}")
    return 0


def _load_advisories(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))["advisories"]


if __name__ == "__main__":
    sys.exit(main())
