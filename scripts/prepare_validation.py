"""Stage the BUILD_PLAN 2.3 validation: one event per candidate pair.

Candidates are the 2.2 pairs in selected repos that are inside the size rule
at their vulnerable commit and not excluded. Advisories resolving to the same
pair become one event (GHSA-p8h7 and GHSA-vqwr share a fix commit).

For each event this writes, under ``data/interim/validation/<event_id>/``
(scratch inputs, not the dataset):

- ``advisories/<GHSA>.json`` — the OSV entries
- ``fix.patch``              — header plus the current pair's diff (2.2's
  review patches predate the corrections and recoveries)
- ``review_2_2.json``        — both 2.2 reviewers' verdicts and pre-screen

and prefetches every ``.py`` blob at both commits, so the analysts' builds
(which disable lazy fetching) and ``git show`` calls never race to fetch into
the same blobless clone. Prints the work list as JSON.

    python scripts/prepare_validation.py > data/interim/validation/worklist.json
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

from graphgate.dataset.fix_pairs import git
from graphgate.dataset.seed_repos import LOC_MAX, LOC_MIN

OSV_ZIP = Path("data/raw/osv/PyPI-all-2026-09-27.zip")
OUT = Path("data/interim/validation")
REPOS = Path("data/interim/repos")

# Excluded by hand in 2.2, with the reason recorded in BUILD_PLAN.
EXCLUDED = {"GHSA-j6cv-98jx-mrwr": "the vulnerable code is PHP"}


def event_id(repo: str, advisory: str) -> str:
    return f"{repo.split('/')[1].removesuffix('_legacy')}-{advisory.split('-')[1]}"


def missing_blobs(clone: Path, commit: str) -> list[str]:
    tree = git(clone, "ls-tree", "-r", commit).stdout.splitlines()
    oids = [line.split()[2] for line in tree if line.endswith(".py") and line.split()[1] == "blob"]
    if not oids:
        return []
    done = subprocess.run(["git", "-C", str(clone), "cat-file", "--batch-check"],
                          input="\n".join(oids) + "\n", capture_output=True, text=True,
                          env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})
    return [line.split()[0] for line in done.stdout.splitlines() if line.endswith(" missing")]


def prefetch(clone: Path, commits: list[str]) -> int:
    missing = sorted({oid for c in commits for oid in missing_blobs(clone, c)})
    if missing:
        subprocess.run(["git", "-C", str(clone), "-c", "fetch.negotiationAlgorithm=noop", "fetch",
                        "origin", "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no",
                        "--filter=blob:none", "--stdin"],
                       input="\n".join(missing) + "\n", capture_output=True, text=True, check=True)
        still = sorted({oid for c in commits for oid in missing_blobs(clone, c)})
        if still:
            raise RuntimeError(f"{clone}: {len(still)} blobs still missing after prefetch")
    return len(missing)


def main() -> int:
    events = json.loads(Path("data/fix_pairs.json").read_text(encoding="utf-8"))["events"]
    review = {r["advisory"]: r for r in
              json.loads(Path("data/fix_review.json").read_text(encoding="utf-8"))["advisories"]}
    osv = zipfile.ZipFile(OSV_ZIP)

    grouped: dict[tuple[str, str, str], list[dict]] = {}
    for e in events:
        loc = (e.get("loc_at_vulnerable") or {}).get("source")
        if (e["role"] != "selected" or not e["vulnerable_commit"] or e["advisory"] in EXCLUDED
                or not LOC_MIN <= (loc or 0) <= LOC_MAX):
            continue
        grouped.setdefault((e["repo"], e["fix_commit"], e["vulnerable_commit"]), []).append(e)

    work = []
    fetched: dict[str, int] = {}
    for (repo, fix, vulnerable), members in grouped.items():
        members.sort(key=lambda m: m["advisory"])
        advisories = [m["advisory"] for m in members]
        eid = event_id(repo, advisories[0])
        clone = (REPOS / repo.replace("/", "__")).resolve()
        fetched[repo] = fetched.get(repo, 0) + prefetch(clone, [fix, vulnerable])

        d = (OUT / eid).resolve()
        (d / "advisories").mkdir(parents=True, exist_ok=True)
        for a in advisories:
            (d / "advisories" / f"{a}.json").write_bytes(osv.read(f"{a}.json"))
        header = git(clone, "show", "-s", "--format=commit %H%nparents %P%ndate %cI%n%n%B", fix).stdout
        diff = git(clone, "diff", "-M", "--stat", "--patch", vulnerable, fix).stdout
        (d / "fix.patch").write_text(header + "\n" + diff, encoding="utf-8")
        (d / "review_2_2.json").write_text(
            json.dumps([review.get(a) for a in advisories], indent=2, ensure_ascii=False),
            encoding="utf-8")
        work.append({
            "event_id": eid,
            "advisories": advisories,
            "cves": [m["cve"] for m in members],
            "repo": repo,
            "classes": sorted({c for m in members for c in m["classes"]}),
            "clean_commit": fix,
            "regressed_commit": vulnerable,
            "flags": sorted({f for m in members for f in m["flags"]}),
            "clone": str(clone),
            "inputs": str(d),
            "event_dir": str((Path("data/events") / eid).resolve()),
        })

    json.dump(work, sys.stdout, indent=1)
    print(f"\n{len(work)} events; blobs prefetched: {fetched}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
