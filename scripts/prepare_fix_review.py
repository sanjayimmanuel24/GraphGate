"""Stage inputs for independent review of the 2.2 commit pairs.

For every eligible event, writes to ``data/interim/review/<advisory>/``:

- ``advisory.json`` — the full OSV entry (description, references, versions)
- ``pair.json``     — the automatic resolution from data/fix_pairs.json
- ``fix.patch``     — commit header plus the vulnerable..fix diff

and prints a JSON work list for the review workflow. Patches are generated
here, one repo at a time, so reviewers read local files instead of making
concurrent lazy blob fetches against the same blobless clone.

Eligible: events of selected or reserve repos, excluding those already out on
the size rule at their vulnerable commit (nothing a reviewer finds would bring
them back in). Advisories linking no fix commit become recovery items.

    python scripts/prepare_fix_review.py > data/interim/review/worklist.json
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

from graphgate.dataset.fix_pairs import git
from graphgate.dataset.seed_repos import LOC_MAX, LOC_MIN

OSV_ZIP = Path("data/raw/osv/PyPI-all-2026-09-27.zip")
REVIEW = Path("data/interim/review")
REPOS = Path("data/interim/repos")


def main() -> int:
    events = json.loads(Path("data/fix_pairs.json").read_text(encoding="utf-8"))["events"]
    osv = zipfile.ZipFile(OSV_ZIP)
    names = set(osv.namelist())
    work = []
    for e in events:
        loc = (e.get("loc_at_vulnerable") or {}).get("source")
        if loc is not None and not LOC_MIN <= loc <= LOC_MAX:
            continue
        linked = "no fix commit linked by the advisory" not in e["flags"]
        if linked and not e["vulnerable_commit"]:
            continue  # linked but unresolvable: nothing to review or search
        clone = (REPOS / e["repo"].replace("/", "__")).resolve()
        d = (REVIEW / e["advisory"]).resolve()
        d.mkdir(parents=True, exist_ok=True)
        entry = f"{e['advisory']}.json"
        if entry in names:
            (d / "advisory.json").write_bytes(osv.read(entry))
        (d / "pair.json").write_text(json.dumps(e, indent=2, sort_keys=True), encoding="utf-8")
        item = {
            "kind": "verify" if linked else "recover",
            "advisory": e["advisory"],
            "cve": e["cve"],
            "repo": e["repo"],
            "role": e["role"],
            "classes": e["classes"],
            "summary": e["summary"],
            "clone": str(clone),
            "dir": str(d),
        }
        if linked:
            header = git(clone, "show", "-s", "--format=commit %H%nparents %P%ndate %cI%n%n%B",
                         e["fix_commit"]).stdout
            diff = git(clone, "diff", "-M", "--stat", "--patch",
                       e["vulnerable_commit"], e["fix_commit"]).stdout
            (d / "fix.patch").write_text(header + "\n" + diff, encoding="utf-8")
            item.update({
                "fix_commit": e["fix_commit"],
                "vulnerable_commit": e["vulnerable_commit"],
                "candidates": [c["sha"] for c in e["candidates"]],
                "flags": e["flags"],
            })
        work.append(item)
    json.dump(work, sys.stdout, indent=1)
    print(f"\n{sum(w['kind']=='verify' for w in work)} to verify, "
          f"{sum(w['kind']=='recover' for w in work)} to recover", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
