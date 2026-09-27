"""Build data/seed_repos.json — the seed repository set (BUILD_PLAN 2.1).

Reproducible from the raw OSV export: re-extracts the injection advisories,
re-fetches each repo's licence, re-counts its lines, and checks every
constraint rather than trusting an earlier screening run.

The *selection* is a human decision (2026-09-27) recorded below with its
reasons; this script only verifies and records it.

    python scripts/build_seed_manifest.py data/raw/osv/PyPI-all-2026-09-27.zip
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from datetime import date
from pathlib import Path

from graphgate.dataset.advisories import (
    INJECTION_CWES,
    extract_injection_advisories,
    group_by_repo,
    load_osv_zip,
)
from graphgate.dataset.seed_repos import (
    LOC_MAX,
    LOC_MIN,
    NON_SOURCE_DIRS,
    PERMISSIVE,
    fetch_repo_meta,
    licence_status,
    measure_repo,
)

# The 7 permissive, in-range projects with two or more usable advisories, plus
# 5 with SQL injection — SQL is scarce (6 of the pool's 100 usable advisories
# in range) and is the proposal's canonical cross-file taint case. Of the SQL
# projects, alerta and pycsw are web services with request-to-SQL flows; the
# three ORMs exercise query construction itself.
SELECTED = [
    "gitpython-developers/gitpython",
    "parisneo/lollms",
    "datadog/guarddog",
    "ietf-tools/xml2rfc",
    "zauberzeug/nicegui",
    "mar10/wsgidav",
    "sqlalchemy/mako",
    "alerta/alerta",
    "geopython/pycsw",
    "piccolo-orm/piccolo",
    "tortoise/tortoise-orm",
    "collerek/ormar",
]

# Swapped in if BUILD_PLAN 2.3 validation drops events below the M1 target.
# copier is 15 lines under LOC_MIN on the source-only rule; it is listed so the
# near-miss is visible, and would need that rule revisited to be used.
RESERVE = [
    "geopandas/geopandas",
    "laowantong/mocodo",
    "parsl/parsl",
    "copier-org/copier",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("osv_zip", type=Path)
    parser.add_argument("--out", type=Path, default=Path("data/seed_repos.json"))
    parser.add_argument("--clones", type=Path, default=Path("data/interim/clones"))
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    advisories, skipped = extract_injection_advisories(load_osv_zip(args.osv_zip))
    groups = group_by_repo(advisories)
    today = date.today().isoformat()
    problems: list[str] = []

    def entry(repo: str, role: str) -> dict:
        advs = groups.get(repo, [])
        meta = fetch_repo_meta(repo)
        measured = measure_repo(repo, args.clones)
        status = licence_status(meta.licence)
        in_range = LOC_MIN <= measured["source"] <= LOC_MAX
        if role == "selected":
            if not advs:
                problems.append(f"{repo}: no usable advisory")
            if status != "permissive":
                problems.append(f"{repo}: licence {meta.licence!r} is {status}")
            if not in_range:
                problems.append(f"{repo}: {measured['source']} source LOC outside {LOC_MIN}-{LOC_MAX}")
            if meta.archived:
                problems.append(f"{repo}: archived")
        return {
            "repo": repo,
            "url": f"https://github.com/{repo}",
            "role": role,
            "licence": meta.licence,
            "licence_status": status,
            "loc_source": measured["source"],
            "loc_total": measured["total"],
            "loc_in_range": in_range,
            # Licence and size were checked at this commit (the default branch
            # on the verification date). Per-event vulnerable commits are pinned
            # in BUILD_PLAN 2.2-2.3, where licence and size are re-checked.
            "verified_at_commit": measured["commit"],
            "verified_on": today,
            # Repository-level holdout (BUILD_PLAN 5.4) is assigned before any
            # rule or allowlist tuning; null until then.
            "holdout": None,
            "advisories": [
                {
                    "id": a.id,
                    "cve": a.cve,
                    "cwes": a.cwes,
                    "classes": a.classes,
                    "summary": a.summary,
                    "fix_commits": a.fix_commits,
                }
                for a in sorted(advs, key=lambda a: a.id)
            ],
        }

    repos = [entry(r, "selected") for r in SELECTED] + [entry(r, "reserve") for r in RESERVE]

    manifest = {
        "schema_version": 1,
        "status": "provisional — final after BUILD_PLAN 2.3 validation",
        "decisions": {
            "seed_repo_reading": "A: seed repos are the projects whose real injection-class "
            "CVE fixes supply the ground truth (2026-09-27)",
            "loc_rule": "non-blank lines in .py files, excluding directories named "
            + ", ".join(sorted(NON_SOURCE_DIRS)),
            "loc_range": [LOC_MIN, LOC_MAX],
            "licences_accepted": sorted(PERMISSIVE),
            "injection_cwes": INJECTION_CWES,
        },
        "source": {
            "dataset": "OSV PyPI export",
            "url": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
            "file": args.osv_zip.name,
            "sha256": sha256(args.osv_zip),
            "retrieved": "2026-09-27",
            "funnel": {
                "injection_advisories": len(advisories),
                "skipped": skipped,
                "usable_with_fix_commit": sum(len(v) for v in groups.values()),
                "repos_with_usable_advisories": len(groups),
            },
        },
        "repos": repos,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                        encoding="utf-8", newline="\n")

    sel = [r for r in repos if r["role"] == "selected"]
    classes: dict[str, int] = {}
    for r in sel:
        for a in r["advisories"]:
            for c in a["classes"]:
                classes[c] = classes.get(c, 0) + 1
    print(f"wrote {args.out}: {len(sel)} selected, {len(repos) - len(sel)} reserve, "
          f"{sum(len(r['advisories']) for r in sel)} advisories in selection {classes}")
    for p in problems:
        print("PROBLEM:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
