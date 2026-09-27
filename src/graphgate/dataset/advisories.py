"""Injection-class advisories for Python packages, from the OSV PyPI export.

Seed repositories are the projects whose real injection-class CVE fixes supply
the ground truth (decided 2026-09-27, reading (A) of proposal §6.1; see
BUILD_PLAN 2.1). So selection starts here: which repos have such fixes, and how
many.

Why OSV: it aggregates GitHub Security Advisories and the PyPA database, is
current, and links fix commits. Only the GitHub-sourced entries (``GHSA-``)
carry CWE ids; ``PYSEC-`` entries alias them, so GHSA is the base and CVE
aliases deduplicate.
"""

from __future__ import annotations

import json
import logging
import re
import zipfile
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)

# The injection family in scope (CLAUDE.md, hard scope constraints).
# CWE-77 is the general "command injection" weakness; many advisories use it
# instead of CWE-78 for the same class of bug, so excluding it would drop
# in-scope cases rather than narrow scope.
INJECTION_CWES: dict[str, str] = {
    "CWE-89": "sql",
    "CWE-78": "os-command",
    "CWE-77": "command",
    "CWE-22": "path-traversal",
}

_COMMIT_URL = re.compile(
    r"https?://github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?"
    r"/(?:pull/\d+/)?commits?/(?P<sha>[0-9a-fA-F]{7,40})\b"
)
_REPO_URL = re.compile(r"https?://github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$")


@dataclass
class InjectionAdvisory:
    """One injection-class advisory, reduced to what seed selection needs."""

    id: str
    cve: str | None
    cwes: list[str]
    classes: list[str]
    packages: list[str]
    summary: str
    published: str | None
    severity: str | None
    repo: str | None  # "owner/name", lowercased
    fix_commits: list[str] = field(default_factory=list)  # full or abbreviated SHAs
    other_repos: list[str] = field(default_factory=list)  # fix commits found elsewhere

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, ensure_ascii=False)


def load_osv_zip(path: Path) -> list[dict[str, Any]]:
    with zipfile.ZipFile(path) as zf:
        return [json.loads(zf.read(name)) for name in sorted(zf.namelist())]


def _repo_key(owner: str, repo: str) -> str:
    return f"{owner}/{repo}".lower()


def _commits_by_repo(entry: dict[str, Any]) -> dict[str, list[str]]:
    """Fix-commit SHAs referenced by an entry, grouped by GitHub repo."""
    found: dict[str, list[str]] = defaultdict(list)
    for ref in entry.get("references") or []:
        m = _COMMIT_URL.match(ref.get("url", ""))
        if m:
            key = _repo_key(m["owner"], m["repo"])
            sha = m["sha"].lower()
            if sha not in found[key]:
                found[key].append(sha)
    # Git ranges name the fixing commit directly when present.
    for affected in entry.get("affected") or []:
        for rng in affected.get("ranges") or []:
            if rng.get("type") != "GIT":
                continue
            m = _REPO_URL.match(rng.get("repo", ""))
            if not m:
                continue
            key = _repo_key(m["owner"], m["repo"])
            for event in rng.get("events") or []:
                sha = (event.get("fixed") or "").lower()
                if sha and sha not in found[key]:
                    found[key].append(sha)
    return dict(found)


def _package_repo(entry: dict[str, Any]) -> str | None:
    for ref in entry.get("references") or []:
        if ref.get("type") in ("PACKAGE", "REPOSITORY"):
            m = _REPO_URL.match(ref.get("url", ""))
            if m:
                return _repo_key(m["owner"], m["repo"])
    return None


def extract_injection_advisories(
    entries: Iterable[dict[str, Any]],
) -> tuple[list[InjectionAdvisory], dict[str, int]]:
    """Filter to live GHSA advisories carrying an injection-class CWE.

    Returns the advisories and a tally of why others were skipped — reported,
    not dropped silently, so the funnel from raw export to seed set is auditable.
    """
    skipped: dict[str, int] = defaultdict(int)
    seen_cves: set[str] = set()
    result: list[InjectionAdvisory] = []

    for entry in entries:
        eid = entry.get("id", "")
        if not eid.startswith("GHSA-"):
            skipped["not GHSA (no CWE ids)"] += 1
            continue
        if entry.get("withdrawn"):
            skipped["withdrawn"] += 1
            continue
        cwes = sorted(
            set((entry.get("database_specific") or {}).get("cwe_ids") or [])
            & set(INJECTION_CWES)
        )
        if not cwes:
            skipped["no injection-class CWE"] += 1
            continue

        cve = next((a for a in entry.get("aliases") or [] if a.startswith("CVE-")), None)
        if cve and cve in seen_cves:
            skipped["duplicate CVE"] += 1
            continue
        if cve:
            seen_cves.add(cve)

        commits = _commits_by_repo(entry)
        package_repo = _package_repo(entry)
        if commits:
            # The repo carrying the most fix commits is the project's own; a
            # vendored copy or fork occasionally appears alongside it.
            repo = max(commits, key=lambda k: (len(commits[k]), k == package_repo))
        else:
            repo = package_repo

        ds = entry.get("database_specific") or {}
        result.append(
            InjectionAdvisory(
                id=eid,
                cve=cve,
                cwes=cwes,
                classes=sorted({INJECTION_CWES[c] for c in cwes}),
                packages=sorted(
                    {a["package"]["name"] for a in entry.get("affected") or [] if "package" in a}
                ),
                summary=entry.get("summary", ""),
                published=entry.get("published"),
                severity=ds.get("severity"),
                repo=repo,
                fix_commits=commits.get(repo, []) if repo else [],
                other_repos=sorted(k for k in commits if k != repo),
            )
        )
        if repo is None:
            log.info("%s: no GitHub repository could be identified", eid)
        elif not commits.get(repo):
            log.info("%s: repository %s identified but no fix commit linked", eid, repo)

    return result, dict(skipped)


def group_by_repo(advisories: Iterable[InjectionAdvisory]) -> dict[str, list[InjectionAdvisory]]:
    """Advisories that have a repo *and* at least one fix commit, per repo.

    Without a fix commit there is no vulnerable/fixed pair to invert, so such
    advisories cannot become ground-truth events.
    """
    groups: dict[str, list[InjectionAdvisory]] = defaultdict(list)
    for adv in advisories:
        if adv.repo and adv.fix_commits:
            groups[adv.repo].append(adv)
    return dict(groups)
