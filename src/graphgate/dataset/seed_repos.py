"""Seed-repository screening: licence, size, and the manifest (BUILD_PLAN 2.1).

Proposal §6.1 requires 8–12 mid-sized Python projects (5k–50k LOC) under
permissive licences, with licence compliance verified before any trace is
redistributed. Screening happens in two passes because counting lines needs a
clone: a cheap estimate from GitHub's per-language byte counts discards the
obviously out-of-range projects, then the survivors are cloned and counted.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Proposal §6.1 names MIT / Apache-2.0 / BSD. These are the SPDX ids accepted
# as exactly that. Anything else — including other permissive-looking licences
# — is flagged for a human decision rather than silently accepted or rejected.
PERMISSIVE: frozenset[str] = frozenset(
    {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"}
)
# Permissive in substance but not named by the proposal: flag, do not assume.
PERMISSIVE_EQUIVALENT: frozenset[str] = frozenset(
    {"ISC", "0BSD", "PostgreSQL", "Unlicense", "Python-2.0", "Zlib", "BSL-1.0"}
)

# Average bytes per Python source line, used only for the first-pass estimate.
# Deliberately a screening number: the manifest records a real count.
BYTES_PER_LINE = 35

LOC_MIN, LOC_MAX = 5_000, 50_000

# Directories whose files are not the project's own source. Counted separately
# so the manifest shows both totals and the choice stays visible.
NON_SOURCE_DIRS = frozenset(
    {"tests", "test", "testing", "docs", "doc", "examples", "example",
     "benchmarks", "vendor", "vendored", "third_party", "_vendor"}
)


def licence_status(spdx_id: str | None) -> str:
    """'permissive', 'confirm' (permissive-equivalent), or 'excluded'."""
    if spdx_id in PERMISSIVE:
        return "permissive"
    if spdx_id in PERMISSIVE_EQUIVALENT:
        return "confirm"
    return "excluded"


@dataclass
class RepoMeta:
    repo: str
    found: bool
    licence: str | None = None
    archived: bool | None = None
    stars: int | None = None
    default_branch: str | None = None
    python_bytes: int | None = None
    error: str | None = None

    @property
    def estimated_loc(self) -> int | None:
        return None if self.python_bytes is None else self.python_bytes // BYTES_PER_LINE


def _gh_api(path: str) -> Any:
    out = subprocess.run(
        ["gh", "api", path], capture_output=True, text=True, encoding="utf-8"
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or f"gh api {path} failed")
    return json.loads(out.stdout)


def fetch_repo_meta(repo: str) -> RepoMeta:
    """Licence, archive status, and Python byte count from the GitHub API."""
    try:
        info = _gh_api(f"repos/{repo}")
        langs = _gh_api(f"repos/{repo}/languages")
    except RuntimeError as exc:
        log.warning("%s: %s", repo, exc)
        return RepoMeta(repo=repo, found=False, error=str(exc)[:200])
    licence = (info.get("license") or {}).get("spdx_id")
    return RepoMeta(
        repo=repo,
        found=True,
        # GitHub reports "NOASSERTION" when it cannot classify the licence file.
        licence=None if licence in (None, "NOASSERTION") else licence,
        archived=info.get("archived"),
        stars=info.get("stargazers_count"),
        default_branch=info.get("default_branch"),
        python_bytes=langs.get("Python", 0),
    )


def count_python_loc(root: Path) -> dict[str, int]:
    """Non-blank lines in .py files: total, and excluding non-source dirs.

    Blank lines are excluded; comments and docstrings are not — distinguishing
    them reliably needs a parser, and a simple, stated definition matters more
    for a screening threshold than a precise one.
    """
    total = source = 0
    for path in root.rglob("*.py"):
        rel = path.relative_to(root).parts
        if ".git" in rel:
            continue
        try:
            lines = sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        except OSError as exc:
            log.warning("could not read %s: %s", path, exc)
            continue
        total += lines
        if not any(part.lower() in NON_SOURCE_DIRS for part in rel[:-1]):
            source += lines
    return {"total": total, "source": source}


def measure_repo(repo: str, clones_dir: Path) -> dict[str, Any]:
    """Shallow-clone ``repo`` at its default branch and count Python lines.

    Records the commit measured, because a project's size changes over time and
    the manifest must say which snapshot the 5k–50k check applied to. The
    per-event vulnerable commits (BUILD_PLAN 2.2/2.3) are pinned separately.
    """
    dest = clones_dir / repo.replace("/", "__")
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        done = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet",
             f"https://github.com/{repo}.git", str(dest)],
            capture_output=True, text=True,
        )
        if done.returncode != 0:
            raise RuntimeError(f"clone of {repo} failed: {done.stderr.strip()[:200]}")
    head = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    return {"commit": head, **count_python_loc(dest)}


def to_jsonable(obj: Any) -> Any:
    return asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj
