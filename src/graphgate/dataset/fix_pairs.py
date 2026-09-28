"""Resolve advisories to vulnerable/fixed commit pairs (BUILD_PLAN 2.2).

For each advisory in ``data/seed_repos.json``:

1. Resolve every linked fix commit in the project's history.
2. Choose the *canonical* fix. Backports copy a fix onto release branches, so
   the main-line commit is preferred: among candidates reachable from the
   default branch, the earliest; if none is, the earliest overall, flagged.
3. Take its first parent as the vulnerable commit.
4. Record what changed, and re-check licence and size **at the vulnerable
   commit** — the seed screen (2.1) only checked the default branch today, and
   both can differ years back.

Everything uncertain is flagged rather than guessed; BUILD_PLAN 2.3 is the
manual validation pass that resolves flags.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from graphgate.dataset.seed_repos import NON_SOURCE_DIRS, count_python_loc

log = logging.getLogger(__name__)


class GitError(RuntimeError):
    pass


def git(repo_dir: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    done = subprocess.run(
        ["git", "-C", str(repo_dir), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if check and done.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {done.stderr.strip()[:300]}")
    return done


def ensure_clone(url: str, dest: Path) -> Path:
    """Blobless, no-checkout clone: full history, file contents fetched lazily.

    Several seed repos carry hundreds of megabytes of binary assets that the
    analysis never reads; a blobless clone fetches only the blobs a command
    actually needs.
    """
    if not (dest / ".git").exists() and not (dest / "HEAD").exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        done = subprocess.run(
            ["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout", url, str(dest)],
            capture_output=True, text=True,
        )
        if done.returncode != 0:
            raise GitError(f"clone {url}: {done.stderr.strip()[:300]}")
    return dest


def resolve_commit(repo_dir: Path, sha: str) -> str | None:
    """Full SHA if the commit exists locally or can be fetched; else None.

    A fix linked from a pull request may not be on any branch (the PR was
    squash-merged, say); GitHub still serves it by SHA, so try one fetch.
    """
    spec = f"{sha}^{{commit}}"
    found = git(repo_dir, "rev-parse", "--verify", "--quiet", spec, check=False)
    if found.returncode == 0:
        return found.stdout.strip()
    git(repo_dir, "fetch", "--quiet", "--filter=blob:none", "origin", sha, check=False)
    found = git(repo_dir, "rev-parse", "--verify", "--quiet", spec, check=False)
    return found.stdout.strip() if found.returncode == 0 else None


def default_branch(repo_dir: Path) -> str:
    ref = git(repo_dir, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD", check=False)
    if ref.returncode == 0:
        return ref.stdout.strip().removeprefix("refs/remotes/")
    return "origin/HEAD"


def is_ancestor(repo_dir: Path, commit: str, of: str) -> bool:
    return git(repo_dir, "merge-base", "--is-ancestor", commit, of, check=False).returncode == 0


def commit_info(repo_dir: Path, sha: str) -> dict[str, Any]:
    out = git(repo_dir, "show", "-s", "--format=%P%x1f%cI%x1f%s", sha).stdout.strip()
    parents, committed_at, subject = out.split("\x1f", 2)
    return {"parents": parents.split(), "committed_at": committed_at, "subject": subject}


def choose_fix(candidates: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, list[str]]:
    """Pick the canonical fix commit among resolved candidates.

    Each candidate needs ``sha``, ``on_default_branch`` and ``committed_at``
    (ISO-8601, which sorts correctly as text for a single timezone offset; the
    offsets are normalised before comparison).
    """
    flags: list[str] = []
    resolved = [c for c in candidates if c.get("resolved")]
    if not resolved:
        return None, ["no fix commit could be resolved"]
    main_line = [c for c in resolved if c["on_default_branch"]]
    pool = main_line or resolved
    if not main_line:
        flags.append("no fix commit is on the default branch")
    if len(resolved) > 1:
        flags.append(f"{len(resolved)} candidate fix commits (backports or multi-part fix)")
    return min(pool, key=lambda c: _utc_key(c["committed_at"])), flags


def _utc_key(iso: str) -> str:
    from datetime import datetime, timezone

    return datetime.fromisoformat(iso).astimezone(timezone.utc).isoformat()


def classify_path(path: str) -> str:
    """'py-source', 'py-test', or 'other' — the split 2.3 needs to judge scope."""
    p = PurePosixPath(path)
    if p.suffix != ".py":
        return "other"
    name = p.name
    in_non_source = any(part.lower() in NON_SOURCE_DIRS for part in p.parts[:-1])
    if in_non_source or name == "conftest.py" or name.startswith("test_") or name.endswith("_test.py"):
        return "py-test"
    return "py-source"


def changed_files(repo_dir: Path, parent: str, fix: str) -> list[dict[str, Any]]:
    """Files changed between the vulnerable commit and the fix, with line counts."""
    numstat = git(repo_dir, "diff", "--numstat", "-M", parent, fix).stdout
    status = git(repo_dir, "diff", "--name-status", "-M", parent, fix).stdout
    kinds: dict[str, str] = {}
    for line in status.splitlines():
        parts = line.split("\t")
        kinds[parts[-1]] = parts[0][0]  # R100 -> R
    files = []
    for line in numstat.splitlines():
        added, deleted, path = line.split("\t", 2)
        if " => " in path:  # rename shown as "a/{old => new}.py" or "old => new"
            path = _rename_target(path)
        files.append({
            "path": path,
            "status": kinds.get(path, "M"),
            "added": None if added == "-" else int(added),  # "-" marks a binary file
            "deleted": None if deleted == "-" else int(deleted),
            "kind": classify_path(path),
        })
    return files


def _rename_target(path: str) -> str:
    m = re.match(r"(.*)\{(.*) => (.*)\}(.*)", path)
    if m:
        return (m[1] + m[3] + m[4]).replace("//", "/")
    return path.split(" => ", 1)[1]


def loc_at_commit(repo_dir: Path, sha: str) -> dict[str, int]:
    """Exact source/total Python line counts at ``sha``.

    Checks out only ``*.py`` files into a throwaway worktree, so a blobless
    clone fetches just those blobs, in one batch.
    """
    tmp = Path(tempfile.mkdtemp(prefix="gg-loc-"))
    wt = tmp / "wt"
    try:
        git(repo_dir, "worktree", "add", "--quiet", "--no-checkout", "--detach", str(wt), sha)
        git(wt, "sparse-checkout", "set", "--no-cone", "*.py")
        git(wt, "checkout", "--quiet")
        return count_python_loc(wt)
    finally:
        git(repo_dir, "worktree", "remove", "--force", str(wt), check=False)
        shutil.rmtree(tmp, ignore_errors=True)


_LICENCE_MARKERS: list[tuple[str, str]] = [
    ("GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL"),
    ("GNU LESSER GENERAL PUBLIC LICENSE", "LGPL"),
    ("GNU GENERAL PUBLIC LICENSE", "GPL"),
    ("Mozilla Public License", "MPL"),
    ("Apache License", "Apache-2.0"),
    ("Permission is hereby granted, free of charge", "MIT"),
    ("Permission to use, copy, modify, and/or distribute", "ISC"),
]


def detect_licence(text: str) -> str | None:
    """Coarse licence family from licence-file text.

    Deliberately coarse: the aim is to catch a project that was under a
    different licence at the vulnerable commit, not to replace a proper
    licence scanner. Copyleft markers are checked first so a GPL file that
    quotes other licences is not misread as permissive.
    """
    for marker, name in _LICENCE_MARKERS:
        if marker.lower() in text.lower():
            return name
    if "redistribution and use in source and binary forms" in text.lower():
        return "BSD-3-Clause" if "neither the name" in text.lower() else "BSD-2-Clause"
    return None


def licence_at_commit(repo_dir: Path, sha: str) -> dict[str, Any]:
    names = git(repo_dir, "ls-tree", "--name-only", sha).stdout.splitlines()
    candidates = [n for n in names if re.match(r"(?i)^(licen[cs]e|copying)(\.|$)", n)]
    if not candidates:
        return {"file": None, "detected": None}
    first = sorted(candidates)[0]
    text = git(repo_dir, "show", f"{sha}:{first}", check=False).stdout
    return {"file": first, "detected": detect_licence(text)}


# Coarse family of each SPDX id, to compare with detect_licence().
_SPDX_FAMILY = {"MIT": "MIT", "Apache-2.0": "Apache-2.0", "BSD-2-Clause": "BSD-2-Clause",
                "BSD-3-Clause": "BSD-3-Clause", "ISC": "ISC"}


# Suffixes of code in other languages. A fix whose change is mostly in these
# files is probably fixing non-Python code, even if it also bumps a version
# string in a .py file.
_OTHER_CODE_SUFFIXES = frozenset({
    ".php", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".rb", ".go",
    ".java", ".c", ".h", ".cc", ".cpp", ".rs", ".sh", ".pl",
})


def _changed_lines(files: list[dict[str, Any]]) -> int:
    return sum((f["added"] or 0) + (f["deleted"] or 0) for f in files)


def resolve_advisory(
    repo_dir: Path,
    advisory: dict[str, Any],
    repo_licence: str | None,
    vulnerable_commit: str | None = None,
) -> dict[str, Any]:
    """Resolve one advisory to a vulnerable/fixed pair.

    ``vulnerable_commit`` overrides the fix's first parent. It is set only by
    a reviewed correction, for a fix spread over several commits where the
    first parent would already contain part of it.
    """
    branch = default_branch(repo_dir)
    if not advisory["fix_commits"]:
        # Distinct from "could not be resolved": nothing was linked, so the fix
        # has to be found by searching the history (see 2.2 recovery).
        return {
            "advisory": advisory["id"], "cve": advisory["cve"],
            "classes": advisory["classes"], "summary": advisory["summary"],
            "default_branch": branch, "candidates": [],
            "fix_commit": None, "vulnerable_commit": None,
            "flags": ["no fix commit linked by the advisory"],
        }
    candidates = []
    for sha in advisory["fix_commits"]:
        full = resolve_commit(repo_dir, sha)
        cand: dict[str, Any] = {"sha": sha, "resolved": full is not None}
        if full:
            cand.update(commit_info(repo_dir, full))
            cand["sha"] = full
            cand["on_default_branch"] = is_ancestor(repo_dir, full, branch)
        candidates.append(cand)

    chosen, flags = choose_fix(candidates)
    result: dict[str, Any] = {
        "advisory": advisory["id"],
        "cve": advisory["cve"],
        "classes": advisory["classes"],
        "summary": advisory["summary"],
        "default_branch": branch,
        "candidates": candidates,
        "fix_commit": None,
        "vulnerable_commit": None,
        "flags": flags,
    }
    if chosen is None:
        return result

    parents = chosen["parents"]
    if vulnerable_commit is not None:
        given = resolve_commit(repo_dir, vulnerable_commit)
        if given is None or given == chosen["sha"] or not is_ancestor(repo_dir, given, chosen["sha"]):
            result["flags"].append(
                f"given vulnerable commit {vulnerable_commit} is not an ancestor of the fix"
            )
            return result
        vulnerable = given
    elif not parents:
        result["flags"].append("fix commit has no parent (root commit)")
        return result
    else:
        if len(parents) > 1:
            result["flags"].append("fix commit is a merge; diff taken against its first parent")
        vulnerable = parents[0]
    files = changed_files(repo_dir, vulnerable, chosen["sha"])
    py_source = [f for f in files if f["kind"] == "py-source"]
    other_code = [f for f in files if PurePosixPath(f["path"]).suffix.lower() in _OTHER_CODE_SUFFIXES]
    if not py_source:
        result["flags"].append("fix changes no Python source file")
    elif _changed_lines(other_code) > _changed_lines(py_source):
        result["flags"].append(
            f"fix changes more non-Python code ({_changed_lines(other_code)} lines) than "
            f"Python source ({_changed_lines(py_source)} lines); check the vulnerable code is Python"
        )
    loc = loc_at_commit(repo_dir, vulnerable)
    licence = licence_at_commit(repo_dir, vulnerable)
    expected = _SPDX_FAMILY.get(repo_licence or "")
    if licence["detected"] is None:
        result["flags"].append("licence at vulnerable commit not recognised; check by hand")
    elif expected and licence["detected"] != expected:
        result["flags"].append(
            f"licence at vulnerable commit looks like {licence['detected']}, "
            f"not {repo_licence} as today"
        )

    result.update({
        "fix_commit": chosen["sha"],
        "fix_committed_at": chosen["committed_at"],
        "fix_subject": chosen["subject"],
        "vulnerable_commit": vulnerable,
        "changed_files": files,
        "py_source_files_changed": len(py_source),
        "loc_at_vulnerable": loc,
        "licence_at_vulnerable": licence,
    })
    return result
