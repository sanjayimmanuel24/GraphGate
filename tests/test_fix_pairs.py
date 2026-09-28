"""Tests for resolving advisories to vulnerable/fixed commit pairs."""

import os
import subprocess
from pathlib import Path

import pytest

from graphgate.dataset.fix_pairs import (
    _rename_target,
    choose_fix,
    classify_path,
    detect_licence,
    ensure_clone,
    resolve_advisory,
)

MIT = "MIT License\n\nPermission is hereby granted, free of charge, to any person...\n"
GPL = "GNU GENERAL PUBLIC LICENSE\nVersion 3\n... see also the Apache License for ...\n"


# --- Pure logic -----------------------------------------------------------


def cand(sha, on_default, at, resolved=True):
    return {"sha": sha, "resolved": resolved, "on_default_branch": on_default, "committed_at": at}


def test_main_line_fix_beats_an_earlier_backport():
    chosen, flags = choose_fix([
        cand("backport", False, "2024-01-01T00:00:00+00:00"),
        cand("mainline", True, "2024-03-01T00:00:00+00:00"),
    ])
    assert chosen["sha"] == "mainline"
    assert "2 candidate fix commits (backports or multi-part fix)" in flags


def test_earliest_main_line_commit_wins():
    chosen, _ = choose_fix([
        cand("later", True, "2024-03-01T00:00:00+00:00"),
        cand("earlier", True, "2024-02-01T00:00:00+00:00"),
    ])
    assert chosen["sha"] == "earlier"


def test_timezones_are_normalised_before_comparing():
    """08:00+05:30 is 02:30 UTC — earlier than 03:00+00:00 despite sorting later as text."""
    chosen, _ = choose_fix([
        cand("utc", True, "2024-01-01T03:00:00+00:00"),
        cand("ist", True, "2024-01-01T08:00:00+05:30"),
    ])
    assert chosen["sha"] == "ist"


def test_off_main_line_fix_is_used_but_flagged():
    chosen, flags = choose_fix([cand("only", False, "2024-01-01T00:00:00+00:00")])
    assert chosen["sha"] == "only"
    assert "no fix commit is on the default branch" in flags


def test_nothing_resolvable_yields_no_pair():
    chosen, flags = choose_fix([{"sha": "abc", "resolved": False}])
    assert chosen is None
    assert flags == ["no fix commit could be resolved"]


@pytest.mark.parametrize("path, kind", [
    ("pkg/db.py", "py-source"),
    ("tests/test_db.py", "py-test"),
    ("pkg/tests/helpers.py", "py-test"),
    ("pkg/test_db.py", "py-test"),
    ("pkg/db_test.py", "py-test"),
    ("conftest.py", "py-test"),
    ("docs/conf.py", "py-test"),
    ("CHANGELOG.md", "other"),
    ("pkg/static/app.js", "other"),
])
def test_classify_path(path, kind):
    assert classify_path(path) == kind


@pytest.mark.parametrize("text, expected", [
    (MIT, "MIT"),
    ("Apache License\nVersion 2.0, January 2004", "Apache-2.0"),
    ("Redistribution and use in source and binary forms ... Neither the name of", "BSD-3-Clause"),
    ("Redistribution and use in source and binary forms ...", "BSD-2-Clause"),
    (GPL, "GPL"),  # mentions Apache, but copyleft markers are checked first
    ("All rights reserved.", None),
])
def test_detect_licence(text, expected):
    assert detect_licence(text) == expected


@pytest.mark.parametrize("raw, target", [
    ("pkg/{old => new}/db.py", "pkg/new/db.py"),
    ("pkg/{ => sub}/db.py", "pkg/sub/db.py"),
    ("old.py => new.py", "new.py"),
])
def test_rename_target(raw, target):
    assert _rename_target(raw) == target


# --- Against a real git history -------------------------------------------


class Origin:
    """A throwaway upstream repository with controllable commit dates."""

    def __init__(self, root: Path):
        self.root = root
        root.mkdir()
        self.run("init", "--quiet", "--initial-branch=main")
        self.run("config", "uploadpack.allowFilter", "true")
        self.tick = 0

    def run(self, *args):
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        if self.__dict__.get("tick") is not None:
            stamp = f"2024-01-{1 + self.tick:02d}T00:00:00+00:00"
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = stamp
        return subprocess.run(["git", "-C", str(self.root), *args], env=env,
                              capture_output=True, text=True, check=True).stdout.strip()

    def commit(self, files: dict[str, str], message: str) -> str:
        for rel, text in files.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        self.run("add", "-A")
        self.tick += 1
        self.run("commit", "--quiet", "-m", message)
        return self.run("rev-parse", "HEAD")

    @property
    def url(self) -> str:
        return self.root.resolve().as_uri()


@pytest.fixture
def history(tmp_path):
    origin = Origin(tmp_path / "origin")
    origin.commit({"LICENSE": MIT, "pkg/db.py": "def q(x):\n    return x\n"}, "initial")
    vulnerable = origin.commit(
        {"pkg/db.py": "def q(x):\n    return 'SELECT ' + x\n"}, "add query"
    )
    origin.run("branch", "release-1", vulnerable)
    fix = origin.commit(
        {"pkg/db.py": "def q(x):\n    return ('SELECT ?', (x,))\n",
         "tests/test_db.py": "def test_q():\n    assert q\n"},
        "fix injection",
    )
    origin.run("checkout", "--quiet", "release-1")
    backport = origin.commit(
        {"pkg/db.py": "def q(x):\n    return ('SELECT ?', (x,))\n"}, "backport fix"
    )
    origin.run("checkout", "--quiet", "main")
    clone = ensure_clone(origin.url, tmp_path / "clone")
    return {"origin": origin, "clone": clone, "vulnerable": vulnerable,
            "fix": fix, "backport": backport}


def advisory(*shas):
    return {"id": "GHSA-test", "cve": "CVE-2024-0001", "classes": ["sql"],
            "summary": "SQL injection", "fix_commits": list(shas)}


def test_resolves_the_main_line_fix_and_its_parent(history):
    result = resolve_advisory(history["clone"], advisory(history["backport"], history["fix"]), "MIT")

    assert result["fix_commit"] == history["fix"]
    assert result["vulnerable_commit"] == history["vulnerable"]
    assert "2 candidate fix commits (backports or multi-part fix)" in result["flags"]


def test_records_changed_files_by_kind(history):
    result = resolve_advisory(history["clone"], advisory(history["fix"]), "MIT")

    kinds = {f["path"]: f["kind"] for f in result["changed_files"]}
    assert kinds == {"pkg/db.py": "py-source", "tests/test_db.py": "py-test"}
    assert result["py_source_files_changed"] == 1


def test_counts_lines_and_reads_licence_at_the_vulnerable_commit(history):
    result = resolve_advisory(history["clone"], advisory(history["fix"]), "MIT")

    # pkg/db.py at the vulnerable commit: two non-blank lines; no tests yet.
    assert result["loc_at_vulnerable"] == {"total": 2, "source": 2}
    assert result["licence_at_vulnerable"] == {"file": "LICENSE", "detected": "MIT"}
    assert not any("licence" in f for f in result["flags"])


def test_flags_a_licence_that_differed_at_the_vulnerable_commit(tmp_path):
    origin = Origin(tmp_path / "origin")
    origin.commit({"LICENSE": GPL, "a.py": "x = 1\n"}, "gpl era")
    fix = origin.commit({"LICENSE": MIT, "a.py": "x = 2\n"}, "relicense and fix")
    clone = ensure_clone(origin.url, tmp_path / "clone")

    result = resolve_advisory(clone, advisory(fix), "MIT")

    assert result["licence_at_vulnerable"]["detected"] == "GPL"
    assert any("looks like GPL, not MIT" in f for f in result["flags"])


def test_flags_a_fix_that_touches_no_python_source(tmp_path):
    origin = Origin(tmp_path / "origin")
    origin.commit({"LICENSE": MIT, "a.py": "x = 1\n", "app.js": "a()\n"}, "start")
    fix = origin.commit({"app.js": "b()\n"}, "js-only fix")
    clone = ensure_clone(origin.url, tmp_path / "clone")

    result = resolve_advisory(clone, advisory(fix), "MIT")

    assert "fix changes no Python source file" in result["flags"]


def test_flags_a_fix_that_is_mostly_non_python_code(tmp_path):
    """A PHP fix that also bumps a version string in a .py file is not a Python fix."""
    origin = Origin(tmp_path / "origin")
    origin.commit({"LICENSE": MIT, "pkg/__init__.py": "__version__ = '1.0'\n",
                   "web/gen.php": "<?php\nexec($a);\nexec($b);\n"}, "start")
    fix = origin.commit({"pkg/__init__.py": "__version__ = '1.1'\n",
                         "web/gen.php": "<?php\nexec(escapeshellarg($a));\nexec(escapeshellarg($b));\n"},
                        "escape shell arguments")
    clone = ensure_clone(origin.url, tmp_path / "clone")

    result = resolve_advisory(clone, advisory(fix), "MIT")

    assert any("more non-Python code (4 lines) than Python source (2 lines)" in f
               for f in result["flags"])


def test_a_python_fix_with_tests_is_not_flagged_as_non_python(history):
    result = resolve_advisory(history["clone"], advisory(history["fix"]), "MIT")

    assert not any("non-Python" in f for f in result["flags"])


def test_given_vulnerable_commit_replaces_the_first_parent(history):
    """A fix spread over commits: the pair spans them from the given ancestor."""
    initial = history["origin"].run("rev-parse", "main~2")

    result = resolve_advisory(history["clone"], advisory(history["fix"]), "MIT",
                              vulnerable_commit=initial)

    assert result["vulnerable_commit"] == initial
    assert result["fix_commit"] == history["fix"]
    # pkg/db.py at the initial commit has two non-blank lines, same as before.
    assert result["loc_at_vulnerable"] == {"total": 2, "source": 2}


def test_given_vulnerable_commit_off_the_fix_history_yields_no_pair(history):
    result = resolve_advisory(history["clone"], advisory(history["fix"]), "MIT",
                              vulnerable_commit=history["backport"])

    assert result["vulnerable_commit"] is None
    assert result["flags"] == [
        f"given vulnerable commit {history['backport']} is not an ancestor of the fix"
    ]


def test_advisory_linking_no_commit_is_flagged_distinctly(history):
    result = resolve_advisory(history["clone"], advisory(), "MIT")

    assert result["fix_commit"] is None
    assert result["flags"] == ["no fix commit linked by the advisory"]


def test_unresolvable_commit_yields_no_pair(history):
    result = resolve_advisory(history["clone"], advisory("f" * 40), "MIT")

    assert result["fix_commit"] is None
    assert result["vulnerable_commit"] is None
    assert result["flags"] == ["no fix commit could be resolved"]
