"""Tests for seed-repository screening."""

import pytest

from graphgate.dataset.seed_repos import (
    BYTES_PER_LINE,
    RepoMeta,
    count_python_loc,
    licence_status,
)


@pytest.mark.parametrize("spdx", ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"])
def test_licences_named_by_the_proposal_are_permissive(spdx):
    assert licence_status(spdx) == "permissive"


@pytest.mark.parametrize("spdx", ["ISC", "Unlicense", "PostgreSQL"])
def test_permissive_equivalents_need_a_human_decision(spdx):
    """Not named by proposal §6.1, so neither silently accepted nor rejected."""
    assert licence_status(spdx) == "confirm"


@pytest.mark.parametrize("spdx", ["GPL-3.0", "AGPL-3.0", "LGPL-2.1", "MPL-2.0", "CC0-1.0", None])
def test_copyleft_and_unknown_licences_are_excluded(spdx):
    assert licence_status(spdx) == "excluded"


def test_estimated_loc_uses_python_bytes():
    meta = RepoMeta(repo="o/r", found=True, python_bytes=BYTES_PER_LINE * 1000)
    assert meta.estimated_loc == 1000
    assert RepoMeta(repo="o/r", found=False).estimated_loc is None


def test_count_python_loc_skips_blank_lines_and_splits_source_from_tests(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "core.py").write_text("a = 1\n\n\nb = 2\n# comment\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_core.py").write_text("def test():\n    pass\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("not python\n" * 50, encoding="utf-8")

    assert count_python_loc(tmp_path) == {"total": 5, "source": 3}


def test_count_python_loc_ignores_the_git_directory(tmp_path):
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    (tmp_path / ".git" / "hooks" / "x.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "m.py").write_text("y = 2\n", encoding="utf-8")
    assert count_python_loc(tmp_path) == {"total": 1, "source": 1}
