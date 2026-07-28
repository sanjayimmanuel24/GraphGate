"""Tests for snapshot loading and diff computation."""

import pytest

from graphgate.harness.diff import changed_paths, unified_diff
from graphgate.harness.snapshot import Snapshot, load_snapshot


def test_updated_carries_forward_untouched_files():
    """A turn that rewrites one file must not drop the rest of the repo."""
    before = Snapshot({"a.py": "a = 1", "b.py": "b = 2"})
    after = before.updated({"a.py": "a = 99"})
    assert after.files == {"a.py": "a = 99", "b.py": "b = 2"}


def test_updated_does_not_mutate_the_original():
    before = Snapshot({"a.py": "a = 1"})
    before.updated({"a.py": "a = 2"})
    assert before.files == {"a.py": "a = 1"}


def test_rejects_non_posix_paths():
    with pytest.raises(ValueError, match="POSIX-relative"):
        Snapshot({"pkg\\mod.py": "x = 1"})


def test_diff_of_identical_snapshots_is_empty():
    snap = Snapshot({"a.py": "a = 1"})
    assert unified_diff(snap, snap) == ""
    assert changed_paths(snap, snap) == []


def test_diff_reports_modified_lines():
    before = Snapshot({"a.py": "a = 1\nb = 2"})
    after = Snapshot({"a.py": "a = 99\nb = 2"})
    diff = unified_diff(before, after)
    assert "-a = 1" in diff
    assert "+a = 99" in diff
    assert changed_paths(before, after) == ["a.py"]


def test_diff_marks_added_file_against_dev_null():
    before = Snapshot({"a.py": "a = 1"})
    after = before.updated({"new.py": "n = 1"})
    diff = unified_diff(before, after)
    assert "--- /dev/null" in diff
    assert "+++ b/new.py" in diff
    assert changed_paths(before, after) == ["new.py"]


def test_diff_marks_removed_file_against_dev_null():
    before = Snapshot({"a.py": "a = 1", "gone.py": "g = 1"})
    after = Snapshot({"a.py": "a = 1"})
    diff = unified_diff(before, after)
    assert "--- a/gone.py" in diff
    assert "+++ /dev/null" in diff


def test_load_snapshot_reads_python_files_recursively(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "app.py").write_text("a = 1", encoding="utf-8")
    (tmp_path / "pkg" / "db.py").write_text("d = 2", encoding="utf-8")

    snapshot = load_snapshot(tmp_path)
    assert snapshot.paths == ["app.py", "pkg/db.py"]


def test_load_snapshot_skips_non_python_files(tmp_path):
    (tmp_path / "app.py").write_text("a = 1", encoding="utf-8")
    (tmp_path / "README.md").write_text("# docs", encoding="utf-8")

    assert load_snapshot(tmp_path).paths == ["app.py"]


def test_load_snapshot_rejects_directory_with_no_python(tmp_path):
    (tmp_path / "README.md").write_text("# docs", encoding="utf-8")
    with pytest.raises(ValueError, match="no .py files"):
        load_snapshot(tmp_path)


def test_load_snapshot_rejects_missing_directory(tmp_path):
    with pytest.raises(NotADirectoryError):
        load_snapshot(tmp_path / "nope")
