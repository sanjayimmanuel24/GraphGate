"""Repo snapshots: the code state at one turn of a refinement trace.

A snapshot is a mapping of POSIX-relative path to file text. Python only, per
the scope constraint in CLAUDE.md.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Snapshot:
    """An immutable code state. Applying a turn yields a new Snapshot."""

    files: dict[str, str]

    def __post_init__(self) -> None:
        # Checked explicitly rather than via Path.as_posix(): on Linux a
        # backslash is a legal filename character, so that comparison would
        # pass there and fail only on Windows.
        for path in self.files:
            if "\\" in path or PurePosixPath(path).is_absolute():
                raise ValueError(f"snapshot paths must be POSIX-relative: {path!r}")

    def updated(self, changes: dict[str, str]) -> Snapshot:
        """Return a new snapshot with ``changes`` applied over this one.

        Files absent from ``changes`` carry forward untouched — a turn that
        rewrites one file must not silently drop the rest of the repo.
        """
        merged = dict(self.files)
        merged.update(changes)
        return Snapshot(files=merged)

    @property
    def paths(self) -> list[str]:
        return sorted(self.files)


def load_snapshot(directory: Path) -> Snapshot:
    """Read every ``*.py`` file under ``directory`` into a snapshot.

    Non-Python files are skipped and logged rather than silently ignored: the
    unknown/skipped counts are a transparency metric (CLAUDE.md).
    """
    if not directory.is_dir():
        raise NotADirectoryError(f"snapshot directory not found: {directory}")

    files: dict[str, str] = {}
    skipped: list[str] = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(directory).as_posix()
        if path.suffix != ".py":
            skipped.append(rel)
            continue
        files[rel] = path.read_text(encoding="utf-8")

    if skipped:
        log.info(
            "snapshot %s: skipped %d non-Python file(s): %s",
            directory,
            len(skipped),
            ", ".join(skipped),
        )
    if not files:
        raise ValueError(f"snapshot directory contains no .py files: {directory}")

    return Snapshot(files=files)
