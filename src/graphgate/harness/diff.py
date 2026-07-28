"""Unified diffs between two snapshots.

The harness computes the diff itself rather than asking the model to emit one.
Models produce invalid hunks often enough that failed patch applications would
become a confound in the degradation curve.
"""

from __future__ import annotations

import difflib

from graphgate.harness.snapshot import Snapshot


def unified_diff(before: Snapshot, after: Snapshot, context: int = 3) -> str:
    """Standard unified diff across every path in either snapshot.

    Covers added, removed, and modified files. Returns an empty string when the
    turn changed nothing — a real and reportable outcome, not an error.
    """
    chunks: list[str] = []
    for path in sorted(set(before.files) | set(after.files)):
        old = before.files.get(path, "")
        new = after.files.get(path, "")
        if old == new:
            continue
        lines = difflib.unified_diff(
            old.splitlines(),
            new.splitlines(),
            fromfile=f"a/{path}" if path in before.files else "/dev/null",
            tofile=f"b/{path}" if path in after.files else "/dev/null",
            n=context,
            lineterm="",
        )
        chunks.extend(lines)
    return "\n".join(chunks)


def changed_paths(before: Snapshot, after: Snapshot) -> list[str]:
    """Paths whose content differs. This is the seed set for the ΔG
    neighbourhood in M2.1 — the harness records it now so the graph layer
    doesn't have to recompute it from the diff text later."""
    return sorted(
        path
        for path in set(before.files) | set(after.files)
        if before.files.get(path) != after.files.get(path)
    )
