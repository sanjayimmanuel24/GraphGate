"""Static-analysis findings and what a change does to them (BUILD_PLAN 3.1).

A finding is one report from Semgrep or Bandit, reduced to the fields both
tools share. The gate cares about the *difference* a turn makes: a pattern
scanner flags the same risky line before and after most edits, and only the
findings that were not there before can be blamed on the change.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Iterable

# The injection family (CLAUDE.md, hard scope constraints): path traversal,
# command injection (general and OS), SQL injection. A parameter everywhere it
# is used, so the family stays a setting rather than a constant in the code.
FAMILY_CWES = frozenset({22, 77, 78, 89})

SEVERITIES = ("low", "medium", "high")


@dataclass(frozen=True)
class Finding:
    tool: str                 # "semgrep" or "bandit"
    rule_id: str
    cwes: tuple[int, ...]
    severity: str             # one of SEVERITIES
    confidence: str | None    # low / medium / high, when the tool gives one
    path: str                 # relative to the snapshot, POSIX
    start_line: int
    end_line: int
    message: str
    code: str                 # the flagged lines, as they stand in the scanned file

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "cwes": list(self.cwes)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(**{**data, "cwes": tuple(data["cwes"])})

    @property
    def identity(self) -> tuple[str, str, str, str]:
        """What makes two reports the same finding across two versions of a file.

        Line numbers are left out because code moves when lines above it
        change, and the flagged code is compared without its whitespace, so a
        turn that only re-indents or re-wraps it does not make it new.
        """
        return (self.tool, self.rule_id, self.path, re.sub(r"\s+", "", self.code))


def cwe_numbers(labels: Any) -> tuple[int, ...]:
    """CWE ids from the forms the tools use: 78, "CWE-78: OS Command ...", or a list."""
    if labels is None:
        return ()
    if isinstance(labels, (str, int)):
        labels = [labels]
    found = []
    for label in labels:
        match = re.search(r"\d+", str(label))
        if match:
            found.append(int(match.group()))
    return tuple(sorted(set(found)))


def in_family(finding: Finding, cwes: Iterable[int] = FAMILY_CWES) -> bool:
    return bool(set(finding.cwes) & set(cwes))


def lines_of(text: str, start_line: int, end_line: int) -> str:
    """Lines ``start_line`` to ``end_line`` (1-based, inclusive) of ``text``."""
    return "\n".join(text.splitlines()[start_line - 1:end_line])


@dataclass(frozen=True)
class ChangeFindings:
    """Findings on the files a change touched, before and after it."""

    before: tuple[Finding, ...]
    after: tuple[Finding, ...]

    @property
    def introduced(self) -> tuple[Finding, ...]:
        """Findings after the change that have no counterpart before it."""
        return _without(self.after, self.before)

    @property
    def resolved(self) -> tuple[Finding, ...]:
        """Findings before the change that are gone after it."""
        return _without(self.before, self.after)


def _without(findings: tuple[Finding, ...], known: tuple[Finding, ...]) -> tuple[Finding, ...]:
    # A multiset difference: three reports of one identity against two known
    # ones leaves one, so a duplicated risky line still counts as new.
    remaining = Counter(f.identity for f in known)
    out = []
    for finding in findings:
        if remaining[finding.identity]:
            remaining[finding.identity] -= 1
        else:
            out.append(finding)
    return tuple(out)
