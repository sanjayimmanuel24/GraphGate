"""The diff-only gates: Condition B and the diff-review baseline B+ (BUILD_PLAN 3.2).

Both see one change, its unified diff, and what Semgrep and Bandit say it
introduces. Neither sees the graph or any code outside the diff.

- **B**, as planned in the proposal: the LLM triages the static findings the
  change introduces. If there are none, the change is allowed without a call.
- **B+**, added with the owner on 2026-10-06: the LLM also judges the change as
  a whole, on every change. The scanners flagged 1 of the 30 validated
  regressions, so B on its own says little; B+ is the strong diff-only check
  GraphGate has to be measured against as well. It is a baseline only: in
  GraphGate itself the LLM still triages flags and nothing else.

A change is blocked when any item is labelled an exploitable regression.
"uncertain" does not block; the label is recorded, so the stricter reading can
be computed afterwards. A refusal, a failed call or an unusable reply never
blocks either, and is recorded as its own outcome, not passed off as a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol

from graphgate.gate.analysers import ChangeScan
from graphgate.gate.findings import Finding
from graphgate.gate.triage import (
    ERROR,
    EXPLOITABLE,
    REFUSED,
    TRIAGED,
    Item,
    change_item,
    finding_items,
    triage,
)
from graphgate.harness.diff import changed_paths, unified_diff
from graphgate.harness.replay import ReplayTurn
from graphgate.harness.snapshot import Snapshot
from graphgate.llm.base import CodeGenClient

CONDITION_B = "B"
CONDITION_B_PLUS = "B+"
LOCAL_CONDITIONS = (CONDITION_B, CONDITION_B_PLUS)

ALLOW = "ALLOW"
BLOCK = "BLOCK"

# How a decision came about: one of these two, or TRIAGED, REFUSED or ERROR
# when the model was asked (graphgate.gate.triage).
NO_CHANGE = "no-change"    # the turn changed nothing
NO_FLAGS = "no-flags"      # nothing to triage, so no model call (Condition B only)
OUTCOMES = (NO_CHANGE, NO_FLAGS, TRIAGED, REFUSED, ERROR)


class Scanner(Protocol):
    def scan_change(self, before: Mapping[str, str], after: Mapping[str, str],
                    changed_paths: Iterable[str]) -> ChangeScan: ...


@dataclass(frozen=True)
class Change:
    """What a gate is shown: two code states and the diff between them.

    Deliberately nothing else. A trace also records which turn carries the
    regression; that is ground truth and must never reach a gate.
    """

    before: Mapping[str, str]
    after: Mapping[str, str]
    changed_paths: tuple[str, ...]
    diff: str

    @classmethod
    def from_turn(cls, turn: ReplayTurn) -> Change:
        return cls(turn.before.files, turn.after.files, tuple(turn.changed_paths), turn.diff)

    @classmethod
    def between(cls, before: Mapping[str, str], after: Mapping[str, str]) -> Change:
        old, new = Snapshot(dict(before)), Snapshot(dict(after))
        return cls(old.files, new.files, tuple(changed_paths(old, new)), unified_diff(old, new))


@dataclass(frozen=True)
class GateDecision:
    condition: str
    decision: str                       # ALLOW or BLOCK
    outcome: str                        # one of OUTCOMES
    rationale: str
    items: tuple[dict[str, Any], ...]   # what was judged: id, kind, text, label, rationale
    findings_introduced: tuple[Finding, ...]
    analysis_errors: tuple[str, ...]    # files a scanner could not fully analyse
    call: dict[str, Any] | None         # the model call, if one was made

    def to_dict(self) -> dict[str, Any]:
        return {
            "condition": self.condition, "decision": self.decision, "outcome": self.outcome,
            "rationale": self.rationale, "items": list(self.items),
            "findings_introduced": [f.to_dict() for f in self.findings_introduced],
            "analysis_errors": list(self.analysis_errors), "call": self.call,
        }


class LocalGate:
    """Condition B or B+ over one change at a time."""

    def __init__(self, condition: str, scanner: Scanner, client: CodeGenClient, *,
                 block_on: Iterable[str] = (EXPLOITABLE,)):
        if condition not in LOCAL_CONDITIONS:
            raise ValueError(f"unknown diff-only condition {condition!r}; expected one of {LOCAL_CONDITIONS}")
        self.condition = condition
        self._scanner = scanner
        self._client = client
        self._block_on = frozenset(block_on)

    def items_for(self, change: Change) -> tuple[list[Item], ChangeScan]:
        """What the model would be asked about ``change``. Makes no model call."""
        scan = self._scanner.scan_change(change.before, change.after, change.changed_paths)
        items = finding_items(scan.findings.introduced)
        if self.condition == CONDITION_B_PLUS:
            items.append(change_item())
        return items, scan

    def decide(self, change: Change, *, replication: int) -> GateDecision:
        if not change.changed_paths:
            return GateDecision(self.condition, ALLOW, NO_CHANGE, "the turn changed nothing", (), (), (), None)
        items, scan = self.items_for(change)
        introduced, errors = scan.findings.introduced, scan.errors
        if not items:
            return GateDecision(self.condition, ALLOW, NO_FLAGS,
                                "the static analysers report nothing introduced by this change",
                                (), introduced, errors, None)

        result = triage(self._client, change.diff, items, replication=replication)
        if not result.ok:
            # Fail open, visibly: a gate that could not judge has not blocked,
            # and the outcome says so instead of posing as a verdict.
            judged = tuple({"id": i.id, "kind": i.kind, "text": i.text, "label": None, "rationale": None}
                           for i in items)
            return GateDecision(self.condition, ALLOW, result.outcome, result.detail or "",
                                judged, introduced, errors, result.call)

        judged = tuple({"id": i.id, "kind": i.kind, "text": i.text, "label": result.verdicts[i.id].label,
                        "rationale": result.verdicts[i.id].rationale} for i in items)
        blocking = [j for j in judged if j["label"] in self._block_on]
        if blocking:
            rationale = " ".join(f"{j['id']}: {j['rationale']}" for j in blocking)
            return GateDecision(self.condition, BLOCK, TRIAGED, rationale, judged, introduced, errors, result.call)
        return GateDecision(self.condition, ALLOW, TRIAGED, "no item was judged an exploitable regression",
                            judged, introduced, errors, result.call)
