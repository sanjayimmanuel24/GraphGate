"""Ground-truth labels for every turn of a recorded trace (BUILD_PLAN 2.5).

A turn's label says whether the event's regression is in the code *after*
that turn: ``clean``, ``local_regression`` or ``cross_file_regression``
(proposal §6.1). The turn that brings it in is marked ``introduced``, so both
readings the metrics need are there: where the regression entered, and for
how many turns it survived (§7.2, iterations-to-detection).

The label is read off the code, not assumed from the plan. The regression is
a set of *units* (functions, assignments, imports) that differ between the
event's clean and regressed files; after each turn those units are compared
with both versions, ignoring comments, docstrings and layout:

- all of them match the regressed version -> the regression is present;
- all of them match the clean version     -> it is not;
- anything else: the model has rewritten one of them, and whether the
  regression survived is a judgement this module does not make. The previous
  turn's label is carried forward and the turn is marked ``carried``, so an
  analysis can leave such turns out or have them reviewed.

Scope of the claim: the labels are about the event's regression only. A
weakness the model introduces by itself elsewhere is not labelled, and a
match says the regressed code is unchanged, not that nothing else on the flow
compensates for it.
"""

from __future__ import annotations

import ast
import hashlib
import json
import textwrap
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from graphgate.dataset.events import CROSS_FILE, LOCAL
from graphgate.harness.injection import InjectionPlan, Unit, units
from graphgate.harness.replay import load_records
from graphgate.harness.trace import KIND_INIT, KIND_TURN, TraceRecord

SCHEMA_VERSION = 1

CLEAN = "clean"
LOCAL_REGRESSION = "local_regression"
CROSS_FILE_REGRESSION = "cross_file_regression"
REGRESSION_LABEL = {LOCAL: LOCAL_REGRESSION, CROSS_FILE: CROSS_FILE_REGRESSION}

# How a turn's label was established.
MATCHES_CLEAN = "matches-clean"
MATCHES_REGRESSED = "matches-regressed"
CARRIED = "carried"


class LabelError(RuntimeError):
    """The trace cannot be labelled, or its labels do not belong to it."""


def parse_unit(text: str) -> ast.Module | None:
    """A unit's syntax tree without its docstrings, or None if it does not parse.

    Comments and layout are gone by construction: the tree does not hold them.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)  # e.g. '\\d' in an old non-raw string
            tree = ast.parse(textwrap.dedent(text))
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str)):
            del body[0]
    return tree


def _normalise(unit: Unit) -> str:
    """A unit's code with comments, docstrings and layout taken out."""
    tree = parse_unit(unit.text)
    if tree is None:
        # A class header on its own, or code dedent could not straighten.
        # Stripped lines are a stricter comparison, never a looser one.
        code = textwrap.dedent(unit.text)
        return "text:" + "\n".join(line.strip() for line in code.splitlines() if line.strip())
    return ast.dump(tree)


def _code_units(text: str | None) -> dict[tuple, str]:
    if text is None:
        return {}
    return {u.key: _normalise(u) for u in units(text) if u.key[0] != "comment"}


class Regression:
    """The units that tell an event's clean code from its regressed code."""

    def __init__(self, plan: InjectionPlan):
        self.event_id = plan.event_id
        # path -> key -> (normalised clean unit, normalised regressed unit); None = absent.
        self._differs: dict[str, dict[tuple, tuple[str | None, str | None]]] = {}
        for path in plan.regressed:
            clean, regressed = _code_units(plan.clean[path]), _code_units(plan.regressed[path])
            differing = {key: (clean.get(key), regressed.get(key))
                         for key in clean.keys() | regressed.keys()
                         if clean.get(key) != regressed.get(key)}
            if differing:
                self._differs[path] = differing
        if not self._differs:
            raise LabelError(f"event {plan.event_id}: clean and regressed code differ only in "
                             "comments, docstrings or layout; its turns cannot be labelled")

    def observe(self, files: dict[str, str]) -> str:
        """Which version the regression's units match in ``files``."""
        as_clean = as_regressed = True
        for path, differing in self._differs.items():
            current = _code_units(files.get(path))
            for key, (clean, regressed) in differing.items():
                as_clean = as_clean and current.get(key) == clean
                as_regressed = as_regressed and current.get(key) == regressed
        if as_regressed:
            return MATCHES_REGRESSED
        return MATCHES_CLEAN if as_clean else CARRIED


def label_replication(records: list[TraceRecord], regression: Regression,
                      regression_label: str) -> dict[str, Any]:
    """Labels for one replication's records (its init record first)."""
    label, introduced_at, turns = CLEAN, None, []
    for record in records[1:]:
        if record.kind != KIND_TURN:
            # A refusal or an error: the code did not change and the replication ends.
            turns.append({"turn": record.turn, "kind": record.kind})
            continue
        basis = regression.observe(record.files_after)
        injected = record.injection is not None and record.injection["status"] == "applied"
        if injected and basis != MATCHES_REGRESSED:
            raise LabelError(f"{regression.event_id} seed {record.seed} turn {record.turn}: the trace "
                             "says the regression was injected here, but the code does not hold it")
        previous = label
        if basis == MATCHES_REGRESSED:
            label = regression_label
        elif basis == MATCHES_CLEAN:
            label = CLEAN
        introduced = previous == CLEAN and label != CLEAN
        if introduced and introduced_at is None:
            introduced_at = record.turn
        turns.append({"turn": record.turn, "kind": record.kind, "label": label, "basis": basis,
                      "introduced": introduced, "injected": injected})
    return {"seed": records[0].seed, "introduced_at": introduced_at, "turns": turns}


def trace_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def label_trace(trace_path: Path, scope: str) -> dict[str, Any]:
    """Labels for every replication of a trace. ``scope`` is the event's."""
    records = load_records(trace_path)
    plan = next((r.injection for r in records if r.kind == KIND_INIT), None)
    if plan is None:
        raise LabelError(f"{trace_path}: the trace carries no injection plan")
    regression = Regression(InjectionPlan.from_dict(plan))

    by_seed: dict[int, list[TraceRecord]] = {}
    for record in records:
        by_seed.setdefault(record.seed, []).append(record)
    replications = [label_replication(by_seed[seed], regression, REGRESSION_LABEL[scope])
                    for seed in sorted(by_seed)]

    labelled = [t for rep in replications for t in rep["turns"] if "label" in t]
    tally: dict[str, int] = {}
    for turn in labelled:
        tally[turn["label"]] = tally.get(turn["label"], 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": regression.event_id,
        "trace_sha256": trace_sha256(trace_path),
        "scope": scope,
        "regression_label": REGRESSION_LABEL[scope],
        "injection_turn": plan["turn"],
        "turns_by_label": dict(sorted(tally.items())),
        # Turns whose label was carried forward because the model rewrote the
        # regression's code; an analysis must decide what to do with them.
        "turns_carried": sum(t["basis"] == CARRIED for t in labelled),
        "replications": replications,
    }


def labels_path(trace_path: Path) -> Path:
    return trace_path.with_name(trace_path.stem + ".labels.json")


def write_labels(trace_path: Path, scope: str) -> dict[str, Any]:
    labels = label_trace(trace_path, scope)
    labels_path(trace_path).write_text(json.dumps(labels, indent=2) + "\n",
                                       encoding="utf-8", newline="\n")
    return labels


@dataclass(frozen=True)
class TurnLabel:
    label: str
    basis: str
    introduced: bool
    injected: bool

    @property
    def verified(self) -> bool:
        """False when the label was carried forward rather than read off the code."""
        return self.basis != CARRIED


def load_labels(trace_path: Path) -> dict[tuple[int, int], TurnLabel]:
    """``(seed, turn) -> label`` for a trace's completed turns.

    Refuses labels written for another version of the trace: a label paired
    with the wrong turn would corrupt every metric built on it.
    """
    path = labels_path(trace_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if data["trace_sha256"] != trace_sha256(trace_path):
        raise LabelError(f"{path} was written for a different version of {trace_path.name}; "
                         "run scripts/label_traces.py again")
    return {(rep["seed"], t["turn"]): TurnLabel(t["label"], t["basis"], t["introduced"], t["injected"])
            for rep in data["replications"] for t in rep["turns"] if "label" in t}
