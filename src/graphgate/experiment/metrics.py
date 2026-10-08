"""The study's measures, from the tidy table alone (BUILD_PLAN 3.4, proposal 7.2).

Everything here is computed from the rows ``runner`` writes, so a figure in
the paper can be re-derived from one CSV file.

- **Degradation curve**: regressions surviving after each iteration, per
  condition.
- **Recall at introduction**: of the turns that bring a regression in, the
  share a condition blocks. This is the measure least touched by carried
  labels, because the introducing turn is always read off the code.
- **Iterations to detection**: turns between a regression's introduction and
  the first BLOCK while it is present; 0 when it is blocked on arrival.
- **False blocks**, in both readings of the proposal's "fraction of BLOCK
  decisions on clean turns": the share of clean turns that are blocked, and
  the share of blocks that fall on clean turns (one minus precision). Clean
  turns whose label was carried are reported apart from those read off the
  code (CLAUDE.md, turn labels). Beside them, the stricter reading: blocks on
  every turn that introduces nothing, which adds the turns where the
  regression is already in the code and the turn's own change is not it.
- **Overhead**: time per stage and tokens per judged turn. The scan time that
  counts is the one measured outside the batched run, where it was measured.
"""

from __future__ import annotations

import csv
import statistics
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from graphgate.dataset.labels import CARRIED
from graphgate.experiment.runner import COLUMNS, ROLE_CLEAN, ROLE_INTRODUCING, ROLE_PERSISTING
from graphgate.gate.local import BLOCK

_BOOLEANS = ("regression_present", "caught", "surviving", "model_call", "cached")
_INTEGERS = ("seed", "iteration", "items", "items_exploitable", "items_uncertain", "findings_introduced", "flags",
             "input_tokens", "output_tokens")
_FLOATS = ("scan_seconds", "graph_seconds", "scan_seconds_unbatched", "triage_ms")


def write_rows(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def read_rows(path: Path) -> list[dict[str, Any]]:
    """The table as written, with numbers and truth values back in their types."""
    rows = []
    with path.open(encoding="utf-8", newline="") as handle:
        for raw in csv.DictReader(handle):
            row: dict[str, Any] = dict(raw)
            for name in _BOOLEANS:
                row[name] = "" if raw[name] == "" else raw[name] == "True"
            for name in _INTEGERS:
                row[name] = "" if raw[name] == "" else int(raw[name])
            for name in _FLOATS:
                row[name] = "" if raw[name] == "" else float(raw[name])
            rows.append(row)
    return rows


def _share(part: int, whole: int) -> float | None:
    return round(part / whole, 4) if whole else None


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 4) if values else None


def _recall(rows: list[dict[str, Any]]) -> dict[str, Any]:
    blocked = sum(r["decision"] == BLOCK for r in rows)
    return {"introduced": len(rows), "blocked": blocked, "recall": _share(blocked, len(rows))}


def _detections(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Per regression: whether it was ever caught while present, and after how many turns."""
    delays = []
    regressions = 0
    by_replication: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in rows:
        by_replication.setdefault((row["trace_id"], row["seed"]), []).append(row)
    for turns in by_replication.values():
        introduced_at = None
        for row in sorted(turns, key=lambda r: r["iteration"]):
            if row["role"] == ROLE_INTRODUCING:
                introduced_at = row["iteration"]
                regressions += 1
                caught = False
            elif not row["regression_present"]:
                introduced_at = None
            if introduced_at is not None and row["decision"] == BLOCK and not caught:
                caught = True
                delays.append(row["iteration"] - introduced_at)
    return {"regressions": regressions, "detected": len(delays), "detected_share": _share(len(delays), regressions),
            "mean_iterations_to_detection": round(statistics.mean(delays), 3) if delays else None,
            "detected_on_arrival": sum(d == 0 for d in delays)}


def _curve(rows: list[dict[str, Any]], iterations: list[int]) -> list[dict[str, int]]:
    """Regressions surviving after each iteration, over all replications.

    Traces differ in length. A replication that has ended keeps the state it
    ended in: the code is still there, with or without its regression. Without
    this the count would fall as the shorter traces run out.
    """
    by_replication: dict[tuple[str, int], dict[int, bool]] = {}
    for row in rows:
        by_replication.setdefault((row["trace_id"], row["seed"]), {})[row["iteration"]] = row["surviving"] is True
    curve = []
    for t in iterations:
        states = [turns[max(i for i in turns if i <= t)] for turns in by_replication.values()
                  if any(i <= t for i in turns)]
        curve.append({"iteration": t, "surviving": sum(states), "replications": len(by_replication),
                      "replications_still_running": sum(t in turns for turns in by_replication.values())})
    return curve


def _condition(rows: list[dict[str, Any]]) -> dict[str, Any]:
    judged = [r for r in rows if r["decision"] != ""]
    blocks = [r for r in judged if r["decision"] == BLOCK]
    clean = [r for r in judged if r["role"] == ROLE_CLEAN]
    read_off = [r for r in clean if r["basis"] != CARRIED]
    introducing = [r for r in judged if r["role"] == ROLE_INTRODUCING]
    persisting = [r for r in judged if r["role"] == ROLE_PERSISTING]
    on_regression = [r for r in blocks if r["role"] in (ROLE_INTRODUCING, ROLE_PERSISTING)]

    def false_blocks(turns: list[dict[str, Any]]) -> dict[str, Any]:
        blocked = sum(r["decision"] == BLOCK for r in turns)
        return {"clean_turns": len(turns), "blocked": blocked, "rate": _share(blocked, len(turns))}

    calls = [r for r in judged if r["model_call"] is True]
    timed = [r for r in judged if r["scan_seconds_unbatched"] != ""]
    added = [r["scan_seconds_unbatched"] + (r["graph_seconds"] or 0) + (r["triage_ms"] or 0) / 1000 for r in timed]
    iterations = sorted({r["iteration"] for r in rows})
    return {
        "turns_judged": len(judged), "blocks": len(blocks),
        "outcomes": dict(sorted(Counter(r["outcome"] for r in judged).items())),
        "recall_at_introduction": {
            "all": _recall(introducing),
            "by_scope": {scope: _recall([r for r in introducing if r["scope"] == scope])
                         for scope in sorted({r["scope"] for r in introducing})},
            "by_class": {cls: _recall([r for r in introducing if r["vulnerability_class"] == cls])
                         for cls in sorted({r["vulnerability_class"] for r in introducing})},
        },
        "detection": _detections(rows),
        "false_blocks": {"all_clean_turns": false_blocks(clean), "labels_read_off_the_code": false_blocks(read_off),
                         "turns_that_introduce_nothing": false_blocks(clean + persisting),
                         "share_of_blocks_on_clean_turns": _share(len(blocks) - len(on_regression), len(blocks)),
                         "precision": _share(len(on_regression), len(blocks))},
        "overhead": {
            "median_graph_seconds": _median([r["graph_seconds"] for r in judged if r["graph_seconds"] != ""]),
            "median_triage_seconds": _median([r["triage_ms"] / 1000 for r in calls if r["triage_ms"] != ""]),
            "median_scan_seconds_unbatched": _median([r["scan_seconds_unbatched"] for r in timed]),
            "median_added_seconds": _median(added), "turns_with_full_timing": len(timed),
            "model_calls": len(calls),
            "mean_input_tokens": round(statistics.mean(r["input_tokens"] for r in calls if r["input_tokens"] != ""), 1)
            if any(r["input_tokens"] != "" for r in calls) else None,
            "mean_output_tokens": round(statistics.mean(r["output_tokens"] for r in calls if r["output_tokens"] != ""), 1)
            if any(r["output_tokens"] != "" for r in calls) else None,
        },
        "degradation_curve": _curve(rows, iterations),
        "per_trace_recall": {trace: _recall([r for r in introducing if r["trace_id"] == trace])["recall"]
                             for trace in sorted({r["trace_id"] for r in introducing})},
    }


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Every measure per condition, and what the traces themselves hold."""
    conditions = list(dict.fromkeys(r["condition"] for r in rows))
    one = [r for r in rows if r["condition"] == conditions[0]] if conditions else []
    labelled = [r for r in one if r["label"] != ""]
    return {
        "traces": {
            "traces": len({r["trace_id"] for r in one}),
            "replications": len({(r["trace_id"], r["seed"]) for r in one}),
            "turns": len(one),
            "turns_by_kind": dict(sorted(Counter(r["kind"] for r in one).items())),
            "turns_by_role": dict(sorted(Counter(r["role"] for r in one).items())),
            "regressions_introduced": sum(r["role"] == ROLE_INTRODUCING for r in one),
            "labels_carried": sum(r["basis"] == CARRIED for r in labelled), "labels": len(labelled),
        },
        "conditions": {name: _condition([r for r in rows if r["condition"] == name]) for name in conditions},
    }
