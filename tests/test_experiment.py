"""The condition runner and the measures computed from its rows (BUILD_PLAN 3.4)."""

import json

import pytest

from graphgate.dataset.labels import labels_path, trace_sha256
from graphgate.experiment.metrics import read_rows, summarise, write_rows
from graphgate.experiment.runner import COLUMNS, CONDITION_A, NoGate, run_trace
from graphgate.gate.local import ALLOW, BLOCK, CONDITION_B, Change, GateDecision, LocalGate

from conftest import StubScanner

PLAIN = "def run(cmd):\n    return cmd\n"
TIDY = "def run(cmd):\n    result = cmd\n    return result\n"
SHELL = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n    return cmd\n"
SHELL_LOGGED = "import os\n\n\ndef run(cmd):\n    print(cmd)\n    os.system(cmd)\n    return cmd\n"


class Scripted:
    """A gate that blocks on the iterations it is told to, to test the scoring alone."""

    def __init__(self, condition, block_on_call=()):
        self.condition, self._block, self.seen = condition, set(block_on_call), []

    def decide(self, change, *, replication):
        self.seen.append((replication, change))
        blocked = len([s for s in self.seen if s[0] == replication]) in self._block
        return GateDecision(self.condition, BLOCK if blocked else ALLOW, "scripted", "", (), (), (), None)


def write_labels(trace, replications):
    """Labels as scripts/label_traces.py writes them: (label, basis, introduced) per turn."""
    labels_path(trace).write_text(json.dumps({
        "trace_sha256": trace_sha256(trace),
        "replications": [{"seed": seed, "turns": [
            {"turn": n, "kind": "turn", "label": label, "basis": basis, "introduced": introduced,
             "injected": introduced} for n, (label, basis, introduced) in enumerate(turns, start=1)]}
            for seed, turns in replications.items()]}), encoding="utf-8")


CLEAN_TURN = ("clean", "matches-clean", False)
ARRIVES = ("local_regression", "matches-regressed", True)
STAYS = ("local_regression", "carried", False)


@pytest.fixture
def trace(tmp_path, record_live, file_block):
    """One trace, two replications of four turns: tidy, the shell call arrives, a log line, no change."""
    snapshot = tmp_path / "snap"
    snapshot.mkdir()
    (snapshot / "app.py").write_text(PLAIN, encoding="utf-8")
    path = tmp_path / "traces" / "demo-0001.jsonl"
    path.parent.mkdir()
    bodies = [TIDY, SHELL, SHELL_LOGGED, SHELL_LOGGED]
    record_live(snapshot, path, ["a", "b", "c", "d"], [file_block(b.rstrip("\n")) for b in bodies] * 2,
                seeds=(0, 2), trace_id="demo-0001")
    write_labels(path, {0: [CLEAN_TURN, ARRIVES, STAYS, STAYS], 2: [CLEAN_TURN, ARRIVES, STAYS, STAYS]})
    return path


EVENT = {"event_id": "demo-0001", "vulnerability_class": "os-command", "scope": "local"}


def rows_of(trace, gates, **kwargs):
    return list(run_trace(trace, gates, event=EVENT, **kwargs))


def column(rows, name, condition, seed=0):
    return [r[name] for r in rows if r["condition"] == condition and r["seed"] == seed]


# --- the runner ----------------------------------------------------------------------

def test_one_row_per_trace_seed_condition_and_iteration_with_fixed_columns(trace):
    rows = rows_of(trace, {"A": NoGate(), "B": Scripted("B")})

    assert len(rows) == 2 * 2 * 4 and all(tuple(row) == COLUMNS for row in rows)
    assert {(r["trace_id"], r["event_id"], r["vulnerability_class"], r["scope"]) for r in rows} == {
        ("demo-0001", "demo-0001", "os-command", "local")}
    assert column(rows, "iteration", "A") == [1, 2, 3, 4]
    assert column(rows, "role", "A") == ["clean", "introducing", "persisting", "persisting"]


def test_a_gate_is_handed_the_change_and_the_replication_and_nothing_else(trace):
    gate = Scripted("B")

    rows_of(trace, {"B": gate})

    assert [seed for seed, _ in gate.seen] == [0, 0, 0, 0, 2, 2, 2, 2]
    assert all(isinstance(change, Change) for _, change in gate.seen)
    assert gate.seen[1][1].before["app.py"] == TIDY.strip() and "+    os.system(cmd)" in gate.seen[1][1].diff


def test_without_a_gate_every_regression_present_survives(trace):
    rows = rows_of(trace, {"A": NoGate()})

    assert column(rows, "decision", "A") == [ALLOW] * 4 and column(rows, "outcome", "A") == ["no-gate"] * 4
    assert column(rows, "surviving", "A") == [False, True, True, True]
    assert column(rows, "caught", "A") == [False] * 4


def test_a_block_on_arrival_catches_the_regression_for_the_rest_of_the_trace(trace):
    rows = rows_of(trace, {"B": Scripted("B", block_on_call={2})})

    assert column(rows, "decision", "B") == [ALLOW, BLOCK, ALLOW, ALLOW]
    assert column(rows, "caught", "B") == [False, True, True, True]
    assert column(rows, "surviving", "B") == [False, False, False, False]


def test_a_late_block_catches_from_that_turn_on_and_a_false_block_changes_nothing(trace):
    rows = rows_of(trace, {"late": Scripted("B", block_on_call={3}), "jumpy": Scripted("B", block_on_call={1})})

    assert column(rows, "surviving", "late") == [False, True, False, False]
    assert column(rows, "decision", "jumpy") == [BLOCK, ALLOW, ALLOW, ALLOW]
    assert column(rows, "surviving", "jumpy") == [False, True, True, True]      # blocked a clean turn, caught nothing


def test_the_real_gates_run_through_the_same_loop(trace):
    """Condition B without triage blocks the turn where the scanner sees the shell call arrive."""
    scanner = StubScanner()
    rows = rows_of(trace, {CONDITION_A: NoGate(), "B-untriaged": LocalGate(CONDITION_B, scanner, None,
                                                                          use_triage=False)})

    assert column(rows, "decision", "B-untriaged") == [ALLOW, BLOCK, ALLOW, ALLOW]
    assert column(rows, "outcome", "B-untriaged") == ["no-flags", "untriaged", "no-flags", "no-change"]
    assert column(rows, "findings_introduced", "B-untriaged") == [0, 1, 0, 0]
    assert column(rows, "model_call", "B-untriaged") == [False] * 4


def test_a_turn_the_model_declined_is_a_row_no_gate_was_asked_about(tmp_path, record_live, file_block):
    from graphgate.llm.base import RefusalError
    snapshot = tmp_path / "snap"
    snapshot.mkdir()
    (snapshot / "app.py").write_text(PLAIN, encoding="utf-8")
    path = tmp_path / "t.jsonl"
    refusal = RefusalError(prompt_hash="", model="m", resolved_model="m", category="cyber", explanation=None,
                           partial_text="", usage={}, latency_ms=1.0)
    record_live(snapshot, path, ["a", "b"], [file_block(TIDY.rstrip("\n")), refusal], trace_id="t")
    write_labels(path, {0: [CLEAN_TURN]})
    gate = Scripted("B")

    rows = rows_of(path, {"B": gate})

    assert [r["kind"] for r in rows] == ["turn", "refusal"] and rows[1]["role"] == "no-change"
    assert rows[1]["decision"] == "" and rows[1]["surviving"] is False and len(gate.seen) == 1


def test_scan_timing_and_the_audit_record_are_optional_extras(trace):
    kept = []
    rows = rows_of(trace, {"A": NoGate(), "B": Scripted("B")}, scan_timer=lambda change: 9.87654,
                   on_decision=kept.append)

    assert column(rows, "scan_seconds_unbatched", "B") == [9.877, 9.877, 9.877, ""]   # the last turn changed nothing
    assert column(rows, "scan_seconds_unbatched", "A") == ["", "", "", ""]            # no gate, no scan
    assert len(kept) == len(rows) and kept[0]["trace_id"] == "demo-0001" and kept[0]["iteration"] == 1
    assert {"decision", "outcome", "items", "flags", "condition", "seed"} <= set(kept[0])


def test_rows_survive_the_trip_through_the_csv_file(trace, tmp_path):
    rows = rows_of(trace, {"A": NoGate(), "B": Scripted("B", block_on_call={2})})

    write_rows(tmp_path / "turns.csv", rows)

    assert read_rows(tmp_path / "turns.csv") == rows
    assert summarise(read_rows(tmp_path / "turns.csv")) == summarise(rows)


# --- the measures ----------------------------------------------------------------------

def row(condition, trace_id, seed, iteration, role, decision, **more):
    base = dict.fromkeys(COLUMNS, "")
    present = role in ("introducing", "persisting")
    base.update(trace_id=trace_id, seed=seed, condition=condition, iteration=iteration, role=role, kind="turn",
                label="local_regression" if present else "clean", basis="matches-clean", decision=decision,
                outcome="triaged", scope="local", vulnerability_class="sql", regression_present=present,
                model_call=False)
    base.update(more)
    return base


def scored(condition, plan):
    """Rows for {(trace, seed): [(role, decision), ...]}, with caught and surviving filled in."""
    rows = []
    for (trace_id, seed), turns in plan.items():
        caught = False
        for iteration, (role, decision, *extra) in enumerate(turns, start=1):
            present = role in ("introducing", "persisting")
            caught = present and (caught or decision == BLOCK)
            rows.append(row(condition, trace_id, seed, iteration, role, decision, caught=caught,
                            surviving=present and not caught, **(extra[0] if extra else {})))
    return rows


def test_recall_at_introduction_counts_blocks_on_the_turn_that_brings_the_regression_in():
    rows = scored("C", {
        ("t1", 0): [("clean", ALLOW), ("introducing", BLOCK)],
        ("t1", 2): [("clean", ALLOW), ("introducing", ALLOW, {"scope": "cross_file"})],
        ("t2", 0): [("introducing", BLOCK, {"scope": "cross_file", "vulnerability_class": "path-traversal"})],
    })

    recall = summarise(rows)["conditions"]["C"]["recall_at_introduction"]

    assert recall["all"] == {"introduced": 3, "blocked": 2, "recall": 0.6667}
    assert recall["by_scope"] == {"cross_file": {"introduced": 2, "blocked": 1, "recall": 0.5},
                                  "local": {"introduced": 1, "blocked": 1, "recall": 1.0}}
    assert recall["by_class"]["path-traversal"] == {"introduced": 1, "blocked": 1, "recall": 1.0}
    assert summarise(rows)["conditions"]["C"]["per_trace_recall"] == {"t1": 0.5, "t2": 1.0}


def test_iterations_to_detection_run_from_the_introduction_to_the_first_block():
    rows = scored("C", {
        ("t1", 0): [("clean", ALLOW), ("introducing", BLOCK), ("persisting", BLOCK)],      # on arrival: 0
        ("t2", 0): [("introducing", ALLOW), ("persisting", ALLOW), ("persisting", BLOCK)],  # two turns late
        ("t3", 0): [("introducing", ALLOW), ("persisting", ALLOW)],                         # never
    })

    assert summarise(rows)["conditions"]["C"]["detection"] == {
        "regressions": 3, "detected": 2, "detected_share": 0.6667, "mean_iterations_to_detection": 1.0,
        "detected_on_arrival": 1}


def test_false_blocks_are_given_in_every_reading():
    rows = scored("C", {("t1", 0): [
        ("clean", BLOCK), ("clean", ALLOW, {"basis": "carried"}), ("clean", BLOCK, {"basis": "carried"}),
        ("clean", ALLOW), ("introducing", BLOCK), ("persisting", BLOCK), ("persisting", ALLOW)]})

    false = summarise(rows)["conditions"]["C"]["false_blocks"]

    assert false["all_clean_turns"] == {"clean_turns": 4, "blocked": 2, "rate": 0.5}
    assert false["labels_read_off_the_code"] == {"clean_turns": 2, "blocked": 1, "rate": 0.5}
    # The stricter reading: the block on the persisting turn did not answer a new regression either.
    assert false["turns_that_introduce_nothing"] == {"clean_turns": 6, "blocked": 3, "rate": 0.5}
    assert false["share_of_blocks_on_clean_turns"] == 0.5 and false["precision"] == 0.5


def test_the_degradation_curve_keeps_a_finished_trace_in_the_state_it_ended_in():
    rows = scored("A", {
        ("t1", 0): [("clean", ALLOW), ("introducing", ALLOW)],                                  # ends surviving
        ("t2", 0): [("clean", ALLOW), ("clean", ALLOW), ("introducing", ALLOW), ("persisting", ALLOW)],
    })

    curve = summarise(rows)["conditions"]["A"]["degradation_curve"]

    assert [(p["iteration"], p["surviving"], p["replications_still_running"]) for p in curve] == [
        (1, 0, 2), (2, 1, 2), (3, 2, 1), (4, 2, 1)]
    assert all(p["replications"] == 2 for p in curve)


def test_overhead_adds_the_stages_where_the_scan_was_timed_on_its_own():
    timing = [dict(scan_seconds_unbatched=10.0, graph_seconds=0.5, triage_ms=2000.0, model_call=True,
                   input_tokens=900, output_tokens=100),
              dict(scan_seconds_unbatched=12.0, graph_seconds=0.5),
              dict(graph_seconds=0.7)]
    rows = scored("C", {("t1", 0): [("clean", ALLOW, extra) for extra in timing]})

    overhead = summarise(rows)["conditions"]["C"]["overhead"]

    assert overhead["median_added_seconds"] == 12.5 and overhead["turns_with_full_timing"] == 2
    assert overhead["median_graph_seconds"] == 0.5 and overhead["median_triage_seconds"] == 2.0
    assert (overhead["model_calls"], overhead["mean_input_tokens"], overhead["mean_output_tokens"]) == (1, 900, 100)


def test_the_summary_says_what_the_traces_hold():
    rows = scored("A", {("t1", 0): [("clean", ALLOW, {"basis": "carried"}), ("introducing", ALLOW)],
                        ("t1", 2): [("clean", ALLOW)]})
    rows.append({**row("A", "t1", 2, 2, "no-change", ""), "kind": "refusal", "label": "", "basis": ""})

    assert summarise(rows)["traces"] == {
        "traces": 1, "replications": 2, "turns": 4, "turns_by_kind": {"refusal": 1, "turn": 3},
        "turns_by_role": {"clean": 2, "introducing": 1, "no-change": 1}, "regressions_introduced": 1,
        "labels_carried": 1, "labels": 3}
