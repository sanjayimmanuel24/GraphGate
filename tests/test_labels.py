"""Tests for turn labels (BUILD_PLAN 2.5)."""

from pathlib import Path

import pytest

from graphgate.config import RunConfig
from graphgate.dataset.labels import (
    CARRIED,
    CLEAN,
    CROSS_FILE_REGRESSION,
    LOCAL_REGRESSION,
    MATCHES_CLEAN,
    MATCHES_REGRESSED,
    LabelError,
    Regression,
    label_trace,
    labels_path,
    load_labels,
    write_labels,
)
from graphgate.dataset.traceplan import injection_plan
from graphgate.harness.driver import RefinementDriver
from graphgate.harness.injection import InjectionPlan
from graphgate.harness.snapshot import load_snapshot
from graphgate.harness.trace import KIND_INIT, TraceWriter
from graphgate.llm.base import RefusalError

EVENTS = Path(__file__).resolve().parent.parent / "data" / "events"

GUARDED = '''\
from checks import check_name


def read(name):
    check_name(name)
    return open(name).read()
'''

UNGUARDED = '''\
def read(name):
    return open(name).read()
'''

VIEWS = '''\
from files import read


def download(request):
    return read(request.args["name"])
'''

PLAN = InjectionPlan.from_files("demo-0001", 2, clean={"files.py": GUARDED, "views.py": VIEWS},
                                regressed={"files.py": UNGUARDED, "views.py": VIEWS})


@pytest.fixture
def record(tmp_path, fake_client):
    """Record a trace from canned replies, with the regression injected at turn 2."""
    snapshot = tmp_path / "snap"
    snapshot.mkdir()
    (snapshot / "files.py").write_text(GUARDED, encoding="utf-8")
    (snapshot / "views.py").write_text(VIEWS, encoding="utf-8")

    def _record(responses, seeds=(0,), turns=4):
        out = tmp_path / "demo-0001.jsonl"
        config = RunConfig(prompts=tuple(f"p{i}" for i in range(1, turns + 1)), trace_path=out,
                           trace_id="demo-0001", snapshot_dir=snapshot, seeds=tuple(seeds))
        client = fake_client(responses)
        RefinementDriver(config, client, clock=client.clock, injection=PLAN).run()
        return out

    return _record


def views(n, file_block):
    """A turn that leaves the regression's file alone."""
    return file_block(VIEWS + f"\n# pass {n}", "views.py")


def turns_of(labels, seed=0):
    return next(rep for rep in labels["replications"] if rep["seed"] == seed)["turns"]


def test_labels_follow_the_regression_through_the_trace(record, file_block):
    trace = record([views(n, file_block) for n in range(4)])

    labels = label_trace(trace, "cross_file")

    assert [(t["label"], t["basis"]) for t in turns_of(labels)] == [
        (CLEAN, MATCHES_CLEAN),
        (CROSS_FILE_REGRESSION, MATCHES_REGRESSED),
        (CROSS_FILE_REGRESSION, MATCHES_REGRESSED),
        (CROSS_FILE_REGRESSION, MATCHES_REGRESSED),
    ]
    assert [(t["introduced"], t["injected"]) for t in turns_of(labels)] == [
        (False, False), (True, True), (False, False), (False, False)]
    assert labels["replications"][0]["introduced_at"] == 2
    assert labels["turns_by_label"] == {CLEAN: 1, CROSS_FILE_REGRESSION: 3}
    assert labels["turns_carried"] == 0
    assert (labels["event_id"], labels["injection_turn"]) == ("demo-0001", 2)


def test_a_local_event_gives_the_local_label(record, file_block):
    labels = label_trace(record([views(n, file_block) for n in range(4)]), "local")

    assert labels["regression_label"] == LOCAL_REGRESSION
    assert turns_of(labels)[1]["label"] == LOCAL_REGRESSION


def test_comments_docstrings_and_layout_do_not_hide_the_regression(record, file_block):
    restyled = ('def read(name):\n    """Return the file\'s text."""\n'
                "    # read it all at once\n    return open(  name  ).read()\n")
    trace = record([views(0, file_block), views(1, file_block), file_block(restyled, "files.py"),
                    views(3, file_block)])

    turns = turns_of(label_trace(trace, "local"))

    assert [t["basis"] for t in turns] == [MATCHES_CLEAN] + [MATCHES_REGRESSED] * 3


def test_a_rewritten_regression_is_carried_not_judged(record, file_block):
    """The model adds a check of its own. Whether that closes the flow is not
    this module's call: the label carries over and the turn says so."""
    rewritten = "def read(name):\n    if not name:\n        raise ValueError(name)\n    return open(name).read()\n"
    trace = record([views(0, file_block), views(1, file_block), file_block(rewritten, "files.py"),
                    views(3, file_block)])

    labels = label_trace(trace, "local")

    assert [(t["label"], t["basis"]) for t in turns_of(labels)][2:] == [
        (LOCAL_REGRESSION, CARRIED), (LOCAL_REGRESSION, CARRIED)]
    assert labels["turns_carried"] == 2
    assert labels["replications"][0]["introduced_at"] == 2


def test_a_restored_guard_is_clean_again(record, file_block):
    trace = record([views(0, file_block), views(1, file_block), file_block(GUARDED, "files.py"),
                    views(3, file_block)])

    labels = label_trace(trace, "local")

    assert [(t["label"], t["basis"]) for t in turns_of(labels)] == [
        (CLEAN, MATCHES_CLEAN), (LOCAL_REGRESSION, MATCHES_REGRESSED),
        (CLEAN, MATCHES_CLEAN), (CLEAN, MATCHES_CLEAN)]
    assert labels["replications"][0]["introduced_at"] == 2  # where it first came in


def test_guard_code_the_model_edits_before_the_injection_is_flagged(record, file_block):
    logged = GUARDED.replace("    check_name(name)\n", "    check_name(name)\n    print(name)\n")
    trace = record([file_block(logged, "files.py")] + [views(n, file_block) for n in range(1, 4)])

    turns = turns_of(label_trace(trace, "local"))

    assert (turns[0]["label"], turns[0]["basis"]) == (CLEAN, CARRIED)
    assert (turns[1]["label"], turns[1]["basis"], turns[1]["injected"]) == (
        LOCAL_REGRESSION, MATCHES_REGRESSED, True)


def test_a_replication_that_never_got_the_regression_is_clean_throughout(record, file_block):
    refusal = RefusalError(prompt_hash="", model="", category="cyber", explanation=None,
                           partial_text="", usage={}, latency_ms=1.0)
    renamed = file_block(GUARDED.replace("def read(name):", "def read_text(name):"), "files.py")
    trace = record([views(0, file_block), refusal,              # seed 0: refused before the injection
                    renamed, views(1, file_block)],             # seed 1: the injection fails
                   seeds=(0, 1))

    labels = label_trace(trace, "local")

    refused, failed = labels["replications"]
    assert refused["introduced_at"] is None and failed["introduced_at"] is None
    assert refused["turns"] == [
        {"turn": 1, "kind": "turn", "label": CLEAN, "basis": MATCHES_CLEAN,
         "introduced": False, "injected": False},
        {"turn": 2, "kind": "refusal"},
    ]
    assert [(t["label"], t["injected"]) for t in failed["turns"]] == [(CLEAN, False), (CLEAN, False)]
    assert labels["turns_by_label"] == {CLEAN: 3}


def test_labels_round_trip_and_refuse_another_version_of_the_trace(record, file_block):
    trace = record([views(n, file_block) for n in range(4)])
    write_labels(trace, "cross_file")

    loaded = load_labels(trace)

    assert labels_path(trace).name == "demo-0001.labels.json"
    assert sorted(loaded) == [(0, 1), (0, 2), (0, 3), (0, 4)]
    assert loaded[(0, 1)].label == CLEAN and loaded[(0, 1)].verified
    assert loaded[(0, 2)].introduced and loaded[(0, 2)].injected
    assert loaded[(0, 3)].label == CROSS_FILE_REGRESSION

    with trace.open("a", encoding="utf-8", newline="") as handle:
        handle.write("\n")
    with pytest.raises(LabelError, match="different version"):
        load_labels(trace)


def test_a_trace_claiming_an_injection_its_code_does_not_hold_is_rejected(tmp_path, make_trace_record):
    trace = tmp_path / "demo-0001.jsonl"
    files = {"files.py": GUARDED, "views.py": VIEWS}
    with TraceWriter(trace) as writer:
        writer.write(make_trace_record(kind=KIND_INIT, turn=0, files_after=files, injection=PLAN.to_dict()))
        writer.write(make_trace_record(turn=1, files_after=files,
                                       injection={"status": "applied", "files": {}, "notes": []}))

    with pytest.raises(LabelError, match="does not hold it"):
        label_trace(trace, "local")


def test_a_trace_without_an_injection_plan_cannot_be_labelled(tmp_path, make_trace_record):
    trace = tmp_path / "plain.jsonl"
    with TraceWriter(trace) as writer:
        writer.write(make_trace_record(kind=KIND_INIT, turn=0))

    with pytest.raises(LabelError, match="no injection plan"):
        label_trace(trace, "local")


def test_a_regression_that_changes_no_code_cannot_be_labelled():
    commented = GUARDED.replace("    check_name(name)\n", "    # checked first\n    check_name(name)\n")
    plan = InjectionPlan.from_files("demo", 2, clean={"files.py": GUARDED}, regressed={"files.py": commented})

    with pytest.raises(LabelError, match="cannot be labelled"):
        Regression(plan)


@pytest.mark.parametrize("event_dir", sorted(d for d in EVENTS.iterdir() if (d / "clean").is_dir()),
                         ids=lambda d: d.name)
def test_the_rule_tells_every_real_events_two_versions_apart(event_dir):
    plan = injection_plan(event_dir, 2)
    regression = Regression(plan)
    clean = load_snapshot(event_dir / "clean").files
    injected, _ = plan.apply(dict(clean))

    assert regression.observe(clean) == MATCHES_CLEAN
    assert regression.observe(load_snapshot(event_dir / "regressed").files) == MATCHES_REGRESSED
    assert regression.observe(injected) == MATCHES_REGRESSED


# --- The script ----------------------------------------------------------------


def load_script():
    import importlib.util
    path = EVENTS.parent.parent / "scripts" / "label_traces.py"
    spec = importlib.util.spec_from_file_location("label_traces", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_script_writes_labels_next_to_each_trace(record, file_block, tmp_path, capsys):
    trace = record([views(n, file_block) for n in range(4)])
    event = tmp_path / "events" / "demo-0001"
    event.mkdir(parents=True)
    (event / "event.json").write_text('{"scope": "cross_file"}', encoding="utf-8")

    code = load_script().main(["--traces-dir", str(tmp_path), "--events-dir", str(tmp_path / "events")])

    assert code == 0
    assert load_labels(trace)[(0, 2)].label == CROSS_FILE_REGRESSION
    out = capsys.readouterr().out
    assert "1 trace(s), 1 replication(s), 1 with the regression" in out


def test_script_says_so_when_there_is_nothing_to_label(tmp_path, capsys):
    assert load_script().main(["--traces-dir", str(tmp_path)]) == 1
    assert "no trace" in capsys.readouterr().out
