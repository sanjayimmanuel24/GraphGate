"""Tests for injecting a regression during a refinement run (BUILD_PLAN 2.4)."""

import json

import pytest

from graphgate.config import RunConfig
from graphgate.harness.driver import RefinementDriver
from graphgate.harness.injection import InjectionPlan
from graphgate.harness.replay import ReplayClient, load_records
from graphgate.harness.trace import KIND_INIT, KIND_REFUSAL, KIND_TURN, TraceRecord
from graphgate.llm.base import RefusalError

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


@pytest.fixture
def two_files(tmp_path):
    directory = tmp_path / "snap"
    directory.mkdir()
    (directory / "files.py").write_text(GUARDED, encoding="utf-8")
    (directory / "views.py").write_text(VIEWS, encoding="utf-8")
    return directory


def plan(turn=2):
    return InjectionPlan.from_files("demo-0001", turn, clean={"files.py": GUARDED, "views.py": VIEWS},
                                    regressed={"files.py": UNGUARDED, "views.py": VIEWS})


def run(two_files, out, responses, fake_client, *, injection, prompts=("p1", "p2", "p3"), seeds=(0,)):
    config = RunConfig(prompts=tuple(prompts), trace_path=out, trace_id="demo",
                       snapshot_dir=two_files, seeds=tuple(seeds))
    client = fake_client(responses)
    driver = RefinementDriver(config, client, clock=client.clock, injection=injection)
    driver.run()
    return driver, client, load_records(out)


def test_regression_is_bundled_with_the_models_turn(two_files, tmp_path, fake_client, file_block):
    views_v2 = VIEWS.replace("def download(request):", "def download(request):\n    # serve a file")
    responses = [file_block(views_v2, "views.py"),            # turn 1 leaves files.py alone
                 file_block(views_v2 + "\n# tidy", "views.py"),  # turn 2: the model's own change
                 file_block(views_v2 + "\n# done", "views.py")]

    driver, client, records = run(two_files, tmp_path / "t.jsonl", responses, fake_client, injection=plan(2))

    init, t1, t2, t3 = records
    assert init.kind == KIND_INIT and init.injection["event_id"] == "demo-0001"
    assert t1.injection is None
    # Turn 2 holds both the model's edit and the regression.
    assert t2.injection == {"status": "applied", "files": {"files.py": "swapped"}, "notes": []}
    assert t2.files_after["files.py"] == UNGUARDED
    assert t2.files_after["views.py"].endswith("# tidy")
    assert sorted(t2.changed_paths) == ["files.py", "views.py"]
    assert "-    check_name(name)" in t2.diff
    # From turn 3 on, the model is shown the regressed code.
    assert "check_name" not in client.prompts_seen[2]
    assert t3.injection is None
    assert driver.injections_applied == 1 and driver.injections_failed == 0


def test_regression_is_merged_into_a_file_the_model_already_changed(two_files, tmp_path, fake_client, file_block):
    documented = GUARDED.replace("def read(name):", 'def read(name):\n    """Return the file\'s text."""')
    extra = documented + "\n\ndef size(name):\n    return len(read(name))\n"
    responses = [file_block(extra, "files.py"), file_block(VIEWS + "\n# tidy", "views.py"), file_block(VIEWS, "views.py")]

    _, _, records = run(two_files, tmp_path / "t.jsonl", responses, fake_client, injection=plan(2))

    after = records[2].files_after["files.py"]
    assert records[2].injection["files"] == {"files.py": "merged"}
    assert "check_name" not in after          # guard and its import are gone
    assert "def size(name):" in after          # the model's earlier addition survives


def test_injected_trace_replays_byte_for_byte(two_files, tmp_path, fake_client, file_block, replay_into):
    responses = [file_block(VIEWS + "\n# a", "views.py"), file_block(VIEWS + "\n# b", "views.py"),
                 file_block(VIEWS + "\n# c", "views.py")] * 2
    source = tmp_path / "source.jsonl"
    run(two_files, source, responses, fake_client, injection=plan(2), seeds=(0, 1))

    replayed = tmp_path / "replayed.jsonl"
    replay_into(source, replayed)

    assert replayed.read_bytes() == source.read_bytes()
    assert ReplayClient.from_trace(source).injection == plan(2)


def test_failed_injection_ends_the_replication(two_files, tmp_path, fake_client, file_block):
    renamed = GUARDED.replace("def read(name):", "def read_text(name):")
    responses = [file_block(renamed, "files.py"), file_block(VIEWS + "\n# b", "views.py"),
                 file_block(VIEWS + "\n# never asked for", "views.py")]

    driver, client, records = run(two_files, tmp_path / "t.jsonl", responses, fake_client, injection=plan(2))

    assert [r.turn for r in records] == [0, 1, 2]       # turn 3 was never requested
    assert client.calls == 2
    assert records[2].kind == KIND_TURN                  # the model's turn itself is real
    assert records[2].injection["status"] == "failed"
    assert "read" in records[2].injection["reason"]
    assert "check_name" in records[2].files_after["files.py"]   # nothing was half-applied
    assert driver.injections_failed == 1


def test_no_injection_when_the_model_refuses_first(two_files, tmp_path, fake_client):
    refusal = RefusalError(prompt_hash="", model="", category="cyber", explanation=None,
                           partial_text="", usage={}, latency_ms=1.0)

    driver, _, records = run(two_files, tmp_path / "t.jsonl", [refusal], fake_client, injection=plan(2))

    assert [r.kind for r in records] == [KIND_INIT, KIND_REFUSAL]
    assert driver.injections_applied == 0 and driver.injections_failed == 0


def test_a_plain_run_records_no_injection(two_files, tmp_path, fake_client, file_block):
    _, _, records = run(two_files, tmp_path / "t.jsonl", [file_block(VIEWS + "\n# a", "views.py")],
                        fake_client, injection=None, prompts=("p1",))

    assert all(r.injection is None for r in records)


# --- Schema versions ----------------------------------------------------------


def test_v4_records_serialise_without_the_injection_key(make_trace_record):
    line = make_trace_record(schema_version=4).to_json()

    assert "injection" not in json.loads(line)
    assert TraceRecord.from_json(line).to_json() == line  # round trip is exact


def test_v5_records_carry_the_injection_key(make_trace_record):
    line = make_trace_record(injection={"status": "applied"}).to_json()

    assert json.loads(line)["schema_version"] == 5
    assert TraceRecord.from_json(line).injection == {"status": "applied"}


def test_injection_needs_schema_v5(two_files, tmp_path, fake_client):
    config = RunConfig(prompts=("p",), trace_path=tmp_path / "t.jsonl", trace_id="x", snapshot_dir=two_files)

    with pytest.raises(ValueError, match="schema v5"):
        RefinementDriver(config, fake_client([]), injection=plan(1), schema_version=4)
