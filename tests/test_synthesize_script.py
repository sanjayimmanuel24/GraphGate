"""The trace-synthesis script end to end, with the provider client swapped out.

This is the code a billable run goes through, so the paths that decide what is
sent, kept and skipped are tested here rather than left to a live run.
"""

import importlib.util
import json
from pathlib import Path

import pytest

from graphgate.dataset.events import dossier_version
from graphgate.dataset.traceplan import plan_trace
from graphgate.harness.replay import load_records
from graphgate.llm.base import CompletionError

REPO_ROOT = Path(__file__).resolve().parent.parent
POOL = tuple(f"instruction {i}" for i in range(10))

GUARDED = "from checks import check\n\n\ndef read(name):\n    check(name)\n    return open(name).read()\n"
UNGUARDED = "def read(name):\n    return open(name).read()\n"


def load_script():
    spec = importlib.util.spec_from_file_location(
        "synthesize_traces", REPO_ROOT / "scripts" / "synthesize_traces.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def project(tmp_path):
    """One built event that passed AI preparation, a prompt pool, no sign-off."""
    event = tmp_path / "events" / "demo-0001"
    for variant, text in (("clean", GUARDED), ("regressed", UNGUARDED)):
        (event / variant).mkdir(parents=True)
        (event / variant / "files.py").write_text(text, encoding="utf-8")
        (event / variant / "views.py").write_text("from files import read\n", encoding="utf-8")
    (tmp_path / "pool.txt").write_text("\n".join(POOL) + "\n", encoding="utf-8")
    (tmp_path / "ai.json").write_text(
        json.dumps({"results": [{"event_id": "demo-0001", "status": "sound"}]}), encoding="utf-8")
    return tmp_path


def run(script, project, *extra, pilot=True):
    return script.main([
        *(["--pilot"] if pilot else []),
        "--events-dir", str(project / "events"), "--prompts", str(project / "pool.txt"),
        "--ai-review", str(project / "ai.json"), "--signoff", str(project / "signoff.json"),
        "--out-dir", str(project / "out"), "--cache", str(project / "cache.sqlite"), *extra,
    ])


@pytest.fixture
def live(monkeypatch, fake_client):
    """Stand a fake in for the provider client; returns a setter for its replies."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "not-a-real-key")
    holder = {}

    def use(responses):
        holder["client"] = fake_client(responses)
        monkeypatch.setattr("graphgate.llm.anthropic_client.AnthropicCodeGenClient",
                            lambda model: holder["client"])
        return holder["client"]

    return use


def replies(file_block, turns, seeds=1):
    return [file_block(f"from files import read\n# turn {t}", "views.py")
            for _ in range(seeds) for t in range(turns)]


def test_without_a_sign_off_nothing_is_recorded(project, live, capsys):
    client = live([])

    assert run(load_script(), project, pilot=False) == 1

    assert client.calls == 0 and not (project / "out").exists()
    assert "not signed off" in capsys.readouterr().out


def test_dry_run_plans_without_a_key_or_a_call(project, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    assert run(load_script(), project, "--dry-run") == 0

    out = capsys.readouterr().out
    assert "demo-0001" in out and "files.py" in out and "call(s) at most" in out
    assert not (project / "out").exists() and not (project / "cache.sqlite").exists()


def test_a_live_run_without_a_key_stops_before_anything_is_written(project, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(SystemExit, match="ANTHROPIC_API_KEY"):
        run(load_script(), project)

    assert not (project / "out").exists()


def test_pilot_run_records_a_trace_and_a_manifest(project, live, file_block):
    plan = plan_trace("demo-0001", POOL)
    client = live(replies(file_block, len(plan.prompts), seeds=2))

    assert run(load_script(), project, "--seeds", "0,1") == 0

    out = project / "out"
    assert sorted(p.name for p in out.iterdir()) == ["demo-0001.jsonl", "manifest.json"]
    records = load_records(out / "demo-0001.jsonl")
    assert [r.turn for r in records if r.injection and r.turn] == [plan.injection_turn] * 2
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["pilot"] is True
    assert manifest["replications_by_outcome"] == {"complete": 2}
    assert manifest["replications_with_regression"] == 2
    assert manifest["traces"][0]["matches_plan"]
    assert client.calls == 2 * len(plan.prompts)


def test_a_recorded_event_is_not_sent_again(project, live, file_block):
    plan = plan_trace("demo-0001", POOL)
    script = load_script()
    live(replies(file_block, len(plan.prompts)))
    run(script, project, "--seeds", "0")
    before = (project / "out" / "demo-0001.jsonl").read_bytes()

    again = live([])   # would fail the test if asked for anything
    assert run(script, project, "--seeds", "0") == 0

    assert again.calls == 0
    assert (project / "out" / "demo-0001.jsonl").read_bytes() == before


def test_a_reply_the_model_gave_but_that_cannot_be_used_stays_in_the_trace(project, live, capsys):
    """An open model sometimes answers in prose. That is its outcome for the
    turn, not a fault of the run: discarding the whole trace for it once left a
    ten-hour run with nothing kept."""
    script = load_script()
    live(["no file blocks here"])

    assert run(script, project, "--seeds", "0") == 0

    out = project / "out"
    assert [r.kind for r in load_records(out / "demo-0001.jsonl")] == ["init", "error"]
    assert not (out / "demo-0001.jsonl.partial").exists()
    assert "1 unusable reply(ies), 0 failed call(s)" in capsys.readouterr().out


def test_a_trace_with_a_failed_call_is_held_back_and_retried(project, live, file_block, capsys):
    plan = plan_trace("demo-0001", POOL)
    script = load_script()
    live([CompletionError("model server call failed: connection refused")])

    assert run(script, project, "--seeds", "0") == 0

    out = project / "out"
    assert not (out / "demo-0001.jsonl").exists() and (out / "demo-0001.jsonl.partial").exists()
    assert json.loads((out / "manifest.json").read_text(encoding="utf-8"))["traces"] == []
    assert "not kept" in capsys.readouterr().out

    # The next run starts the trace afresh instead of appending to the leftover.
    live(replies(file_block, len(plan.prompts)))
    assert run(script, project, "--seeds", "0") == 0
    assert (out / "demo-0001.jsonl").exists() and not (out / "demo-0001.jsonl.partial").exists()


def test_max_calls_stops_before_an_event_it_cannot_afford(project, live, capsys):
    client = live([])

    assert run(load_script(), project, "--seeds", "0", "--max-calls", "3") == 0

    assert client.calls == 0
    assert "stopping before demo-0001" in capsys.readouterr().out
    assert not (project / "out" / "demo-0001.jsonl").exists()


def test_cache_only_never_calls_the_provider(project, live, capsys):
    client = live([])

    assert run(load_script(), project, "--seeds", "0", "--cache-only") == 0

    assert client.calls == 0
    assert "read-only" in capsys.readouterr().out
    assert not (project / "out" / "demo-0001.jsonl").exists()


def test_dataset_and_pilot_traces_do_not_share_a_directory(project, live, file_block):
    plan = plan_trace("demo-0001", POOL)
    script = load_script()
    live(replies(file_block, len(plan.prompts)))
    run(script, project, "--seeds", "0")

    review = {"event_id": "demo-0001", "status": "sound"}
    version = dossier_version(project / "events" / "demo-0001", review)
    (project / "signoff.json").write_text(
        json.dumps({"decisions": {"demo-0001": {"decision": "accept", "dossier": version}}}),
        encoding="utf-8")

    with pytest.raises(SystemExit, match="pilot"):
        run(script, project, "--seeds", "0", pilot=False)
