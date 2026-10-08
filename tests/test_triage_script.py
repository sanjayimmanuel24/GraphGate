"""The triage pilot script end to end, with the model and the analysers swapped out.

A billable run goes through this code, so what it sends, keeps and stops at
is tested here and not left to a live run.
"""

import importlib.util
import json
from pathlib import Path

import pytest

from graphgate.dataset.events import dossier_version

from conftest import StubScanner

REPO_ROOT = Path(__file__).resolve().parent.parent

GUARDED = "def read(name):\n    check(name)\n    return open(name).read()\n"
SHELL = "import os\n\n\ndef read(name):\n    os.system('cat ' + name)\n"   # the regression adds a shell call


def reply(**labels):
    return json.dumps({"items": [{"id": k, "label": v, "rationale": f"because {k}"} for k, v in labels.items()]})


@pytest.fixture
def script(monkeypatch):
    spec = importlib.util.spec_from_file_location("triage_events", REPO_ROOT / "scripts" / "triage_events.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "default_scanner", lambda cache=None: StubScanner())
    return module


@pytest.fixture
def project(tmp_path):
    """One validated event whose regression adds a flagged shell call."""
    event = tmp_path / "events" / "demo-0001"
    for variant, text in (("clean", GUARDED), ("regressed", SHELL)):
        (event / variant).mkdir(parents=True)
        (event / variant / "files.py").write_text(text, encoding="utf-8")
    (event / "event.json").write_text(json.dumps({"vulnerability_class": "os-command", "scope": "local"}),
                                      encoding="utf-8")
    review = {"event_id": "demo-0001", "status": "sound"}
    (tmp_path / "ai.json").write_text(json.dumps({"results": [review]}), encoding="utf-8")
    (tmp_path / "signoff.json").write_text(json.dumps({"decisions": {"demo-0001": {
        "decision": "accept", "dossier": dossier_version(event, review)}}}), encoding="utf-8")
    return tmp_path


def run(script, project, *extra):
    return script.main([*extra, "--events-dir", str(project / "events"), "--signoff", str(project / "signoff.json"),
                        "--ai-review", str(project / "ai.json"), "--cache", str(project / "cache.sqlite"),
                        "--analysis-cache", str(project / "analysis.sqlite"),
                        "--out", str(project / "out" / "decisions.jsonl")])


@pytest.fixture
def live(monkeypatch, fake_client):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "not-a-real-key")
    holder = {}

    def use(responses):
        holder["client"] = fake_client(responses)
        monkeypatch.setattr("graphgate.llm.anthropic_client.AnthropicCodeGenClient",
                            lambda model: holder["client"])
        return holder["client"]

    return use


def test_dry_run_counts_the_calls_without_a_key_or_a_call(script, project, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    assert run(script, project, "--dry-run") == 0

    out = capsys.readouterr().out
    # B is asked only about the regression (its shell call is flagged); B+ about both changes.
    assert "3 call(s) at most" in out
    assert not (project / "out").exists() and not (project / "cache.sqlite").exists()


def test_show_prompt_prints_the_request_and_nothing_that_gives_the_answer_away(script, project, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    assert run(script, project, "--show-prompt", "demo-0001") == 0

    out = capsys.readouterr().out
    assert "=== system ===" in out and "+    os.system('cat ' + name)" in out and "- C0:" in out
    assert "demo-0001" not in out and "os-command" not in out   # no event id, no class label


def test_a_live_run_without_a_key_stops_before_anything_is_written(script, project, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(SystemExit, match="ANTHROPIC_API_KEY"):
        run(script, project)
    assert not (project / "out").exists()


def test_a_run_judges_the_regression_and_the_fix_under_both_conditions(script, project, live, capsys):
    # Order of calls: regression under B, regression under B+, then the fix under B+ (B has nothing to ask).
    client = live([reply(F1="exploitable-regression"),
                   reply(F1="exploitable-regression", C0="exploitable-regression"),
                   reply(C0="benign-refactor")])

    assert run(script, project) == 0

    rows = [json.loads(line) for line in (project / "out" / "decisions.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [(r["change"], r["condition"], r["decision"], r["outcome"]) for r in rows] == [
        ("regression", "B", "BLOCK", "triaged"),
        ("regression", "B+", "BLOCK", "triaged"),
        ("fix", "B", "ALLOW", "no-flags"),
        ("fix", "B+", "ALLOW", "triaged"),
    ]
    assert all((r["event_id"], r["seed"], r["scope"]) == ("demo-0001", 0, "local") for r in rows)
    assert client.calls == 3 and all("demo-0001" not in prompt for prompt in client.prompts_seen)
    out = capsys.readouterr().out
    assert "blocked 1 of 1 regression change(s)" in out and "blocked 0 of 1 fix change(s)" in out
    assert "not the study's result" in out


def test_no_control_judges_the_regressions_only(script, project, live):
    client = live([reply(F1="benign-refactor")])

    assert run(script, project, "--no-control", "--condition", "B") == 0

    rows = (project / "out" / "decisions.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(rows) == 1 and json.loads(rows[0])["decision"] == "ALLOW" and client.calls == 1


def test_max_calls_stops_before_the_call_that_would_pass_it(script, project, live, capsys):
    client = live([reply(F1="uncertain")])

    assert run(script, project, "--max-calls", "1") == 0

    assert client.calls == 1
    assert "stopped early: --max-calls 1 reached" in capsys.readouterr().out
    assert len((project / "out" / "decisions.jsonl").read_text(encoding="utf-8").splitlines()) == 1


def test_a_rerun_is_served_from_the_cache(script, project, live):
    live([reply(F1="uncertain"), reply(F1="uncertain", C0="uncertain"), reply(C0="benign-refactor")])
    run(script, project)
    first = (project / "out" / "decisions.jsonl").read_text(encoding="utf-8")

    again = live([])   # would fail the test if asked for anything
    assert run(script, project) == 0

    assert again.calls == 0
    rerun = [json.loads(line) for line in (project / "out" / "decisions.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [r["decision"] for r in rerun] == [json.loads(line)["decision"] for line in first.splitlines()]
    assert all(r["call"]["cached"] for r in rerun if r["call"])
