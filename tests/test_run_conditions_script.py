"""The condition runner's script end to end, with the model and the analysers swapped out.

The study's numbers come out of this code, so what it runs, writes and
refuses is tested here and not left to a live run.
"""

import importlib.util
import json
from pathlib import Path

import pytest

from graphgate.dataset.labels import labels_path, trace_sha256
from graphgate.experiment.metrics import read_rows
from graphgate.graph.overlay import write_snapshot

from conftest import StubScanner

REPO_ROOT = Path(__file__).resolve().parent.parent

PLAIN = "def run(cmd):\n    return cmd\n"
TIDY = "def run(cmd):\n    result = cmd\n    return result\n"
SHELL = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n    return cmd\n"
CLI = "import sys\nfrom app import run\n\nrun(sys.argv[1])\n"      # elsewhere in the repository: a caller


def reply(**labels):
    return json.dumps({"items": [{"id": k, "label": v, "rationale": f"because {k}"} for k, v in labels.items()]})


@pytest.fixture
def script(monkeypatch):
    spec = importlib.util.spec_from_file_location("run_conditions", REPO_ROOT / "scripts" / "run_conditions.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "default_scanner", lambda cache=None: StubScanner())
    return module


@pytest.fixture
def project(tmp_path, record_live, file_block):
    """One labelled trace of two turns: a tidy-up, then a shell call arrives."""
    snapshot = tmp_path / "snap"
    snapshot.mkdir()
    (snapshot / "app.py").write_text(PLAIN, encoding="utf-8")
    traces = tmp_path / "traces"
    traces.mkdir()
    trace = traces / "demo-0001.jsonl"
    record_live(snapshot, trace, ["a", "b"], [file_block(TIDY.strip()), file_block(SHELL.strip())],
                trace_id="demo-0001")
    turns = [("clean", "matches-clean", False), ("local_regression", "matches-regressed", True)]
    labels_path(trace).write_text(json.dumps({"trace_sha256": trace_sha256(trace), "replications": [
        {"seed": 0, "turns": [{"turn": n, "kind": "turn", "label": label, "basis": basis, "introduced": new,
                               "injected": new} for n, (label, basis, new) in enumerate(turns, start=1)]}]}),
        encoding="utf-8")
    (traces / "manifest.json").write_text(json.dumps({"pilot": True}), encoding="utf-8")
    event = tmp_path / "events" / "demo-0001"
    event.mkdir(parents=True)
    (event / "event.json").write_text(json.dumps({"vulnerability_class": "os-command", "scope": "local"}),
                                      encoding="utf-8")
    # The event's clean slice, and its repository: the slice file plus a caller in another file.
    (event / "clean").mkdir()
    (event / "clean" / "app.py").write_text(PLAIN, encoding="utf-8")
    write_snapshot(tmp_path / "snapshots", "demo-0001", "o/r", "abc", [
        ("app.py", "b1", PLAIN), ("cli.py", "b2", CLI)])
    (tmp_path / "leakage.json").write_text(json.dumps({"events": {"demo-0001": {"exclusions": []}}}),
                                           encoding="utf-8")
    return tmp_path


def run(script, project, *extra):
    return script.main(["--traces", str(project / "traces"), "--events-dir", str(project / "events"),
                        "--out-dir", str(project / "out"), "--cache", str(project / "cache.sqlite"),
                        "--repo-snapshots", str(project / "snapshots"), "--leakage", str(project / "leakage.json"),
                        "--analysis-cache", str(project / "analysis.sqlite"), "--time-scans", "0", *extra])


def test_without_triage_it_needs_no_model_and_writes_every_file(script, project, capsys):
    assert run(script, project, "--no-triage") == 0

    out = project / "out"
    assert {p.name for p in out.iterdir()} >= {"turns.csv", "decisions.jsonl", "summary.json"}
    rows = read_rows(out / "turns.csv")
    assert sorted({r["condition"] for r in rows}) == ["A", "B-untriaged", "C-slice-untriaged", "C-untriaged"]
    assert [(r["iteration"], r["decision"]) for r in rows if r["condition"] == "B-untriaged"] == [
        (1, "ALLOW"), (2, "BLOCK")]
    assert {r["vulnerability_class"] for r in rows} == {"os-command"}
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["pilot"] is True and summary["complete"] is True and summary["triage"] is None
    assert summary["graph"]["setting"] == "graphgate" and summary["graph"]["hops"] == 2
    # Only the repository view knows that the command line reaches run(): a new path to the shell call.
    flags = {c: [r["flags"] for r in rows if r["condition"] == c] for c in ("C-untriaged", "C-slice-untriaged")}
    assert flags["C-slice-untriaged"] == [0, 1] and flags["C-untriaged"] == [0, 2]
    assert summary["conditions"]["B-untriaged"]["recall_at_introduction"]["all"]["recall"] == 1.0
    assert summary["conditions"]["A"]["degradation_curve"][-1]["surviving"] == 1
    assert "left out" in capsys.readouterr().out                    # B+ has no form without triage
    decisions = [json.loads(line) for line in (out / "decisions.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(decisions) == len(rows) and decisions[0]["trace_id"] == "demo-0001"


def test_with_triage_the_model_judges_what_is_flagged_and_the_run_is_recorded(script, project, monkeypatch,
                                                                                fake_client):
    # B: the shell call (F1). B+: the tidy-up as a whole, then the shell call and the change.
    # C: the tidy-up raises nothing; then the shell call and what the graph rules flag.
    asked = []

    class Model:
        def __init__(self):
            self.inner = fake_client([])

        def describe_params(self):
            return self.inner.describe_params()

        def request_hash(self, system, user):
            return self.inner.request_hash(system, user)

        def complete(self, system, user, *, replication):
            ids = [line.split(":")[0][2:] for line in user.split("Items to judge:")[1].splitlines()
                   if line.startswith("- ")]
            asked.append(ids)
            self.inner._responses.append(reply(**{i: "exploitable-regression" if i == "F1" else "benign-refactor"
                                                  for i in ids}))
            return self.inner.complete(system, user, replication=replication)

    monkeypatch.setattr(script, "make_client", lambda model: Model())

    assert run(script, project, "--provider", "openai-compatible", "--base-url", "http://localhost:1/v1",
               "--model", "stand-in") == 0

    rows = read_rows(project / "out" / "turns.csv")
    blocks = {c: [r["decision"] for r in rows if r["condition"] == c] for c in ("A", "B", "B+", "C-slice", "C")}
    assert blocks["A"] == ["ALLOW", "ALLOW"]
    assert blocks["B"] == blocks["B+"] == blocks["C-slice"] == blocks["C"] == ["ALLOW", "BLOCK"]
    assert ["C0"] in asked and ["F1"] in asked and ["F1", "C0"] in asked
    summary = json.loads((project / "out" / "summary.json").read_text(encoding="utf-8"))
    assert summary["triage"]["model"] == "stand-in" and summary["triage"]["prompt_version"] == 1
    assert summary["conditions"]["B+"]["overhead"]["model_calls"] == 2
    assert summary["conditions"]["B"]["overhead"]["model_calls"] == 1


def test_unlabelled_traces_are_refused(script, project):
    labels_path(project / "traces" / "demo-0001.jsonl").unlink()

    with pytest.raises(SystemExit, match="label_traces"):
        run(script, project, "--no-triage")


def test_an_unknown_condition_is_refused(script, project):
    with pytest.raises(SystemExit, match="unknown condition"):
        run(script, project, "--conditions", "A,D")


def test_a_run_with_triage_stops_before_anything_is_written_when_no_model_can_be_reached(script, project):
    with pytest.raises(SystemExit, match="base-url"):
        run(script, project, "--provider", "openai-compatible")

    assert not (project / "out").exists()


def test_c_without_a_repository_snapshot_stops_and_never_uses_the_slice_instead(script, project):
    (project / "snapshots" / "demo-0001.json").unlink()

    with pytest.raises(SystemExit, match="no repository snapshot for demo-0001"):
        run(script, project, "--no-triage")

    assert run(script, project, "--no-triage", "--conditions", "A,C-slice") == 0


def test_c_without_the_leakage_exclusions_is_refused(script, project):
    (project / "leakage.json").unlink()

    with pytest.raises(SystemExit, match="leakage exclusions"):
        run(script, project, "--no-triage")


def test_dataset_and_pilot_results_go_to_different_places(script, project, monkeypatch):
    monkeypatch.chdir(project)
    (project / "traces" / "manifest.json").write_text(json.dumps({"pilot": False}), encoding="utf-8")

    assert script.main(["--traces", "traces", "--events-dir", "events", "--analysis-cache", "a.sqlite",
                        "--time-scans", "0", "--no-triage", "--conditions", "A"]) == 0

    summary = json.loads((project / "data" / "results" / "summary.json").read_text(encoding="utf-8"))
    assert summary["pilot"] is False and not (project / "runs" / "conditions-pilot").exists()
