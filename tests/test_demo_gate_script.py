"""The one-event demonstration script, with the analysers swapped out."""

import importlib.util
import json
from pathlib import Path

import pytest

from graphgate.graph.overlay import write_snapshot

from conftest import StubScanner

REPO_ROOT = Path(__file__).resolve().parent.parent

CHECKED = "from store import save\n\n\ndef upload(name, data):\n    if '..' in name:\n        raise ValueError(name)\n    save(name, data)\n"
UNCHECKED = "from store import save\n\n\ndef upload(name, data):\n    save(name, data)\n"
STORE = "def save(name, data):\n    with open(name, 'w') as handle:\n        handle.write(data)\n"


@pytest.fixture
def script(monkeypatch):
    spec = importlib.util.spec_from_file_location("demo_gate", REPO_ROOT / "scripts" / "demo_gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "default_scanner", lambda cache=None: StubScanner())
    return module


@pytest.fixture
def project(tmp_path):
    """An event whose slice is api.py alone; the sink is in store.py, elsewhere in the repository."""
    event = tmp_path / "events" / "demo-0001"
    for variant, text in (("clean", CHECKED), ("regressed", UNCHECKED)):
        (event / variant).mkdir(parents=True)
        (event / variant / "api.py").write_text(text, encoding="utf-8")
    write_snapshot(tmp_path / "snapshots", "demo-0001", "o/r", "abc", [("api.py", "b1", CHECKED), ("store.py", "b2", STORE)])
    (tmp_path / "leakage.json").write_text(json.dumps({"events": {}}), encoding="utf-8")
    return tmp_path


def run(script, project, *extra):
    return script.main(["demo-0001", *extra, "--events-dir", str(project / "events"),
                        "--repo-snapshots", str(project / "snapshots"), "--leakage", str(project / "leakage.json"),
                        "--analysis-cache", str(project / "analysis.sqlite")])


def test_the_regression_is_walked_through_every_stage(script, project, capsys):
    assert run(script, project) == 0

    out = capsys.readouterr().out
    assert "1. The change: demo-0001, the regression" in out and "-    if '..' in name:" in out
    assert "findings the change introduces: 0" in out and "Condition B without triage: ALLOW" in out
    # The slice has no sink, so only the repository view sees what the removed test guarded.
    assert "slice alone (C-slice): graph of 1 file(s)" in out and "rules: none  -> without triage: ALLOW" in out
    assert "with the repository (C, registered): graph of 2 file(s)" in out and "rules: R3  -> without triage: BLOCK" in out
    assert "Graph check R3 (a guard is gone)" in out and "# store.py, lines 1-3" in out
    assert "no model is called here" in out


def test_the_fix_can_be_shown_as_a_control(script, project, capsys):
    assert run(script, project, "--fix") == 0

    out = capsys.readouterr().out
    assert "the fix (control)" in out and "+    if '..' in name:" in out


def test_without_a_snapshot_the_slice_view_is_still_shown_and_the_gap_is_said(script, project, capsys):
    (project / "snapshots" / "demo-0001.json").unlink()

    assert run(script, project) == 0

    out = capsys.readouterr().out
    assert "repository view not shown: no repository snapshot for demo-0001" in out
    assert "nothing was flagged, so nothing is sent to the model" in out


def test_an_unknown_event_is_refused(script, project):
    with pytest.raises(SystemExit, match="no event nope"):
        script.main(["nope", "--events-dir", str(project / "events")])
