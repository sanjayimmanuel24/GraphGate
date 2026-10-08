"""Tests for saving the owner's sign-off (BUILD_PLAN 2.3)."""

import importlib.util
import json
from pathlib import Path

import pytest

from graphgate.dataset.events import dossier_version

REPO_ROOT = Path(__file__).resolve().parent.parent
REVIEW = {"a-0001": {"event_id": "a-0001", "status": "sound"},
          "b-0002": {"event_id": "b-0002", "status": "sound"},
          "c-0003": {"event_id": "c-0003", "status": "excluded"}}


def load_script():
    spec = importlib.util.spec_from_file_location("save_signoff", REPO_ROOT / "scripts" / "save_signoff.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def project(tmp_path):
    for event_id in ("a-0001", "b-0002"):
        (tmp_path / "events" / event_id / "clean").mkdir(parents=True)
        (tmp_path / "events" / event_id / "clean" / "m.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "ai.json").write_text(json.dumps({"results": list(REVIEW.values())}), encoding="utf-8")
    (tmp_path / "export").mkdir()
    return tmp_path


def decide(project, event_id, decision="accept", note="", dossier=None):
    current = dossier_version(project / "events" / event_id, REVIEW[event_id])
    (project / "export" / f"{event_id}.json").write_text(json.dumps({
        "decision": decision, "note": note, "decided_at": "2026-10-05T19:24:18.210Z",
        "dossier": current if dossier is None else dossier}), encoding="utf-8")


def run(project):
    return load_script().main([str(project / "export"), "--ai-review", str(project / "ai.json"),
                               "--events", str(project / "events"), "--out", str(project / "signoff.json")])


def test_decisions_are_saved_with_a_tally(project, capsys):
    decide(project, "a-0001")
    decide(project, "c-0003", "reject", "the fix does not close the flow")

    assert run(project) == 0

    saved = json.loads((project / "signoff.json").read_text(encoding="utf-8"))
    assert saved["tally"] == {"accept": 1, "reject": 1, "revise": 0}
    assert saved["decisions"]["a-0001"]["decision"] == "accept"
    assert saved["decisions"]["c-0003"]["note"] == "the fix does not close the flow"
    out = capsys.readouterr().out
    assert "validated (accepted on the current dossier): 1" in out
    assert "no decision yet: b-0002" in out


def test_an_accept_on_an_older_dossier_is_reported_and_not_counted(project, capsys):
    decide(project, "a-0001")
    decide(project, "b-0002", dossier="0123456789ab")

    assert run(project) == 0

    out = capsys.readouterr().out
    assert "validated (accepted on the current dossier): 1" in out
    assert "not counted: b-0002" in out


@pytest.mark.parametrize("decision, note, message", [
    ("reject", "", "needs a note"),
    ("revise", "   ", "needs a note"),
    ("maybe", "", "unknown decision"),
])
def test_a_malformed_decision_stops_the_save(project, decision, note, message):
    decide(project, "a-0001", decision, note)

    with pytest.raises(SystemExit, match=message):
        run(project)
    assert not (project / "signoff.json").exists()


def test_a_decision_for_an_event_that_was_never_prepared_is_refused(project):
    (project / "export" / "z-9999.json").write_text(json.dumps({
        "decision": "accept", "note": "", "decided_at": "x", "dossier": "y"}), encoding="utf-8")

    with pytest.raises(SystemExit, match="never prepared"):
        run(project)


def test_the_saved_sign_off_matches_what_the_trace_tools_count():
    """The checked-in file: every accept names a built event."""
    saved = json.loads((REPO_ROOT / "data" / "validation_signoff.json").read_text(encoding="utf-8"))

    accepted = [e for e, d in saved["decisions"].items() if d["decision"] == "accept"]
    assert saved["tally"]["accept"] == len(accepted)
    assert all((REPO_ROOT / "data" / "events" / e / "clean").is_dir() for e in accepted)
