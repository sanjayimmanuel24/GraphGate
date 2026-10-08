"""The first-look script for the graph rules, on a made-up event."""

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CLEAN = "import os, shlex\n\ndef export(name):\n    os.system('tar cf out.tar ' + shlex.quote(name))\n"
REGRESSED = "import os, shlex\n\ndef export(name):\n    os.system('tar cf out.tar ' + name)\n"


def load_script():
    spec = importlib.util.spec_from_file_location("delta_events", REPO_ROOT / "scripts" / "delta_events.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_event(root: Path, event_id: str = "demo-0001") -> None:
    for variant, text in (("clean", CLEAN), ("regressed", REGRESSED)):
        (root / event_id / variant).mkdir(parents=True)
        (root / event_id / variant / "tool.py").write_text(text, encoding="utf-8")
    (root / event_id / "event.json").write_text(
        json.dumps({"vulnerability_class": "os-command", "scope": "local"}), encoding="utf-8")


def test_a_preview_prints_the_flags_and_writes_nothing(tmp_path, capsys):
    make_event(tmp_path / "events")
    out = tmp_path / "look.json"

    assert load_script().main(["demo-0001", "--events-dir", str(tmp_path / "events"), "--out", str(out)]) == 0

    printed = capsys.readouterr().out
    assert "demo-0001" in printed and "R1, R2, R3" in printed and "preview only" in printed
    assert not out.exists()


def test_the_full_record_holds_every_setting_the_control_and_the_depths(tmp_path, capsys):
    make_event(tmp_path / "events")
    (tmp_path / "ai.json").write_text(json.dumps({"results": [{"event_id": "demo-0001", "status": "sound"}]}),
                                      encoding="utf-8")
    script = load_script()
    # Sign-off is what makes an event part of the record; stand in for it here.
    script.select_events = lambda *args, **kwargs: type("Selection", (), {"events": ("demo-0001",)})()
    out = tmp_path / "look.json"

    assert script.main(["--events-dir", str(tmp_path / "events"), "--ai-review", str(tmp_path / "ai.json"),
                        "--signoff", str(tmp_path / "none.json"), "--out", str(out)]) == 0

    look = json.loads(out.read_text(encoding="utf-8"))
    event = look["events"]["demo-0001"]
    assert look["primary_setting"] == "graphgate" and look["hops"] == 2
    assert set(event["settings"]) == {"graphgate", "public-api-sources-only", "structural-guards-only", "as-proposed"}
    # The parameter is a source only when a library's public parameters count as one.
    assert event["settings"]["graphgate"]["rules"] == ["R1", "R2", "R3"]
    assert event["settings"]["as-proposed"]["rules"] == ["R1"]
    assert event["settings"]["graphgate"]["fix_rules"] == []       # the fix adds the sanitizer: nothing to flag
    assert set(event["by_depth"]) == {"1", "2", "3", "None"}
    assert look["summary"]["settings"]["graphgate"]["flagged"] == 1
    assert look["summary"]["control_fix_flagged"]["graphgate"] == 0
    assert look["summary"]["slice_graphs"]["regression_changes_an_edge"] == 1
