"""The significance-test script, on a made-up run of the conditions."""

import importlib.util
import json
from pathlib import Path

import pytest

from graphgate.experiment.metrics import write_rows
from graphgate.experiment.runner import COLUMNS

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_script():
    spec = importlib.util.spec_from_file_location("significance_tests",
                                                  REPO_ROOT / "scripts" / "significance_tests.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def row(condition, event, seed, decision, role="introducing", scope="cross_file"):
    values = dict.fromkeys(COLUMNS, "")
    values.update(trace_id=event, event_id=event, seed=seed, condition=condition, iteration=2, role=role,
                  scope=scope, decision=decision)
    return values


def make_run(directory: Path, pilot: bool = False) -> None:
    directory.mkdir()
    rows = []
    for condition in ("A", "B", "B+", "C"):
        for seed in (0, 2):
            catch = condition == "C" or (condition == "B" and seed == 0)
            rows.append(row(condition, "x-1", seed, "BLOCK" if catch else "ALLOW"))
            rows.append(row(condition, "x-2", seed, "BLOCK" if condition == "C" else "ALLOW"))
            rows.append(row(condition, "x-3", seed, "ALLOW", scope="local"))
            rows.append(row(condition, "x-4", seed, "ALLOW", role="clean"))   # nothing was placed here
    write_rows(directory / "turns.csv", rows)
    (directory / "summary.json").write_text(json.dumps(
        {"pilot": pilot, "complete": True, "triage": {"model": "stand-in"}}), encoding="utf-8")


def test_writes_the_primary_and_secondary_tests(tmp_path, capsys):
    make_run(tmp_path / "results")
    out = tmp_path / "tests.json"
    assert load_script().main(["--results-dir", str(tmp_path / "results"), "--out", str(out)]) == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["events"] == {"in_run": 4, "with_a_placed_regression": 3,
                                "cross_file_with_a_placed_regression": 2, "without_a_placed_regression": ["x-4"]}
    primary = result["primary"]
    assert (primary["first"], primary["second"], primary["scope"]) == ("C", "B", "cross_file")
    assert primary["pairs"] == 2 and primary["first_better"] == 2 and primary["significant"] is False
    assert [(s["second"], s["scope"]) for s in result["secondary"]] == [("B", "all"), ("B+", "cross_file"),
                                                                       ("B+", "all")]
    assert all(s["p_holm"] >= s["p_two_sided"] for s in result["secondary"])
    assert result["per_condition"]["C"]["cross_file"]["mean_recall"] == 1.0
    assert "C vs B, cross_file" in capsys.readouterr().out


def test_refuses_a_pilot_run(tmp_path):
    make_run(tmp_path / "results", pilot=True)
    with pytest.raises(SystemExit):
        load_script().main(["--results-dir", str(tmp_path / "results"), "--out", str(tmp_path / "t.json")])
    assert not (tmp_path / "t.json").exists()
