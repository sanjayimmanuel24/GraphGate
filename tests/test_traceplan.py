"""Tests for planning and recording a refinement trace for an event."""

import shutil
from pathlib import Path

import pytest

from graphgate.dataset.events import dossier_version
from graphgate.dataset.traceplan import (
    INJECT_MAX,
    INJECT_MIN,
    MAX_TURNS,
    MIN_TURNS,
    estimate,
    injection_plan,
    load_prompt_pool,
    plan_trace,
    select_events,
    summarize_trace,
    synthesize,
)
from graphgate.harness.replay import load_records
from graphgate.llm.base import RefusalError

POOL = tuple(f"instruction {i}" for i in range(10))
REPO_ROOT = Path(__file__).resolve().parent.parent


def test_plan_depends_only_on_seed_and_event():
    assert plan_trace("gitpython-2f96", POOL) == plan_trace("gitpython-2f96", POOL)
    assert plan_trace("gitpython-2f96", POOL, plan_seed=1) != plan_trace("gitpython-2f96", POOL)


def test_plans_stay_inside_the_registered_ranges():
    plans = [plan_trace(f"event-{i}", POOL) for i in range(300)]

    assert {len(p.prompts) for p in plans} == set(range(MIN_TURNS, MAX_TURNS + 1))
    assert {p.injection_turn for p in plans} == set(range(INJECT_MIN, INJECT_MAX + 1))
    assert all(p.injection_turn <= len(p.prompts) for p in plans)
    assert all(len(set(p.prompts)) == len(p.prompts) for p in plans)  # no repeated instruction


def test_events_get_different_plans():
    plans = {plan_trace(f"event-{i}", POOL).prompts for i in range(20)}

    assert len(plans) > 15


def test_a_small_pool_is_rejected():
    with pytest.raises(ValueError, match="at least 8"):
        plan_trace("e", POOL[:5])


def test_the_shipped_pool_is_usable_and_carries_no_research_framing():
    pool = load_prompt_pool(REPO_ROOT / "data" / "refinement_prompts.txt")

    assert len(pool) >= MAX_TURNS
    text = " ".join(pool).lower()
    for word in ("security", "vulnerab", "regression", "cve", "inject", "sanitiz", "exploit", "attack"):
        assert word not in text


def test_duplicate_instructions_are_rejected(tmp_path):
    path = tmp_path / "pool.txt"
    path.write_text("a\n# note\nb\na\n", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate"):
        load_prompt_pool(path)


# --- Recording a trace for an event ------------------------------------------

GUARDED = "from checks import check\n\n\ndef read(name):\n    check(name)\n    return open(name).read()\n"
UNGUARDED = "def read(name):\n    return open(name).read()\n"


@pytest.fixture
def event_dir(tmp_path):
    d = tmp_path / "demo-0001"
    for variant, text in (("clean", GUARDED), ("regressed", UNGUARDED)):
        (d / variant).mkdir(parents=True)
        (d / variant / "files.py").write_text(text, encoding="utf-8")
        (d / variant / "views.py").write_text("from files import read\n", encoding="utf-8")
    return d


def test_injection_plan_holds_only_the_changed_files(event_dir):
    plan = injection_plan(event_dir, 3)

    assert plan.event_id == "demo-0001" and plan.turn == 3
    assert plan.clean == {"files.py": GUARDED} and plan.regressed == {"files.py": UNGUARDED}


def test_synthesize_records_a_trace_with_the_regression_at_the_planned_turn(
    event_dir, tmp_path, fake_client, file_block, replay_into
):
    plan = plan_trace("demo-0001", POOL)
    responses = [file_block(f"from files import read\n# turn {t}", "views.py")
                 for t in range(1, len(plan.prompts) + 1)]
    client = fake_client(responses)
    out = tmp_path / "traces" / "demo-0001.jsonl"

    driver = synthesize(event_dir, out, client, POOL, seeds=(0,), clock=client.clock)

    records = load_records(out)
    turns = [r for r in records if r.turn > 0]
    assert [r.prompt for r in turns] == list(plan.prompts)
    injected = [r.turn for r in turns if r.injection is not None]
    assert injected == [plan.injection_turn]
    assert turns[plan.injection_turn - 1].files_after["files.py"] == UNGUARDED
    assert turns[plan.injection_turn - 2].files_after["files.py"] == GUARDED  # clean until then
    assert driver.injections_applied == 1

    replayed = tmp_path / "replayed.jsonl"
    replay_into(out, replayed)
    assert replayed.read_bytes() == out.read_bytes()


# --- Which events get a trace --------------------------------------------------


def _decision(events, event_id, review, decision="accept"):
    return {"decision": decision, "dossier": dossier_version(events / event_id, review.get(event_id, {}))}


@pytest.fixture
def events(event_dir, tmp_path):
    """Two built events side by side, and one directory that is not built yet."""
    shutil.copytree(event_dir, tmp_path / "demo-0002")
    (tmp_path / "demo-0003").mkdir()
    return tmp_path


def test_dataset_traces_need_a_current_sign_off(events):
    review = {"demo-0001": {"status": "sound"}, "demo-0002": {"status": "sound"}}

    nothing = select_events(events, review, {})
    assert nothing.events == ()
    assert nothing.skipped == {"demo-0001": "not signed off", "demo-0002": "not signed off"}

    decisions = {"demo-0001": _decision(events, "demo-0001", review),
                 "demo-0002": _decision(events, "demo-0002", review, "reject")}
    chosen = select_events(events, review, decisions)
    assert chosen.events == ("demo-0001",)
    assert chosen.skipped == {"demo-0002": "sign-off: reject"}


def test_a_sign_off_on_an_older_dossier_does_not_count(events):
    review = {"demo-0001": {"status": "sound"}}
    decisions = {"demo-0001": _decision(events, "demo-0001", review)}
    (events / "demo-0001" / "regressed" / "files.py").write_text(UNGUARDED + "# x\n", encoding="utf-8")

    selection = select_events(events, review, decisions, only=("demo-0001",))

    assert selection.events == ()
    assert "older version" in selection.skipped["demo-0001"]


def test_pilot_also_takes_events_that_passed_ai_preparation(events):
    review = {"demo-0001": {"status": "sound-after-fix"}, "demo-0002": {"status": "excluded"}}

    selection = select_events(events, review, {}, pilot=True)

    assert selection.events == ("demo-0001",)
    assert selection.skipped == {"demo-0002": "AI preparation: excluded"}


def test_an_unknown_event_is_an_error_not_a_silent_skip(events):
    with pytest.raises(ValueError, match="demo-0003"):
        select_events(events, {}, {}, only=("demo-0003",))


# --- Budgeting and summaries ----------------------------------------------------


def test_estimate_scales_with_turns_and_replications(event_dir):
    plan = plan_trace("demo-0001", POOL)

    one, three = estimate(event_dir, plan, 1), estimate(event_dir, plan, 3)

    assert one["calls"] == len(plan.prompts) and three["calls"] == 3 * len(plan.prompts)
    assert three["input_tokens"] == 3 * one["input_tokens"] > 0
    low, high = one["output_tokens"]
    assert 0 < low < high


def _record(event_dir, out, responses, fake_client, seeds=(0,)):
    client = fake_client(responses)
    synthesize(event_dir, out, client, POOL, seeds=seeds, clock=client.clock)
    return plan_trace("demo-0001", POOL)


def test_summary_reports_each_replications_outcome(event_dir, tmp_path, fake_client, file_block):
    plan = plan_trace("demo-0001", POOL)
    full = [file_block(f"from files import read\n# turn {t}", "views.py") for t in range(len(plan.prompts))]
    refusal = RefusalError(prompt_hash="", model="", category="cyber", explanation=None,
                           partial_text="", usage={"input_tokens": 9}, latency_ms=1.0)
    renamed = file_block(GUARDED.replace("def read(name):", "def read_text(name):"), "files.py")
    broken = [renamed] + full[: plan.injection_turn - 1]   # the changed function is gone by then
    out = tmp_path / "t.jsonl"

    _record(event_dir, out, full + [refusal] + broken, fake_client, seeds=(0, 1, 2))
    summary = summarize_trace(out, plan)

    done, refused, failed = summary["replications"]
    assert (done["ended"], done["injection"], done["turns"]) == ("complete", "applied", len(plan.prompts))
    assert done["injected_files"] == {"files.py": "swapped"}
    assert done["billed"] == {"input_tokens": 5 * len(plan.prompts), "output_tokens": 7 * len(plan.prompts)}
    assert (refused["ended"], refused["injection"], refused["turns"]) == ("refusal", "not-reached", 0)
    assert refused["refusal_category"] == "cyber" and refused["billed"] == {"input_tokens": 9}
    assert (failed["ended"], failed["injection"], failed["turns"]) == ("injection-failed", "failed",
                                                                       plan.injection_turn)
    assert summary["matches_plan"] and summary["turns_planned"] == len(plan.prompts)
    assert summary["model"] == "fake-model"


def test_summary_flags_a_trace_recorded_under_another_plan(event_dir, tmp_path, fake_client, file_block):
    plan = plan_trace("demo-0001", POOL)
    out = tmp_path / "t.jsonl"
    _record(event_dir, out, [file_block("from files import read\n# x", "views.py")] * len(plan.prompts), fake_client)

    other = plan_trace("demo-0001", tuple(reversed(POOL)), plan_seed=7)

    assert summarize_trace(out, plan)["matches_plan"]
    assert not summarize_trace(out, other)["matches_plan"]
