"""Plan and record a refinement trace for one regression event (BUILD_PLAN 2.4).

A trace starts from an event's clean slice and runs 5 to 8 refinement turns
with the code-generation model. At one turn, chosen between the second and the
sixth, the event's regression is placed in the code the model produced
(:mod:`graphgate.harness.injection`), so that turn's change bundles the
model's own edit with the regression.

The plan (how many turns, which instructions, which turn carries the
regression) depends only on the plan seed and the event id. Every replication
of an event therefore follows the same plan, and a rerun plans the same trace;
replications differ only in what the model writes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from graphgate.config import ModelConfig, RunConfig
from graphgate.dataset.events import approx_tokens, dossier_version
from graphgate.harness.driver import RefinementDriver
from graphgate.harness.injection import InjectionPlan
from graphgate.harness.protocol import SYSTEM_PROMPT, render_user_prompt
from graphgate.harness.replay import load_records
from graphgate.harness.snapshot import load_snapshot
from graphgate.harness.trace import KIND_ERROR, KIND_INIT, KIND_REFUSAL, utc_now_iso
from graphgate.llm.base import CodeGenClient

# Proposal §6.1: traces of 5 to 8 turns. BUILD_PLAN 2.4: the regression lands
# at a turn between 2 and 6, so at least one clean turn always comes first.
MIN_TURNS, MAX_TURNS = 5, 8
INJECT_MIN, INJECT_MAX = 2, 6
DEFAULT_PLAN_SEED = 0

# AI-preparation statuses (data/validation_ai_review.json) a pilot run accepts.
PILOT_STATUSES = frozenset({"sound", "sound-after-fix"})

# The model returns whole files, so a turn's output is roughly the size of the
# files it rewrites plus its reasoning. As a share of the slice's size; a rough
# range for budgeting, not a measurement.
OUTPUT_SHARE = (0.8, 1.5)


@dataclass(frozen=True)
class TracePlan:
    event_id: str
    plan_seed: int
    prompts: tuple[str, ...]
    injection_turn: int


def load_prompt_pool(path: Path) -> tuple[str, ...]:
    """One instruction per line; blank lines and '#' comments are skipped."""
    pool = tuple(line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                 if line.strip() and not line.lstrip().startswith("#"))
    if len(set(pool)) != len(pool):
        raise ValueError(f"{path}: duplicate instructions in the prompt pool")
    return pool


def plan_trace(event_id: str, pool: tuple[str, ...], plan_seed: int = DEFAULT_PLAN_SEED) -> TracePlan:
    """The trace plan for an event: deterministic in ``(plan_seed, event_id)``."""
    if len(pool) < MAX_TURNS:
        raise ValueError(f"the prompt pool has {len(pool)} instructions; at least {MAX_TURNS} are needed")
    # Seeded with a string: Python derives the state from its SHA-512, so the
    # plan is the same on every platform. No other randomness is involved.
    rng = random.Random(f"{plan_seed}:{event_id}")
    turns = rng.randint(MIN_TURNS, MAX_TURNS)
    injection_turn = rng.randint(INJECT_MIN, min(INJECT_MAX, turns))
    return TracePlan(event_id, plan_seed, tuple(rng.sample(pool, turns)), injection_turn)


def injection_plan(event_dir: Path, turn: int) -> InjectionPlan:
    """The event's regression as an injection plan for ``turn``."""
    clean = load_snapshot(event_dir / "clean").files
    regressed = load_snapshot(event_dir / "regressed").files
    return InjectionPlan.from_files(event_dir.name, turn, clean, regressed)


def synthesize(
    event_dir: Path,
    trace_path: Path,
    client: CodeGenClient,
    pool: tuple[str, ...],
    *,
    seeds: tuple[int, ...],
    plan_seed: int = DEFAULT_PLAN_SEED,
    model: ModelConfig = ModelConfig(),
    clock: Callable[[], str] = utc_now_iso,
) -> RefinementDriver:
    """Record the trace for one event. Returns the driver, for its counters."""
    plan = plan_trace(event_dir.name, pool, plan_seed)
    config = RunConfig(
        prompts=plan.prompts,
        trace_path=trace_path,
        trace_id=event_dir.name,
        snapshot_dir=event_dir / "clean",
        seeds=seeds,
        model=model,
    )
    driver = RefinementDriver(config, client, clock=clock,
                              injection=injection_plan(event_dir, plan.injection_turn))
    driver.run()
    return driver


# --- Which events get a trace ---------------------------------------------------


@dataclass(frozen=True)
class Selection:
    events: tuple[str, ...]
    skipped: dict[str, str]  # event id -> why it gets no trace


def select_events(
    events_dir: Path,
    ai_review: dict[str, dict[str, Any]],
    decisions: dict[str, dict[str, Any]],
    *,
    pilot: bool = False,
    only: tuple[str, ...] = (),
) -> Selection:
    """The events to record, and the reason for every one left out.

    Dataset traces come only from events the owner accepted, on the dossier as
    it stands now. A pilot run also takes events that passed AI preparation;
    its traces test the tooling and are not part of the dataset.
    """
    built = sorted(d.name for d in events_dir.iterdir()
                   if (d / "clean").is_dir() and (d / "regressed").is_dir())
    unknown = sorted(set(only) - set(built))
    if unknown:
        raise ValueError(f"no built event named {', '.join(unknown)} under {events_dir}")

    chosen, skipped = [], {}
    for event_id in only or built:
        review = ai_review.get(event_id, {})
        decision = decisions.get(event_id)
        current = dossier_version(events_dir / event_id, review)
        if decision and decision.get("decision") == "accept" and decision.get("dossier") == current:
            chosen.append(event_id)
        elif pilot and review.get("status") in PILOT_STATUSES:
            chosen.append(event_id)
        elif decision is None:
            skipped[event_id] = (f"AI preparation: {review.get('status', 'none')}" if pilot
                                 else "not signed off")
        elif decision.get("decision") != "accept":
            skipped[event_id] = f"sign-off: {decision.get('decision')}"
        else:
            skipped[event_id] = "accepted on an older version of the dossier"
    return Selection(tuple(chosen), skipped)


# --- Budgeting -------------------------------------------------------------------


def estimate(event_dir: Path, plan: TracePlan, replications: int) -> dict[str, Any]:
    """Rough token use for one event's trace, before anything is spent."""
    files = load_snapshot(event_dir / "clean").files
    slice_tokens = sum(approx_tokens(text) for text in files.values())
    per_call_in = approx_tokens(SYSTEM_PROMPT + render_user_prompt(files, max(plan.prompts, key=len)))
    calls = len(plan.prompts) * replications
    return {
        "calls": calls,
        "input_tokens": calls * per_call_in,
        "output_tokens": tuple(round(calls * slice_tokens * share) for share in OUTPUT_SHARE),
    }


# --- What a recorded trace holds ---------------------------------------------------


def summarize_trace(path: Path, plan: TracePlan) -> dict[str, Any]:
    """Per-replication outcome of a recorded trace, checked against its plan."""
    records = load_records(path)
    init = next(r for r in records if r.kind == KIND_INIT)
    replications: dict[int, dict[str, Any]] = {}
    matches = (init.injection or {}).get("turn") == plan.injection_turn

    for record in records:
        if record.kind == KIND_INIT:
            replications[record.seed] = {"seed": record.seed, "turns": 0, "ended": "incomplete",
                                         "injection": "not-reached", "billed": {}}
            continue
        rep = replications[record.seed]
        matches = (matches and record.turn <= len(plan.prompts)
                   and record.prompt == plan.prompts[record.turn - 1])
        if not record.cached:
            for key, value in record.usage.items():
                rep["billed"][key] = rep["billed"].get(key, 0) + value
        if record.kind in (KIND_REFUSAL, KIND_ERROR):
            rep["ended"] = record.kind
            if record.kind == KIND_REFUSAL:
                rep["refusal_category"] = record.refusal_category
            continue
        rep["turns"] = record.turn
        if record.turn == len(plan.prompts):
            rep["ended"] = "complete"
        if record.injection is not None:
            rep["injection"] = record.injection["status"]
            rep["injected_files"] = record.injection.get("files", {})
            if record.injection["status"] == "failed":
                rep["ended"] = "injection-failed"
                rep["reason"] = record.injection["reason"]

    turns = [r for r in records if r.kind != KIND_INIT]
    return {
        "event_id": plan.event_id,
        "turns_planned": len(plan.prompts),
        "injection_turn": plan.injection_turn,
        "prompts": list(plan.prompts),
        "model": next((r.model for r in turns if r.model), None),
        "resolved_model": next((r.resolved_model for r in turns if r.resolved_model), None),
        # False when the prompt pool or plan seed changed after this was recorded.
        "matches_plan": matches,
        "replications": [replications[seed] for seed in sorted(replications)],
    }
