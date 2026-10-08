"""Record refinement traces for regression events (BUILD_PLAN 2.4).

    python scripts/synthesize_traces.py --dry-run
    python scripts/synthesize_traces.py --pilot --seeds 0 mako-2h4p lollms-m45c
    python scripts/synthesize_traces.py

Each event gets one trace, <out-dir>/<event_id>.jsonl, holding every
replication, and <out-dir>/manifest.json summarises what was recorded.

Without --pilot only events accepted in data/validation_signoff.json are
recorded, into data/traces/. --pilot also takes events that passed AI
preparation and writes to runs/pilot-traces/; pilot traces test the tooling
and are not part of the dataset.

--dry-run prints the plan and a rough cost and sends nothing. Any other run
makes billable API calls, using the key in the ANTHROPIC_API_KEY environment
variable. Responses are cached, so a rerun pays only for what is missing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

from graphgate.cli import _parse_seeds
from graphgate.config import DEFAULT_SEEDS, OMIT, PRICES_PER_MTOK, USE_PRESET, ModelConfig
from graphgate.llm.factory import ANTHROPIC, PROVIDERS, make_client, not_ready
from graphgate.dataset.traceplan import (
    DEFAULT_PLAN_SEED,
    estimate,
    injection_plan,
    load_prompt_pool,
    plan_trace,
    select_events,
    summarize_trace,
    synthesize,
)

MANIFEST_SCHEMA_VERSION = 1
DATASET_DIR = Path("data/traces")
PILOT_DIR = Path("runs/pilot-traces")



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("events", nargs="*", help="event ids (default: every eligible event)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the plan and a rough cost; send nothing")
    parser.add_argument("--pilot", action="store_true",
                        help="also take events that passed AI preparation but are not signed off")
    parser.add_argument("--out-dir", type=Path, default=None,
                        help=f"default: {DATASET_DIR.as_posix()}, or {PILOT_DIR.as_posix()} with --pilot")
    parser.add_argument("--events-dir", type=Path, default=Path("data/events"))
    parser.add_argument("--prompts", type=Path, default=Path("data/refinement_prompts.txt"))
    parser.add_argument("--signoff", type=Path, default=Path("data/validation_signoff.json"))
    parser.add_argument("--ai-review", type=Path, default=Path("data/validation_ai_review.json"))
    parser.add_argument("--plan-seed", type=int, default=DEFAULT_PLAN_SEED,
                        help="seed for turn count, instructions and injection turn (default: %(default)s)")
    parser.add_argument("--seeds", type=_parse_seeds, default=DEFAULT_SEEDS,
                        help="comma-separated replications per event (default: %(default)s)")
    parser.add_argument("--model", default=ModelConfig.model, help="default: %(default)s")
    parser.add_argument("--provider", choices=PROVIDERS, default=ANTHROPIC,
                        help="'openai-compatible' for an open-weight model behind --base-url")
    parser.add_argument("--base-url", default=None,
                        help="model server address, for example http://localhost:11434/v1")
    parser.add_argument("--max-tokens", type=int, default=ModelConfig.max_tokens)
    parser.add_argument("--effort", default=USE_PRESET,
                        choices=[USE_PRESET, OMIT, "low", "medium", "high", "xhigh", "max"])
    parser.add_argument("--thinking", default=USE_PRESET,
                        choices=[USE_PRESET, OMIT, "adaptive", "disabled"])
    parser.add_argument("--cache", type=Path, default=Path("runs/cache.sqlite"),
                        help="response cache (default: %(default)s)")
    parser.add_argument("--cache-only", action="store_true",
                        help="fail on a cache miss instead of making a billable call")
    parser.add_argument("--max-calls", type=int, default=None,
                        help="stop before an event that could take this run past N billable calls")
    parser.add_argument("--keep-errors", action="store_true",
                        help="keep a trace even if a call to the model server failed in it")
    parser.add_argument("--log-level", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def load_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def print_plan(args, selection, plans, out_dir: Path) -> None:
    calls = tokens_in = 0
    tokens_out = [0, 0]
    print(f"{'event':<20} {'turns':>5} {'inject at':>9} {'calls':>5} {'~input tok':>10}  regression in")
    for event_id in selection.events:
        plan = plans[event_id]
        event_dir = args.events_dir / event_id
        est = estimate(event_dir, plan, len(args.seeds))
        recorded = (out_dir / f"{event_id}.jsonl").exists()
        if not recorded:
            calls += est["calls"]
            tokens_in += est["input_tokens"]
            tokens_out = [a + b for a, b in zip(tokens_out, est["output_tokens"])]
        changed = ", ".join(sorted(injection_plan(event_dir, plan.injection_turn).regressed))
        print(f"{event_id:<20} {len(plan.prompts):>5} {plan.injection_turn:>9} {est['calls']:>5} "
              f"{est['input_tokens']:>10}  {changed}{'  [already recorded]' if recorded else ''}")
        # Whole files come back, so a slice near the output limit can be cut off.
        if est["output_tokens"][1] / est["calls"] > args.max_tokens:
            print(f"{'':<20} may exceed --max-tokens {args.max_tokens} on a turn that rewrites every file")

    print(f"\nto record: {calls} call(s) at most, ~{tokens_in:,} input tokens, "
          f"~{tokens_out[0]:,} to {tokens_out[1]:,} output tokens (rough)")
    price = PRICES_PER_MTOK.get(args.model)
    if price:
        low, high = ((tokens_in * price[0] + out * price[1]) / 1e6 for out in tokens_out)
        print(f"rough cost on {args.model}: ${low:.0f} to ${high:.0f} "
              "(before caching; a refusal or failed injection ends a replication early)")


def write_manifest(out_dir: Path, args, pool) -> dict:
    traces = [summarize_trace(path, plan_trace(path.stem, pool, args.plan_seed))
              for path in sorted(out_dir.glob("*.jsonl"))]
    tally: dict[str, int] = {}
    for trace in traces:
        for rep in trace["replications"]:
            tally[rep["ended"]] = tally.get(rep["ended"], 0) + 1
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "pilot": args.pilot,
        "plan_seed": args.plan_seed,
        "prompt_pool": {"path": args.prompts.as_posix(),
                        "sha256": hashlib.sha256("\n".join(pool).encode()).hexdigest()},
        "replications_by_outcome": dict(sorted(tally.items())),
        "replications_with_regression": sum(rep["injection"] == "applied"
                                            for t in traces for rep in t["replications"]),
        "traces": traces,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return manifest


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    sys.stdout.reconfigure(encoding="utf-8")
    out_dir = args.out_dir or (PILOT_DIR if args.pilot else DATASET_DIR)

    pool = load_prompt_pool(args.prompts)
    ai_review = {r["event_id"]: r for r in load_json(args.ai_review, {"results": []})["results"]}
    decisions = load_json(args.signoff, {"decisions": {}})["decisions"]
    selection = select_events(args.events_dir, ai_review, decisions,
                              pilot=args.pilot, only=tuple(args.events))
    plans = {e: plan_trace(e, pool, args.plan_seed) for e in selection.events}

    for event_id, reason in selection.skipped.items():
        print(f"skipping {event_id}: {reason}")
    if not selection.events:
        print("no eligible event." + ("" if args.pilot else
              " Dataset traces need a sign-off in " + args.signoff.as_posix() +
              "; use --pilot to try the tool on AI-prepared events."))
        return 1
    if args.dry_run:
        print_plan(args, selection, plans, out_dir)
        return 0

    previous = load_json(out_dir / "manifest.json", None)
    if previous is not None and previous["pilot"] != args.pilot:
        raise SystemExit(f"{out_dir} holds {'pilot' if previous['pilot'] else 'dataset'} traces; "
                         "pilot and dataset traces do not share a directory")
    model = ModelConfig.for_model(args.model, max_tokens=args.max_tokens, thinking=args.thinking,
                                  effort=args.effort, provider=args.provider, base_url=args.base_url)
    if not args.cache_only and not_ready(model):
        raise SystemExit(not_ready(model))

    # Imported after validation, so a bad command line needs no SDK.
    from graphgate.llm.cache import CacheError, CachingClient, ResponseCache

    out_dir.mkdir(parents=True, exist_ok=True)
    with ResponseCache(args.cache) as cache:
        client = CachingClient(make_client(model), cache, read_only=args.cache_only)
        for event_id in selection.events:
            final = out_dir / f"{event_id}.jsonl"
            if final.exists():
                print(f"{event_id}: already recorded")
                continue
            needed = len(plans[event_id].prompts) * len(args.seeds)
            if args.max_calls is not None and cache.misses + needed > args.max_calls:
                print(f"stopping before {event_id}: {cache.misses} billable call(s) so far, "
                      f"up to {needed} more would pass --max-calls {args.max_calls}")
                break
            # Recorded under a working name: a trace file is appended to, so a
            # run that died halfway must not be mistaken for a finished trace.
            partial = final.with_name(final.name + ".partial")
            partial.unlink(missing_ok=True)
            try:
                driver = synthesize(args.events_dir / event_id, partial, client, pool,
                                    seeds=args.seeds, plan_seed=args.plan_seed, model=model)
            except CacheError as exc:
                print(f"{event_id}: {exc}")
                break
            print(f"{event_id}: regression placed in {driver.injections_applied}/{len(args.seeds)} "
                  f"replication(s); {driver.injections_failed} failed injection(s), "
                  f"{driver.refusals} refusal(s), {driver.errors - driver.call_failures} unusable "
                  f"reply(ies), {driver.call_failures} failed call(s)")
            # A reply the model gave but that cannot be used is the model's
            # outcome and belongs in the trace. Only a call that failed outright
            # holds the trace back, because the next run can retry it.
            if driver.call_failures and not args.keep_errors:
                print(f"  not kept ({partial.name}): a call to the model server failed; "
                      "the next run retries it, and finished turns come from the cache")
                continue
            partial.replace(final)
        stats = cache.stats()
        print(f"\ncache: {stats.hits} hit(s), {stats.misses} miss(es)"
              + ("" if args.cache_only else "; every miss was a billable call"))

    manifest = write_manifest(out_dir, args, pool)
    print(f"{out_dir.as_posix()}: {len(manifest['traces'])} trace(s); replications by outcome: "
          f"{manifest['replications_by_outcome']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
