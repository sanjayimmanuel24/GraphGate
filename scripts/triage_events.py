"""Try the diff-only gates on each event's regression (BUILD_PLAN 3.2).

    python scripts/triage_events.py --dry-run
    python scripts/triage_events.py --show-prompt mako-2h4p
    python scripts/triage_events.py --max-calls 70

Runs Condition B (the LLM triages what Semgrep and Bandit flag) and the
diff-review baseline B+ (the LLM also judges every change as a whole) on two
changes per validated event: the regression itself, clean slice to regressed
slice, and as a control its reverse, the fix. A gate that blocks the
regression and lets the fix through is doing its job; one that blocks both is
only reacting to security-looking code.

This is a pilot of the triage step, not the study's result: the registered
evaluation runs over recorded refinement traces, where the regression arrives
bundled with a model's own edits (BUILD_PLAN 3.4).

--dry-run and --show-prompt send nothing and need no key. Any other run makes
billable API calls with the key in ANTHROPIC_API_KEY; responses are cached, so
a rerun pays only for what is missing. Decisions go to
runs/triage-pilot/decisions.jsonl.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path

from graphgate.cli import _parse_seeds
from graphgate.config import OMIT, PRICES_PER_MTOK, USE_PRESET, ModelConfig
from graphgate.dataset.events import approx_tokens
from graphgate.dataset.traceplan import select_events
from graphgate.gate.analysers import FindingCache, default_scanner
from graphgate.gate.local import BLOCK, CONDITION_B, CONDITION_B_PLUS, Change, LocalGate
from graphgate.gate.triage import SYSTEM_PROMPT, render_user_prompt
from graphgate.harness.snapshot import load_snapshot
from graphgate.llm.factory import ANTHROPIC, PROVIDERS, make_client, not_ready

TRIAGE_MAX_TOKENS = 8000
# A reply is a short JSON object, plus whatever reasoning the model does first.
# A rough range per call, for the cost estimate only.
OUTPUT_TOKENS = (300, 2000)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("events", nargs="*", help="event ids (default: every validated event)")
    parser.add_argument("--condition", choices=[CONDITION_B, CONDITION_B_PLUS, "both"], default="both")
    parser.add_argument("--no-control", action="store_true",
                        help="judge the regressions only, not the fixes as well")
    parser.add_argument("--dry-run", action="store_true", help="print what would be sent and a rough cost")
    parser.add_argument("--show-prompt", metavar="EVENT",
                        help="print the exact B+ request for one event's regression and stop")
    parser.add_argument("--seeds", type=_parse_seeds, default=(0,),
                        help="comma-separated replications (default: 0)")
    parser.add_argument("--model", default=ModelConfig.model, help="default: %(default)s")
    parser.add_argument("--provider", choices=PROVIDERS, default=ANTHROPIC,
                        help="'openai-compatible' for an open-weight model behind --base-url")
    parser.add_argument("--base-url", default=None,
                        help="model server address, for example http://localhost:11434/v1")
    parser.add_argument("--max-tokens", type=int, default=TRIAGE_MAX_TOKENS)
    parser.add_argument("--effort", default=USE_PRESET,
                        choices=[USE_PRESET, OMIT, "low", "medium", "high", "xhigh", "max"])
    parser.add_argument("--thinking", default=USE_PRESET,
                        choices=[USE_PRESET, OMIT, "adaptive", "disabled"])
    parser.add_argument("--cache", type=Path, default=Path("runs/cache.sqlite"),
                        help="model response cache (default: %(default)s)")
    parser.add_argument("--cache-only", action="store_true",
                        help="fail on a cache miss instead of making a billable call")
    parser.add_argument("--max-calls", type=int, default=None,
                        help="stop before the billable call that would pass this number")
    parser.add_argument("--analysis-cache", type=Path, default=Path("runs/analysis-cache.sqlite"))
    parser.add_argument("--out", type=Path, default=Path("runs/triage-pilot/decisions.jsonl"))
    parser.add_argument("--events-dir", type=Path, default=Path("data/events"))
    parser.add_argument("--signoff", type=Path, default=Path("data/validation_signoff.json"))
    parser.add_argument("--ai-review", type=Path, default=Path("data/validation_ai_review.json"))
    parser.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def load_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def load_changes(args) -> dict[str, dict]:
    """Per event: its facts, and the changes to judge (regression, and the fix as a control)."""
    ai_review = {r["event_id"]: r for r in load_json(args.ai_review, {"results": []})["results"]}
    decisions = load_json(args.signoff, {"decisions": {}})["decisions"]
    selected = tuple(args.events) or select_events(args.events_dir, ai_review, decisions).events
    events = {}
    for event_id in selected:
        event_dir = args.events_dir / event_id
        clean, regressed = load_snapshot(event_dir / "clean").files, load_snapshot(event_dir / "regressed").files
        facts = json.loads((event_dir / "event.json").read_text(encoding="utf-8"))
        changes = {"regression": Change.between(clean, regressed)}
        if not args.no_control:
            changes["fix"] = Change.between(regressed, clean)
        events[event_id] = {"class": facts["vulnerability_class"], "scope": facts["scope"], "changes": changes}
    return events


def prescan(scanner, events) -> None:
    # One run of each analyser for every file version of every event.
    scanner.scan((path, files[path]) for event in events.values() for change in event["changes"].values()
                 for files in (change.before, change.after) for path in change.changed_paths if path in files)


def dry_run(args, events, scanner, conditions) -> None:
    calls = tokens_in = 0
    print(f"{'event':<20} {'change':<10} " + " ".join(f"{c + ' items':>9}" for c in conditions) + "  ~input tokens")
    for event_id, event in events.items():
        for name, change in event["changes"].items():
            counts, size = [], 0
            for condition in conditions:
                items, _ = LocalGate(condition, scanner, None).items_for(change)
                counts.append(len(items))
                if items:
                    request = approx_tokens(SYSTEM_PROMPT + render_user_prompt(change.diff, items))
                    calls += len(args.seeds)
                    tokens_in += request * len(args.seeds)
                    size = max(size, request)
            print(f"{event_id:<20} {name:<10} " + " ".join(f"{n:>9}" for n in counts) + f"  {size or '-':>13}")
    low, high = (calls * n for n in OUTPUT_TOKENS)
    print(f"\n{calls} call(s) at most (a change with nothing to judge needs none), ~{tokens_in:,} input tokens, "
          f"~{low:,} to {high:,} output tokens (rough)")
    price = PRICES_PER_MTOK.get(args.model)
    if price:
        print(f"rough cost on {args.model}: ${(tokens_in * price[0] + low * price[1]) / 1e6:.2f} to "
              f"${(tokens_in * price[0] + high * price[1]) / 1e6:.2f}, before caching")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    sys.stdout.reconfigure(encoding="utf-8")
    if args.show_prompt:
        args.events = [args.show_prompt]
    conditions = [CONDITION_B, CONDITION_B_PLUS] if args.condition == "both" else [args.condition]

    events = load_changes(args)
    if not events:
        print(f"no validated event in {args.signoff.as_posix()}")
        return 1

    with FindingCache(args.analysis_cache) as analysis_cache:
        scanner = default_scanner(cache=analysis_cache)
        prescan(scanner, events)

        if args.show_prompt:
            change = events[args.show_prompt]["changes"]["regression"]
            items, _ = LocalGate(CONDITION_B_PLUS, scanner, None).items_for(change)
            print("=== system ===\n" + SYSTEM_PROMPT + "\n=== user ===\n" + render_user_prompt(change.diff, items))
            return 0
        if args.dry_run:
            dry_run(args, events, scanner, conditions)
            return 0

        model = ModelConfig.for_model(args.model, max_tokens=args.max_tokens, thinking=args.thinking,
                                      effort=args.effort, provider=args.provider, base_url=args.base_url)
        if not args.cache_only and not_ready(model):
            raise SystemExit(not_ready(model))
        # Imported after validation, so a dry run needs no SDK.
        from graphgate.llm.cache import CacheError, CachingClient, ResponseCache

        args.out.parent.mkdir(parents=True, exist_ok=True)
        blocked: Counter = Counter()
        outcomes: Counter = Counter()
        judged: Counter = Counter()
        stopped = None
        with ResponseCache(args.cache) as cache, args.out.open("w", encoding="utf-8", newline="") as out:
            client = CachingClient(make_client(model), cache, read_only=args.cache_only)
            gates = {c: LocalGate(c, scanner, client) for c in conditions}
            for event_id, event in events.items():
                for name, change in event["changes"].items():
                    for condition, gate in gates.items():
                        for seed in args.seeds:
                            if args.max_calls is not None and cache.misses >= args.max_calls:
                                stopped = f"--max-calls {args.max_calls} reached"
                                break
                            try:
                                decision = gate.decide(change, replication=seed)
                            except CacheError as exc:
                                stopped = str(exc)
                                break
                            out.write(json.dumps({"event_id": event_id, "change": name, "seed": seed,
                                                  "vulnerability_class": event["class"], "scope": event["scope"],
                                                  **decision.to_dict()}, ensure_ascii=False) + "\n")
                            judged[(condition, name)] += 1
                            blocked[(condition, name)] += decision.decision == BLOCK
                            outcomes[(condition, decision.outcome)] += 1
                            print(f"{event_id} {name:<10} {condition:<2} seed {seed}: {decision.decision} "
                                  f"({decision.outcome})")
                        if stopped:
                            break
                    if stopped:
                        break
                if stopped:
                    break
            stats = cache.stats()
        if stopped:
            print(f"\nstopped early: {stopped}")
        print(f"\nmodel responses: {stats.hits} from the cache, {stats.misses} miss(es)"
              + ("" if args.cache_only else "; every miss was a billable call"))

    for condition in conditions:
        print(f"\nCondition {condition}:")
        for name in ("regression", "fix"):
            if judged[(condition, name)]:
                print(f"    blocked {blocked[(condition, name)]} of {judged[(condition, name)]} {name} change(s)")
        print("    how decisions came about: "
              + ", ".join(f"{n} {outcome}" for (c, outcome), n in sorted(outcomes.items()) if c == condition))
    print(f"\nwrote {args.out.as_posix()}  (a pilot of the triage step, not the study's result)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
