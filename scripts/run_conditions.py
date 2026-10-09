"""Replay recorded traces under the gate conditions and score them (BUILD_PLAN 3.4).

    python scripts/run_conditions.py --traces runs/pilot-traces --no-triage
    python scripts/run_conditions.py --provider openai-compatible --base-url http://localhost:11434/v1 \
        --model qwen2.5-coder-14b-ctx32768

Conditions: A (no gate), B (Semgrep and Bandit, then LLM triage), B+ (B, with
the model also judging every change as a whole) and C (B plus the graph rules).
C has two views. "C" is the registered one: its graph holds the slice and the
rest of the repository at the fix commit, from the snapshots written by
scripts/build_repo_snapshots.py, with the event's leakage exclusions applied.
"C-slice" sees the slice alone and is reported beside it. Every condition is
given the same recorded turns. Traces must be labelled first
(scripts/label_traces.py).

Written to the output directory:
- turns.csv       one row per (trace, seed, condition, iteration); every
                  measure is computed from this file alone;
- decisions.jsonl the full record of every decision, for audit;
- summary.json    the measures per condition;
- degradation.png regressions surviving per iteration.

--no-triage runs B and C without the model: whatever is flagged blocks. That
is the proposal's "rules without LLM triage" ablation; it needs no model
server, and B+ has no such form. Reported as B-untriaged and C-untriaged.

Triage calls go to the model given by --provider/--model; responses are
cached, so a rerun pays only for what is missing. --cache-only never calls.

Pilot traces (runs/pilot-traces/) test the tools; their numbers are never
dataset results, and the summary says which kind it was computed from.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from graphgate.config import OMIT, USE_PRESET, ModelConfig
from graphgate.dataset.labels import labels_path
from graphgate.dataset.leakage import load_exclusions
from graphgate.experiment.metrics import summarise, write_rows
from graphgate.experiment.runner import CONDITION_A, NoGate, run_trace
from graphgate.gate.analysers import FindingCache, default_scanner
from graphgate.gate.graph_gate import CONDITION_C, GraphGate
from graphgate.gate.local import CONDITION_B, CONDITION_B_PLUS, LocalGate
from graphgate.gate.triage import PROMPT_VERSION, prompt_sha256
from graphgate.graph.delta import DEFAULT_HOPS
from graphgate.graph.link import SETTINGS
from graphgate.graph.overlay import SnapshotMissing, view_for_event
from graphgate.harness.replay import replay_turns
from graphgate.llm.factory import ANTHROPIC, PROVIDERS, make_client, not_ready

CONDITION_C_SLICE = "C-slice"
ALL_CONDITIONS = (CONDITION_A, CONDITION_B, CONDITION_B_PLUS, CONDITION_C_SLICE, CONDITION_C)
UNTRIAGED_SUFFIX = "-untriaged"
TRIAGE_MAX_TOKENS = 8000
SCHEMA_VERSION = 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--traces", type=Path, default=Path("data/traces"), help="default: %(default)s")
    parser.add_argument("--out-dir", type=Path, default=None,
                        help="default: data/results, or runs/conditions-pilot for pilot traces")
    parser.add_argument("--conditions", default=",".join(ALL_CONDITIONS),
                        help="comma-separated, from A, B, B+, C-slice, C (default: %(default)s)")
    parser.add_argument("--no-triage", action="store_true",
                        help="run B and C without the model: whatever is flagged blocks")
    parser.add_argument("--graph-setting", choices=sorted(SETTINGS), default="graphgate",
                        help="graph settings for Condition C (default: %(default)s, the registered one)")
    parser.add_argument("--hops", type=lambda v: None if v == "none" else int(v), default=DEFAULT_HOPS,
                        help="how far around a change the graph rules look; 'none' lifts the bound")
    parser.add_argument("--time-scans", type=int, default=None, metavar="N",
                        help="time the static scan of N turns on its own, outside the batched run "
                             "(default: every turn; 0: none). Semgrep takes about ten seconds each time.")
    parser.add_argument("--events-dir", type=Path, default=Path("data/events"))
    parser.add_argument("--repo-snapshots", type=Path, default=Path("data/interim/repo_snapshots"),
                        help="repositories at the fix commit, for C (default: %(default)s)")
    parser.add_argument("--leakage", type=Path, default=Path("data/leakage_exclusions.json"),
                        help="what C's repository view must leave out (default: %(default)s)")
    parser.add_argument("--model", default=ModelConfig.model, help="triage model (default: %(default)s)")
    parser.add_argument("--provider", choices=PROVIDERS, default=ANTHROPIC)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--max-tokens", type=int, default=TRIAGE_MAX_TOKENS)
    parser.add_argument("--effort", default=USE_PRESET,
                        choices=[USE_PRESET, OMIT, "low", "medium", "high", "xhigh", "max"])
    parser.add_argument("--thinking", default=USE_PRESET, choices=[USE_PRESET, OMIT, "adaptive", "disabled"])
    parser.add_argument("--cache", type=Path, default=Path("runs/cache.sqlite"))
    parser.add_argument("--cache-only", action="store_true", help="fail on a cache miss instead of calling")
    parser.add_argument("--max-calls", type=int, default=None,
                        help="stop before a trace once this many calls have gone to the model")
    parser.add_argument("--analysis-cache", type=Path, default=Path("runs/analysis-cache.sqlite"))
    parser.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def trace_files(directory: Path) -> list[Path]:
    traces = sorted(directory.glob("*.jsonl"))
    missing = [t.name for t in traces if not labels_path(t).exists()]
    if missing:
        raise SystemExit(f"{len(missing)} trace(s) in {directory.as_posix()} have no labels ({missing[0]} ...); "
                         "run scripts/label_traces.py first")
    return traces


def event_facts(events_dir: Path, trace: Path) -> dict:
    path = events_dir / trace.stem / "event.json"
    if not path.exists():
        return {"event_id": trace.stem}
    facts = json.loads(path.read_text(encoding="utf-8"))
    return {"event_id": trace.stem, "vulnerability_class": facts["vulnerability_class"], "scope": facts["scope"]}


def make_scan_timer(limit: int | None):
    """Time a turn's scan alone: a fresh scanner, the changed files as they are after the turn.

    The state before the turn is known from the turn before it, as it would
    be in a running gate, so only the new versions are scanned.
    """
    timed = 0

    def timer(change) -> float | None:
        nonlocal timed
        if limit is not None and timed >= limit:
            return None
        timed += 1
        scanner = default_scanner()
        versions = [(path, change.after[path]) for path in change.changed_paths if path in change.after]
        started = time.perf_counter()
        scanner.scan(versions)
        return time.perf_counter() - started

    return timer


def plot(summary: dict, path: Path) -> bool:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False
    figure, axis = plt.subplots(figsize=(6, 3.4))
    for name, result in summary["conditions"].items():
        curve = result["degradation_curve"]
        axis.plot([p["iteration"] for p in curve], [p["surviving"] for p in curve], marker="o", label=name)
    axis.set_xlabel("Iteration")
    axis.set_ylabel("Regressions surviving")
    axis.yaxis.get_major_locator().set_params(integer=True)
    axis.legend(title="Condition", frameon=False)
    figure.tight_layout()
    figure.savefig(path, dpi=200)
    plt.close(figure)
    return True


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)-7s %(name)s: %(message)s")
    sys.stdout.reconfigure(encoding="utf-8")

    wanted = [c.strip() for c in args.conditions.split(",") if c.strip()]
    unknown = [c for c in wanted if c not in ALL_CONDITIONS]
    if unknown:
        raise SystemExit(f"unknown condition(s) {', '.join(unknown)}; choose from {', '.join(ALL_CONDITIONS)}")
    if args.no_triage and CONDITION_B_PLUS in wanted:
        print("B+ is the model's judgement of the whole change and has no form without triage: left out")
        wanted.remove(CONDITION_B_PLUS)

    traces = trace_files(args.traces)
    if not traces:
        print(f"no trace in {args.traces.as_posix()}")
        return 1
    manifest_path = args.traces / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    pilot = bool(manifest.get("pilot", True))            # without a manifest saying otherwise: not dataset results
    out_dir = args.out_dir or Path("runs/conditions-pilot" if pilot else "data/results")

    needs_model = not args.no_triage and any(c != CONDITION_A for c in wanted)
    model = ModelConfig.for_model(args.model, max_tokens=args.max_tokens, thinking=args.thinking,
                                  effort=args.effort, provider=args.provider, base_url=args.base_url)
    if needs_model and not args.cache_only and not_ready(model):
        raise SystemExit(not_ready(model))

    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    complete = True
    with FindingCache(args.analysis_cache) as analysis_cache:
        needs_scanner = any(c != CONDITION_A for c in wanted)
        scanner = default_scanner(cache=analysis_cache) if needs_scanner else None
        if scanner is not None:
            # Every file version of every trace in one go: the scanners'
            # start-up cost is paid once, not once per turn.
            scanner.scan((path, files[path]) for trace in traces for turn in replay_turns(trace)
                         for files in (turn.before.files, turn.after.files)
                         for path in turn.changed_paths if path in files)

        cache = client = None
        if needs_model:
            from graphgate.llm.cache import CachingClient, ResponseCache
            cache = ResponseCache(args.cache)
            client = CachingClient(make_client(model), cache, read_only=args.cache_only)

        exclusions = load_exclusions(args.leakage) if CONDITION_C in wanted and args.leakage.exists() else {}
        if CONDITION_C in wanted and not args.leakage.exists():
            raise SystemExit(f"{args.leakage.as_posix()} is missing: C's repository view must apply the "
                             "leakage exclusions (scripts/check_leakage.py)")

        def gates_for(trace: Path) -> dict:
            """The gates for one trace. C's repository view belongs to the trace's event."""
            gates = {}
            for condition in wanted:
                name = condition + (UNTRIAGED_SUFFIX if args.no_triage and condition != CONDITION_A else "")
                if condition == CONDITION_A:
                    gates[name] = NoGate()
                elif condition in (CONDITION_C, CONDITION_C_SLICE):
                    view = None
                    if condition == CONDITION_C:
                        left_out = exclusions.get(trace.stem)
                        view = view_for_event(args.events_dir / trace.stem, args.repo_snapshots,
                                              exclude_files=left_out.files if left_out else (),
                                              exclude_symbols=left_out.symbols if left_out else ())
                    gates[name] = GraphGate(scanner, client, config=SETTINGS[args.graph_setting],
                                            hops=args.hops, use_triage=not args.no_triage, view=view)
                else:
                    gates[name] = LocalGate(condition, scanner, client, use_triage=not args.no_triage)
            return gates

        timer = make_scan_timer(args.time_scans) if needs_scanner and args.time_scans != 0 else None
        try:
            with (out_dir / "decisions.jsonl").open("w", encoding="utf-8", newline="\n") as audit:
                def keep(record: dict) -> None:
                    audit.write(json.dumps(record, ensure_ascii=False) + "\n")

                for trace in traces:
                    if args.max_calls is not None and cache is not None and cache.misses >= args.max_calls:
                        print(f"stopping before {trace.stem}: {cache.misses} call(s) made, --max-calls "
                              f"{args.max_calls}")
                        complete = False
                        break
                    try:
                        gates = gates_for(trace)
                    except SnapshotMissing as exc:
                        # Never fall back to the slice: that would be C-slice under C's name.
                        raise SystemExit(f"{exc}; or leave C out with --conditions") from exc
                    found = list(run_trace(trace, gates, event=event_facts(args.events_dir, trace),
                                           scan_timer=timer, on_decision=keep))
                    rows.extend(found)
                    blocks = {name: sum(r["condition"] == name and r["decision"] == "BLOCK" for r in found)
                              for name in gates if name != CONDITION_A}
                    print(f"{trace.stem:<22} {len({(r['seed'], r['iteration']) for r in found}):>3} turn(s); blocks: "
                          + ", ".join(f"{name} {count}" for name, count in blocks.items()))
        finally:
            if cache is not None:
                stats = cache.stats()
                print(f"cache: {stats.hits} hit(s), {stats.misses} miss(es)")
                cache.close()

    write_rows(out_dir / "turns.csv", rows)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "pilot": pilot,
        "note": ("Pilot traces: a test of the tools, not a dataset result." if pilot else
                 "Dataset traces.") + " A BLOCK is scored on the recorded course of the trace; what the model "
                "would have written after a block is not simulated.",
        "complete": complete,
        "traces_dir": args.traces.as_posix(),
        "triage": None if not needs_model else {
            "model": args.model, "provider": args.provider, "prompt_version": PROMPT_VERSION,
            "prompt_sha256": prompt_sha256()},
        "graph": {"setting": args.graph_setting, "config": SETTINGS[args.graph_setting].to_dict(),
                  "hops": args.hops, "registered_view": "repository (condition C); C-slice is the slice alone"}
        if {CONDITION_C, CONDITION_C_SLICE} & set(wanted) else None,
        "scanner": scanner.config if scanner is not None else None,
        **summarise(rows),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n")
    plotted = plot(summary, out_dir / "degradation.png")

    print()
    for name, result in summary["conditions"].items():
        recall, false = result["recall_at_introduction"]["all"], result["false_blocks"]["all_clean_turns"]
        added = result["overhead"]["median_added_seconds"]
        print(f"{name:<14} blocks {recall['blocked']} of {recall['introduced']} regression(s) on arrival; "
              f"{false['blocked']} of {false['clean_turns']} clean turn(s) blocked"
              + (f"; median added time {added:.1f} s" if added is not None else ""))
    print(f"wrote {out_dir.as_posix()}/turns.csv, decisions.jsonl, summary.json"
          + (", degradation.png" if plotted else " (no plot: matplotlib is not installed)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
