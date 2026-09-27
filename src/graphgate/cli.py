"""Command-line entry point for the refinement harness.

Every knob is a flag rather than a constant, per CLAUDE.md — the ablation study
(proposal §7.3) varies model, effort, and seeds from here.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from graphgate.config import DEFAULT_SEEDS, OMIT, USE_PRESET, ModelConfig, RunConfig
from graphgate.harness.driver import RefinementDriver
from graphgate.harness.replay import ReplayClient

# The provider SDK is imported lazily inside _run_live() so that replaying an
# archived trace needs nothing but this package — someone reproducing our
# results from the artifact release (proposal §9) should not have to install an
# LLM SDK or hold an API key to do it.


def _parse_seeds(raw: str) -> tuple[int, ...]:
    try:
        seeds = tuple(int(part) for part in raw.split(",") if part.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"seeds must be comma-separated integers: {exc}")
    if not seeds:
        raise argparse.ArgumentTypeError("at least one seed is required")
    return seeds


def _load_prompts(path: Path) -> tuple[str, ...]:
    """One refinement instruction per line; blank lines and '#' comments skipped."""
    lines = path.read_text(encoding="utf-8").splitlines()
    prompts = tuple(
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    )
    if not prompts:
        raise ValueError(f"no prompts found in {path}")
    return prompts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="graphgate-harness",
        description="Run an LLM refinement loop over a snapshot and record a JSONL trace.",
    )
    parser.add_argument(
        "--out", type=Path, required=True,
        help="Path to the JSONL trace file to write (appended to).",
    )
    parser.add_argument(
        "--replay", type=Path, default=None, metavar="TRACE",
        help=(
            "Replay a saved trace instead of calling the LLM. Prompts, seeds, "
            "trace id, starting snapshot, and request params all come from the "
            "recording, so --snapshot/--prompts/--trace-id and the model flags "
            "are not used."
        ),
    )
    parser.add_argument(
        "--no-verify-hash", action="store_true",
        help=(
            "Replay only: don't fail when a rebuilt request doesn't hash to the "
            "recorded value. Use solely to read an old trace recorded before a "
            "prompt-format change — the replay is not faithful."
        ),
    )

    cache = parser.add_argument_group("response cache (live runs only)")
    cache.add_argument(
        "--cache", type=Path, default=None, metavar="DB",
        help=(
            "SQLite response cache. Identical requests are served from here "
            "instead of being paid for again."
        ),
    )
    cache.add_argument(
        "--cache-only", action="store_true",
        help=(
            "Fail on a cache miss instead of making a billable call. Enforces "
            "the pre-set API budget ceiling on a rerun expected to be fully "
            "cached. Requires --cache."
        ),
    )

    live = parser.add_argument_group("live run (ignored with --replay)")
    live.add_argument(
        "--snapshot", type=Path, default=None,
        help="Directory holding the starting Python files.",
    )
    live.add_argument(
        "--prompts", type=Path, default=None,
        help="Text file with one refinement instruction per line.",
    )
    live.add_argument(
        "--trace-id", default=None,
        help="Identifier recorded on every record in this run.",
    )
    live.add_argument(
        "--seeds", type=_parse_seeds, default=DEFAULT_SEEDS,
        help=(
            "Comma-separated replication seeds (default: %(default)s). "
            "Labels independent replications; the Anthropic API takes no seed "
            "parameter, so this does not by itself make the provider deterministic."
        ),
    )
    parser.add_argument("--model", default=ModelConfig.model, help="Model id (default: %(default)s).")
    parser.add_argument(
        "--max-tokens", type=int, default=ModelConfig.max_tokens,
        help="Max output tokens per turn (default: %(default)s).",
    )
    parser.add_argument(
        "--effort", default=USE_PRESET,
        choices=[USE_PRESET, OMIT, "low", "medium", "high", "xhigh", "max"],
        help=(
            "Reasoning depth / token spend. 'preset' (default) uses the model's "
            "known-good setting; 'none' leaves it out of the request."
        ),
    )
    parser.add_argument(
        "--thinking", default=USE_PRESET,
        choices=[USE_PRESET, OMIT, "adaptive", "disabled"],
        help=(
            "Thinking mode. 'preset' (default) uses the model's known-good "
            "setting; 'none' leaves it out of the request."
        ),
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


def _run_live(args: argparse.Namespace) -> int:
    missing = [
        flag
        for flag, value in (
            ("--snapshot", args.snapshot),
            ("--prompts", args.prompts),
            ("--trace-id", args.trace_id),
        )
        if value is None
    ]
    if missing:
        raise SystemExit(
            f"a live run requires {', '.join(missing)} (or pass --replay TRACE)"
        )
    if args.cache_only and args.cache is None:
        raise SystemExit("--cache-only requires --cache")

    # Imported here, after validation, so a bad command line reports the actual
    # problem rather than failing on a missing SDK.
    from graphgate.llm.anthropic_client import AnthropicCodeGenClient
    from graphgate.llm.cache import CachingClient, ResponseCache

    model = ModelConfig.for_model(
        args.model,
        max_tokens=args.max_tokens,
        thinking=args.thinking,
        effort=args.effort,
    )
    config = RunConfig(
        snapshot_dir=args.snapshot,
        prompts=_load_prompts(args.prompts),
        trace_path=args.out,
        trace_id=args.trace_id,
        seeds=args.seeds,
        model=model,
    )

    client = AnthropicCodeGenClient(model)
    if args.cache is None:
        return RefinementDriver(config, client).run()

    with ResponseCache(args.cache) as cache:
        wrapped = CachingClient(client, cache, read_only=args.cache_only)
        turns = RefinementDriver(config, wrapped).run()
        stats = cache.stats()
        logging.getLogger(__name__).info(
            "cache: %d hit(s), %d miss(es) (%.0f%% hit rate), %d entries in %s",
            stats.hits,
            stats.misses,
            stats.hit_rate * 100,
            stats.entries,
            args.cache,
        )
    return turns


def _run_replay(args: argparse.Namespace) -> int:
    """Re-run a recording through the driver with no network calls.

    Everything comes from the trace, so the run is reproducible from the trace
    file alone. The driver is the *same* code path as a live run — the parse and
    the diff are recomputed rather than copied, which is what makes a
    byte-identical result meaningful.
    """
    if args.replay.resolve() == args.out.resolve():
        raise SystemExit(
            "--out must differ from --replay: the writer appends, so replaying "
            "onto the source would corrupt it. Write elsewhere and diff the two."
        )

    client = ReplayClient.from_trace(args.replay, verify_hash=not args.no_verify_hash)
    config = RunConfig(
        prompts=client.prompts,
        trace_path=args.out,
        trace_id=client.trace_id,
        seeds=client.seeds,
        # snapshot_dir stays None: the recording carries its own starting state.
    )
    driver = RefinementDriver(
        config,
        client,
        clock=client.clock,
        initial=client.initial_snapshot,
    )
    return driver.run()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    log = logging.getLogger(__name__)

    if args.replay is not None:
        turns = _run_replay(args)
        log.info(
            "replayed %d turn(s) from %s into %s", turns, args.replay, args.out
        )
    else:
        turns = _run_live(args)
        log.info("wrote %d turn record(s) to %s", turns, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
