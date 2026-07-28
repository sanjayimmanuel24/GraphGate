"""Command-line entry point for the refinement harness.

Every knob is a flag rather than a constant, per CLAUDE.md — the ablation study
(proposal §7.3) varies model, effort, and seeds from here.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from graphgate.config import DEFAULT_SEEDS, ModelConfig, RunConfig
from graphgate.harness.driver import RefinementDriver
from graphgate.llm.anthropic_client import AnthropicCodeGenClient


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
        "--snapshot", type=Path, required=True,
        help="Directory holding the starting Python files.",
    )
    parser.add_argument(
        "--prompts", type=Path, required=True,
        help="Text file with one refinement instruction per line.",
    )
    parser.add_argument(
        "--out", type=Path, required=True,
        help="Path to the JSONL trace file (appended to).",
    )
    parser.add_argument(
        "--trace-id", required=True,
        help="Identifier recorded on every record in this run.",
    )
    parser.add_argument(
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
        "--effort", default=ModelConfig.effort,
        choices=["low", "medium", "high", "xhigh", "max"],
        help="Reasoning depth / token spend (default: %(default)s).",
    )
    parser.add_argument(
        "--thinking", default=ModelConfig.thinking, choices=["adaptive", "disabled"],
        help="Thinking mode (default: %(default)s).",
    )
    parser.add_argument(
        "--temperature", type=float, default=None,
        help=(
            "Only valid on models that still accept sampling parameters "
            "(Sonnet 4.6, Haiku 4.5, older). Current models return HTTP 400."
        ),
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    model = ModelConfig(
        model=args.model,
        max_tokens=args.max_tokens,
        effort=args.effort,
        thinking=args.thinking,
        temperature=args.temperature,
    )
    config = RunConfig(
        snapshot_dir=args.snapshot,
        prompts=_load_prompts(args.prompts),
        trace_path=args.out,
        trace_id=args.trace_id,
        seeds=args.seeds,
        model=model,
    )

    driver = RefinementDriver(config, AnthropicCodeGenClient(model))
    turns = driver.run()
    logging.getLogger(__name__).info(
        "wrote %d turn record(s) to %s", turns, config.trace_path
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
