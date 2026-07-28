"""Run configuration for the refinement harness.

Everything tunable lives here rather than as constants buried in code, so the
ablation study (proposal §7.3) can vary it from the CLI. See CLAUDE.md,
"Config over hardcoding".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Proposal §7.2 runs multiple seeds per trace to get confidence intervals and
# the paired Wilcoxon tests. A fixed *list*, not a single value.
DEFAULT_SEEDS: tuple[int, ...] = (0, 1, 2)


@dataclass(frozen=True)
class ModelConfig:
    """Model identity plus every generation setting that affects its output.

    Recorded verbatim on each trace record and hashed into ``prompt_hash``, so a
    replay (step 1.3) or cache hit (step 1.4) can only match a request issued
    under identical settings.

    On ``temperature``
    ------------------
    CLAUDE.md and proposal §9 call for "temperature 0" on gate/triage calls.
    That parameter **no longer exists** on current Anthropic models: Opus 4.7+,
    Sonnet 5, and Fable 5 removed ``temperature``/``top_p``/``top_k``, and
    sending one returns HTTP 400. The Messages API has never had a seed
    parameter either.

    Determinism in this project therefore rests on response caching (step 1.4)
    and trace replay (step 1.3) — not on sampling settings. This is not a
    weakening of the design: temperature 0 never guaranteed identical outputs
    on the models that did accept it, so replay was always the load-bearing
    mechanism. Set ``temperature`` below only if you pin an older model that
    still accepts it.
    """

    provider: str = "anthropic"
    model: str = "claude-opus-5"
    max_tokens: int = 16_000
    # low | medium | high | xhigh | max. "medium" keeps per-iteration cost down
    # for a capped student API budget (proposal §9); raise for harder scenarios.
    effort: str = "medium"
    # "adaptive" or "disabled". Keep adaptive: with thinking disabled, Opus 5
    # can leak <thinking> tags into the visible response, which would corrupt
    # the code we parse back out of it.
    thinking: str = "adaptive"
    # Only set on models that still accept it (Sonnet 4.6, Haiku 4.5, older).
    # Left as None on current models, where any value is a 400.
    temperature: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RunConfig:
    """One harness invocation: a snapshot, a prompt sequence, and where to log."""

    snapshot_dir: Path
    prompts: tuple[str, ...]
    trace_path: Path
    trace_id: str
    # Each seed is one independent replication of the full prompt sequence.
    # NOTE: the Anthropic API accepts no seed parameter, so this labels the
    # replication — it does not make the provider deterministic. Byte-identical
    # reruns come from replay mode (step 1.3), not from this value.
    seeds: tuple[int, ...] = DEFAULT_SEEDS
    model: ModelConfig = ModelConfig()

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_dir": str(self.snapshot_dir),
            "prompts": list(self.prompts),
            "trace_path": str(self.trace_path),
            "trace_id": self.trace_id,
            "seeds": list(self.seeds),
            "model": self.model.to_dict(),
        }
