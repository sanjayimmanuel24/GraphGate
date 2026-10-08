"""Run configuration for the refinement harness.

Everything tunable lives here rather than as constants buried in code, so the
ablation study (proposal §7.3) can vary it from the CLI. See CLAUDE.md,
"Config over hardcoding".
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Proposal §7.2 runs multiple seeds per trace to get confidence intervals and
# the paired Wilcoxon tests. A fixed *list*, not a single value.
DEFAULT_SEEDS: tuple[int, ...] = (0, 1, 2)

# Request settings each model is known to accept, used unless overridden.
# These differ because the models' APIs differ, not to tune the comparison:
# - Haiku 4.5 predates adaptive thinking and the effort parameter; sending
#   either is an HTTP 400, so its preset omits both.
# - Opus 4.8 does not think unless asked, so "adaptive" is explicit there
#   rather than resting on a default that differs from model to model.
# - Opus 5.5 thinks always and rejects "disabled"; "adaptive" names that mode.
# The settings actually sent are recorded on every trace record, so the §9
# model ablation is transparent about the model differing in more than size.
MODEL_PRESETS: dict[str, dict[str, str | None]] = {
    "claude-opus-5-5": {"thinking": "adaptive", "effort": "medium"},
    "claude-opus-5": {"thinking": "adaptive", "effort": "medium"},
    "claude-opus-4-8": {"thinking": "adaptive", "effort": "medium"},
    "claude-haiku-4-5": {"thinking": None, "effort": None},
}

# USD per million tokens, (input, output). For cost estimates printed before a
# paid run only; what a run actually used is in the recorded token counts.
PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-opus-4-8": (5.0, 25.0),
    "claude-haiku-4-5": (1.0, 5.0),
}

# CLI values for thinking/effort: take the model's preset, or omit the field.
USE_PRESET = "preset"
OMIT = "none"


@dataclass(frozen=True)
class ModelConfig:
    """Model identity plus every generation setting that affects its output.

    Recorded verbatim on each trace record and hashed into ``prompt_hash``, so a
    replay (step 1.3) or cache hit (step 1.4) can only match a request issued
    under identical settings.

    There is deliberately no ``temperature`` field. Current models removed the
    sampling parameters and return HTTP 400 for any value, and determinism here
    comes from response caching (step 1.4) and trace replay (step 1.3) instead.
    See ``docs/DETERMINISM.md`` and the determinism convention in CLAUDE.md.
    """

    provider: str = "anthropic"
    # Proposal §9: one primary code LLM plus a smaller ablation model. Primary
    # here; pass --model claude-haiku-4-5 for the ablation arm. Opus 4.8 rather
    # than a newer Opus because Opus 5 and 5.5 refused ordinary refinement turns
    # on harmless code; see docs/MODEL_CHOICE.md.
    model: str = "claude-opus-4-8"
    max_tokens: int = 16_000
    # low | medium | high | xhigh | max, or None to leave it out of the request
    # (Haiku 4.5 rejects it). "medium" keeps per-iteration cost down for a
    # capped student API budget (proposal §9); raise for harder scenarios.
    effort: str | None = "medium"
    # "adaptive" or "disabled", or None to leave it out (Haiku 4.5 rejects
    # adaptive). Prefer adaptive where supported: with thinking disabled, Opus 5
    # can leak <thinking> tags into the visible response, which would corrupt
    # the code we parse back out of it.
    thinking: str | None = "adaptive"
    # Where an open-weight model is served ("openai-compatible" provider only),
    # for example http://localhost:11434/v1 for a model run in a notebook.
    base_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def for_model(
        cls,
        model: str,
        *,
        max_tokens: int = 16_000,
        thinking: str = USE_PRESET,
        effort: str = USE_PRESET,
        provider: str = "anthropic",
        base_url: str | None = None,
    ) -> ModelConfig:
        """Settings for ``model``, filled from its preset unless overridden.

        ``thinking`` and ``effort`` take ``"preset"`` for the model's known-good
        value, ``"none"`` to omit the field, or an explicit value to send as-is.
        """
        if provider != "anthropic":
            # Thinking and effort are Anthropic request settings; other
            # servers are sent neither.
            return cls(provider=provider, model=model, max_tokens=max_tokens,
                       effort=None, thinking=None, base_url=base_url)
        preset = MODEL_PRESETS.get(model)
        if preset is None:
            if USE_PRESET in (thinking, effort):
                log.warning(
                    "no request preset for model %r; using the Opus defaults "
                    "(thinking=%s, effort=%s), which the API may reject",
                    model,
                    cls.thinking,
                    cls.effort,
                )
            preset = {"thinking": cls.thinking, "effort": cls.effort}

        def pick(value: str, field: str) -> str | None:
            if value == USE_PRESET:
                return preset[field]
            if value == OMIT:
                return None
            return value

        return cls(
            model=model,
            max_tokens=max_tokens,
            thinking=pick(thinking, "thinking"),
            effort=pick(effort, "effort"),
        )


@dataclass(frozen=True)
class RunConfig:
    """One harness invocation: a snapshot, a prompt sequence, and where to log."""

    prompts: tuple[str, ...]
    trace_path: Path
    trace_id: str
    # None in replay mode: a recorded trace carries its own starting snapshot, so
    # replaying one needs nothing on disk beyond the trace file itself.
    snapshot_dir: Path | None = None
    # Each seed is one independent replication of the full prompt sequence.
    # NOTE: the Anthropic API accepts no seed parameter, so this labels the
    # replication — it does not make the provider deterministic. Byte-identical
    # reruns come from replay mode (step 1.3), not from this value.
    seeds: tuple[int, ...] = DEFAULT_SEEDS
    model: ModelConfig = ModelConfig()

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_dir": None if self.snapshot_dir is None else str(self.snapshot_dir),
            "prompts": list(self.prompts),
            "trace_path": str(self.trace_path),
            "trace_id": self.trace_id,
            "seeds": list(self.seeds),
            "model": self.model.to_dict(),
        }
