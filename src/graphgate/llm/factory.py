"""Choosing the model client from the run's configuration.

The provider is a setting, like the model: the scripts build their client here
so that a run against an open-weight model and one against the Anthropic API
differ in flags only.
"""

from __future__ import annotations

import os

from graphgate.config import ModelConfig
from graphgate.llm.base import CacheableClient

ANTHROPIC = "anthropic"
OPENAI_COMPATIBLE = "openai-compatible"
PROVIDERS = (ANTHROPIC, OPENAI_COMPATIBLE)


def not_ready(config: ModelConfig) -> str | None:
    """Why a live call cannot be made with ``config``, or None if it can."""
    if config.provider == ANTHROPIC and not os.environ.get("ANTHROPIC_API_KEY"):
        return ("ANTHROPIC_API_KEY is not set in this shell. Set it yourself "
                "(never in a project file), or pass --cache-only.")
    if config.provider == OPENAI_COMPATIBLE and not config.base_url:
        return "--provider openai-compatible needs --base-url, for example http://localhost:11434/v1"
    return None


def make_client(config: ModelConfig) -> CacheableClient:
    # Imported here so that neither provider's code is needed to use the other.
    if config.provider == ANTHROPIC:
        from graphgate.llm.anthropic_client import AnthropicCodeGenClient
        return AnthropicCodeGenClient(config)
    if config.provider == OPENAI_COMPATIBLE:
        from graphgate.llm.openai_compat import OpenAICompatClient
        return OpenAICompatClient(config)
    raise ValueError(f"unknown provider {config.provider!r}; expected one of {PROVIDERS}")
