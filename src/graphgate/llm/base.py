"""Provider-agnostic code-generation client interface.

CLAUDE.md requires model choice to be a config flag, so the harness talks to
this protocol rather than to any one SDK. Anthropic is the concrete default
(see ``anthropic_client.py``); a second provider only has to satisfy
``CodeGenClient``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol


class CompletionError(RuntimeError):
    """The provider call failed or returned something unusable.

    Raised rather than swallowed: CLAUDE.md forbids silent fallbacks, and a
    turn that silently produced no code would corrupt the degradation curve.
    """


@dataclass(frozen=True)
class Completion:
    """One model response, plus everything the trace and metrics need.

    ``usage`` and ``latency_ms`` feed the overhead metrics in proposal §7.2;
    ``prompt_hash`` is the cache key for step 1.4.
    """

    text: str
    model: str
    stop_reason: str | None
    prompt_hash: str
    latency_ms: float
    usage: dict[str, int] = field(default_factory=dict)


def prompt_hash(system: str, user: str, model: str, params: dict[str, Any]) -> str:
    """Stable cache/replay key over the full request.

    ``sort_keys`` matters: an unsorted dict would hash differently run to run
    and silently defeat the cache in step 1.4.
    """
    payload = json.dumps(
        {"system": system, "user": user, "model": model, "params": params},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CodeGenClient(Protocol):
    """Single-shot completion. The harness owns the loop, not the client."""

    def complete(self, system: str, user: str) -> Completion: ...

    def describe_params(self) -> dict[str, Any]:
        """Generation settings, for the trace record.

        Part of the protocol so the driver records them without sniffing at a
        provider-specific attribute.
        """
        ...
