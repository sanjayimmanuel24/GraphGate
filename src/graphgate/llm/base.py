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


class RefusalError(CompletionError):
    """The model declined the request.

    Kept distinct from other failures because a refusal is a *model outcome*,
    not an infrastructure problem, and the study reports it as one (CLAUDE.md,
    "Refusals"). The classifier is most likely to decline exactly the
    security-relevant turns being measured, so refusals that were silently
    lumped in with network errors would bias the degradation curve downward
    without anyone being able to see it.

    Carries everything needed to write a full trace record — including the
    request hash, so a replay can verify it reproduced the refused request.
    """

    def __init__(
        self,
        *,
        prompt_hash: str,
        model: str,
        category: str | None = None,
        explanation: str | None = None,
        partial_text: str = "",
        usage: dict[str, int] | None = None,
        latency_ms: float | None = None,
        resolved_model: str | None = None,
    ):
        self.prompt_hash = prompt_hash
        # Same split as Completion: `model` is the ID requested (and hashed),
        # `resolved_model` the snapshot the API reported.
        self.model = model
        self.resolved_model = resolved_model
        # Either may be None even on a genuine refusal: the API documents
        # stop_details as informational, and explanation as not guaranteed.
        self.category = category
        self.explanation = explanation
        # Output streamed before a mid-generation refusal. Recorded for
        # provenance only — never parsed into the snapshot.
        self.partial_text = partial_text
        self.usage = dict(usage or {})
        self.latency_ms = latency_ms
        super().__init__(
            f"model declined the request (category={category or 'unspecified'}, "
            f"prompt_hash={prompt_hash[:12]})"
        )


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
    # True when served from the response cache. `latency_ms` and `usage` still
    # carry the originally measured values, so this flag is what separates
    # "what a deployment would cost" from "what this run actually spent".
    # See graphgate.llm.cache for the reasoning.
    cached: bool = False
    # `model` is the ID that was *requested* - the one prompt_hash covers.
    # `resolved_model` is the snapshot the API reports it served, which can
    # differ: requesting "claude-haiku-4-5" is answered as
    # "claude-haiku-4-5-20251001". Recording only the reported name broke
    # replay's hash check on every Haiku trace; recording only the requested
    # one would lose the exact identifier the paper must report.
    resolved_model: str | None = None


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

    def complete(self, system: str, user: str, *, replication: int) -> Completion:
        """One completion.

        ``replication`` is the seed of the replication this turn belongs to.
        The provider API takes no seed, so a live client does not send it; it
        exists so a cache can keep replications apart. Keyword-only and with no
        default on purpose — a caller that forgot it would silently collapse
        every seed into one cached trajectory.
        """
        ...

    def describe_params(self) -> dict[str, Any]:
        """Generation settings, for the trace record.

        Part of the protocol so the driver records them without sniffing at a
        provider-specific attribute.
        """
        ...


class CacheableClient(CodeGenClient, Protocol):
    """A client whose requests can be cached.

    Separate from :class:`CodeGenClient` because not every client is worth
    caching — replaying a recording is already free, so ReplayClient
    deliberately does not implement this.
    """

    def request_hash(self, system: str, user: str) -> str:
        """Hash of the request exactly as it will be sent (the ``prompt_hash``).

        On the client rather than computed by the cache so there is exactly one
        implementation: a caller that rebuilt it independently could drift from
        what the client hashes and silently miss every lookup. The cache key is
        this hash *plus* the replication — see graphgate.llm.cache.
        """
        ...
