"""Anthropic implementation of :class:`~graphgate.llm.base.CodeGenClient`."""

from __future__ import annotations

import logging
import time
from typing import Any

import anthropic

from graphgate.config import ModelConfig
from graphgate.llm.base import Completion, CompletionError, RefusalError, prompt_hash

log = logging.getLogger(__name__)


class AnthropicCodeGenClient:
    """Wraps the Messages API for one code-generation turn.

    Deliberately not agentic: the harness drives the refinement loop and this
    makes exactly one request per turn, so each turn maps to one trace record.
    """

    def __init__(self, config: ModelConfig, client: anthropic.Anthropic | None = None):
        if config.provider != "anthropic":
            raise ValueError(f"expected provider 'anthropic', got {config.provider!r}")
        self.config = config
        # Injectable so tests can drive a fake without touching the network.
        self._client = client if client is not None else anthropic.Anthropic()

    def _request_params(self) -> dict[str, Any]:
        """Generation settings, in the exact shape sent to the API.

        Also hashed into the cache key, so anything that changes the output
        must appear here.
        """
        # No temperature/top_p/top_k: removed on current models (HTTP 400), and
        # determinism comes from caching + replay instead. See docs/DETERMINISM.md.
        params: dict[str, Any] = {"max_tokens": self.config.max_tokens}
        # Omitted rather than sent as null when unset: models that predate a
        # setting reject the field outright (Haiku 4.5 rejects both).
        if self.config.thinking is not None:
            params["thinking"] = {"type": self.config.thinking}
        if self.config.effort is not None:
            params["output_config"] = {"effort": self.config.effort}
        return params

    def request_hash(self, system: str, user: str) -> str:
        """The hash this request will carry. Used by CachingClient to look up
        before spending anything, and by complete() below, so the two can never
        disagree."""
        return prompt_hash(system, user, self.config.model, self._request_params())

    def describe_params(self) -> dict[str, Any]:
        # Deliberately the wire params, not ModelConfig.to_dict(): these are what
        # prompt_hash is computed over, so recording them lets replay recompute
        # the hash and prove it reproduced the request exactly. Recording the
        # config shape instead would make that check impossible.
        return self._request_params()

    def complete(self, system: str, user: str, *, replication: int) -> Completion:
        # `replication` is deliberately not sent: the Messages API has no seed
        # parameter. It is accepted only to satisfy CodeGenClient; the cache in
        # front of this client is what uses it.
        del replication
        params = self._request_params()
        key = self.request_hash(system, user)

        started = time.perf_counter()
        try:
            response = self._client.messages.create(
                model=self.config.model,
                system=system,
                messages=[{"role": "user", "content": user}],
                **params,
            )
        except anthropic.APIError as exc:
            raise CompletionError(f"Anthropic call failed: {exc}") from exc
        latency_ms = (time.perf_counter() - started) * 1000

        text = "".join(
            block.text for block in response.content if block.type == "text"
        )
        usage = self._usage(response)

        # Opus 5 runs safety classifiers that can decline a request: HTTP 200,
        # stop_reason "refusal". Branch on stop_reason, never on stop_details —
        # the API documents stop_details as informational and possibly null.
        if response.stop_reason == "refusal":
            details = response.stop_details
            raise RefusalError(
                prompt_hash=key,
                model=self.config.model,
                resolved_model=response.model,
                category=getattr(details, "category", None),
                explanation=getattr(details, "explanation", None),
                partial_text=text,
                usage=usage,
                latency_ms=latency_ms,
            )
        if response.stop_reason == "max_tokens":
            # Not fatal, but the returned file is probably truncated — and a
            # truncated file would look like a deletion in the diff.
            log.warning(
                "response hit max_tokens=%d; file contents may be truncated "
                "(prompt_hash=%s)",
                self.config.max_tokens,
                key[:12],
            )

        if not text.strip():
            raise CompletionError(
                f"model returned no text (stop_reason={response.stop_reason}, "
                f"prompt_hash={key[:12]})"
            )

        return Completion(
            text=text,
            model=self.config.model,
            resolved_model=response.model,
            stop_reason=response.stop_reason,
            prompt_hash=key,
            latency_ms=latency_ms,
            usage=usage,
        )

    @staticmethod
    def _usage(response: Any) -> dict[str, int]:
        """Token counts from a response, including a refused one — a refusal
        after partial output is billed, so it still counts toward cost."""
        usage = response.usage
        return {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", 0) or 0,
            "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", 0) or 0,
        }
