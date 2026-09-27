"""Deterministic replay of a saved trace (BUILD_PLAN step 1.3).

Two consumers, one source of truth:

* :func:`replay_turns` yields the recorded turns as structured objects. This is
  the interface the gate conditions (A / B / C) consume in M1.3 and M2.2 — they
  all see byte-identical inputs because they read the same recording, so any
  difference in their results is attributable to the gate and not to the LLM.

* :class:`ReplayClient` satisfies :class:`~graphgate.llm.base.CodeGenClient`, so
  the *unmodified* driver can be re-run against a recording with no network
  calls. That re-derives the parse and the diff rather than trusting the stored
  ones, which is what makes M1.1's exit check meaningful: a byte-identical trace
  proves the whole pipeline is deterministic, not just that the file round-trips.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from graphgate.harness.snapshot import Snapshot
from graphgate.harness.trace import (
    KIND_ERROR,
    KIND_INIT,
    KIND_REFUSAL,
    KIND_TURN,
    TraceRecord,
    read_trace,
)
from graphgate.llm.base import Completion, CompletionError, RefusalError, prompt_hash

log = logging.getLogger(__name__)


class ReplayError(RuntimeError):
    """The recording cannot be replayed faithfully.

    Always raised rather than worked around: a replay that silently diverges
    from its source would invalidate every A/B/C comparison built on it.
    """


@dataclass(frozen=True)
class ReplayTurn:
    """One recorded turn, with the code state on both sides of it.

    ``before`` is reconstructed from the preceding record, so a gate gets the
    pre-change graph state without having to walk the trace itself.
    """

    trace_id: str
    seed: int
    turn: int
    kind: str
    prompt: str | None
    diff: str
    changed_paths: list[str]
    before: Snapshot
    after: Snapshot
    model: str | None
    usage: dict[str, int]
    latency_ms: float | None
    cached: bool
    error: str | None
    refusal_category: str | None = None
    refusal_explanation: str | None = None
    resolved_model: str | None = None

    @property
    def failed(self) -> bool:
        """The harness or API failed. Distinct from :attr:`refused`."""
        return self.kind == KIND_ERROR

    @property
    def refused(self) -> bool:
        """The model declined. A model outcome, reported in its own right."""
        return self.kind == KIND_REFUSAL


def load_records(path: Path) -> list[TraceRecord]:
    """Read a whole trace into memory.

    Traces are 5–8 turns over small files (proposal §6.1), so streaming buys
    nothing and random access makes the integrity checks below straightforward.
    """
    records = list(read_trace(path))
    if not records:
        raise ReplayError(f"trace is empty: {path}")
    return records


def replay_turns(path: Path) -> Iterator[ReplayTurn]:
    """Yield every recorded turn in trace order, with before/after snapshots.

    Init records are consumed to establish each replication's starting state and
    are not yielded — they are not turns. Error records *are* yielded, so a
    condition can account for replications that ended early instead of silently
    seeing a short trace.
    """
    current: Snapshot | None = None
    seen_init = False

    for record in load_records(path):
        if record.kind == KIND_INIT:
            current = Snapshot(files=dict(record.files_after))
            seen_init = True
            continue

        if not seen_init:
            raise ReplayError(
                f"{path}: record for seed {record.seed} turn {record.turn} "
                f"appears before any '{KIND_INIT}' record; cannot establish the "
                "starting snapshot"
            )
        assert current is not None  # guarded by seen_init

        after = Snapshot(files=dict(record.files_after))
        yield ReplayTurn(
            trace_id=record.trace_id,
            seed=record.seed,
            turn=record.turn,
            kind=record.kind,
            prompt=record.prompt,
            diff=record.diff,
            changed_paths=list(record.changed_paths),
            before=current,
            after=after,
            model=record.model,
            usage=dict(record.usage),
            latency_ms=record.latency_ms,
            cached=record.cached,
            error=record.error,
            refusal_category=record.refusal_category,
            refusal_explanation=record.refusal_explanation,
            resolved_model=record.resolved_model,
        )
        current = after


class ReplayClient:
    """A :class:`CodeGenClient` that serves pre-recorded responses.

    Hands back the recorded response text in trace order and never touches the
    network. Verifies as it goes: if the request the driver builds does not hash
    to the value stored alongside the recorded response, the replay has diverged
    and we stop rather than emit a trace that looks valid but isn't.
    """

    def __init__(self, records: list[TraceRecord], verify_hash: bool = True):
        self._verify_hash = verify_hash
        # Every record's timestamp, in file order, for the injected clock. The
        # driver writes records in exactly this order, so a FIFO lines up.
        self._timestamps: deque[str] = deque(r.timestamp for r in records)
        # Only the turn/error records, which are what complete() serves.
        self._pending: deque[TraceRecord] = deque(
            r for r in records if r.kind in (KIND_TURN, KIND_REFUSAL, KIND_ERROR)
        )
        self._source = records
        self.calls = 0

    @classmethod
    def from_trace(cls, path: Path, verify_hash: bool = True) -> ReplayClient:
        return cls(load_records(path), verify_hash=verify_hash)

    # -- Replay parameters recovered from the recording ---------------------
    #
    # A replay run is fully described by its source trace, so the CLI does not
    # need --prompts, --seeds, or the model flags repeated back to it. Taking
    # them from the recording also removes the chance of replaying a trace
    # against a prompt list that has since been edited.

    @property
    def trace_id(self) -> str:
        return self._source[0].trace_id

    @property
    def seeds(self) -> tuple[int, ...]:
        seen: list[int] = []
        for record in self._source:
            if record.seed not in seen:
                seen.append(record.seed)
        return tuple(seen)

    @property
    def initial_snapshot(self) -> Snapshot:
        """The starting code state, from the first init record."""
        for record in self._source:
            if record.kind == KIND_INIT:
                return Snapshot(files=dict(record.files_after))
        raise ReplayError(
            f"trace {self.trace_id} has no '{KIND_INIT}' record; the starting "
            "snapshot cannot be recovered"
        )

    @property
    def prompts(self) -> tuple[str, ...]:
        """The prompt sequence, taken from the longest replication.

        Every other replication must be a prefix of it; anything else means the
        trace was assembled from different runs and is not replayable as one.

        The longest, not the first: a replication cut short by a refusal or
        error holds only a prefix, and seed 0 is as likely to be cut short as
        any other. Using the first seed rejected a real Opus 5.5 trace in which
        seed 0 was refused at turn 2 and seed 1 ran all three turns.
        """
        by_seed: dict[int, list[str]] = {}
        for record in self._source:
            if record.kind in (KIND_TURN, KIND_REFUSAL, KIND_ERROR) and record.prompt is not None:
                by_seed.setdefault(record.seed, []).append(record.prompt)

        reference = max(by_seed.values(), key=len, default=[])
        if not reference:
            raise ReplayError(f"trace {self.trace_id} has no prompts to replay")

        for seed, prompts in by_seed.items():
            # An errored replication legitimately stops early, so a prefix match
            # is the correct test rather than full equality.
            if reference[: len(prompts)] != prompts:
                raise ReplayError(
                    f"trace {self.trace_id}: seed {seed} replays a prompt "
                    "sequence that is not a prefix of the longest replication's; "
                    "the trace is not a single replayable run"
                )
        return tuple(reference)

    # -- CodeGenClient ------------------------------------------------------

    def describe_params(self) -> dict[str, Any]:
        """The params recorded on the first served record.

        Replay does not choose params — it reproduces whatever the live run used,
        so the re-emitted trace carries the original values.

        Refusal and error records are searched too, not just successful turns.
        The driver writes the same params on all three, and a trace in which the
        model declined turn 1 on every seed contains no successful turn at all —
        restricting this to turns made such a trace unreplayable.
        """
        for record in self._source:
            if (
                record.kind in (KIND_TURN, KIND_REFUSAL, KIND_ERROR)
                and record.params is not None
            ):
                return dict(record.params)
        raise ReplayError(f"trace {self.trace_id} records no request params")

    def clock(self) -> str:
        """Next recorded timestamp, for injection into the driver."""
        if not self._timestamps:
            raise ReplayError(
                "replay wrote more records than the source trace contains; "
                "the driver's record sequence has diverged from the recording"
            )
        return self._timestamps.popleft()

    def complete(self, system: str, user: str, *, replication: int) -> Completion:
        if not self._pending:
            raise ReplayError(
                "replay requested more turns than the source trace contains; "
                "the driver's turn sequence has diverged from the recording"
            )
        record = self._pending.popleft()
        self.calls += 1

        if record.seed != replication:
            raise ReplayError(
                f"trace {record.trace_id} turn {record.turn}: recorded for seed "
                f"{record.seed} but requested by seed {replication}; the "
                "replay's replication order has diverged from the recording"
            )

        if record.kind == KIND_ERROR:
            # Reproduce the original failure so the replayed trace carries the
            # same error record and the replication stops at the same turn.
            raise CompletionError(record.error or "recorded failure (no message)")

        # Refusals carry the request hash, so unlike errors they are verified:
        # a replay that reaches a recorded refusal via a *different* request has
        # diverged just as surely as one that reaches a different response.
        if self._verify_hash:
            self._check_hash(record, system, user)

        if record.kind == KIND_REFUSAL:
            # Re-raise the recorded refusal so the driver writes an identical
            # refusal record — required for a byte-identical replay.
            raise RefusalError(
                prompt_hash=record.prompt_hash or "",
                model=record.model or "",
                resolved_model=record.resolved_model,
                category=record.refusal_category,
                explanation=record.refusal_explanation,
                partial_text=record.response_text or "",
                usage=record.usage,
                latency_ms=record.latency_ms,
            )

        return Completion(
            text=record.response_text or "",
            model=record.model or "",
            resolved_model=record.resolved_model,
            stop_reason="replayed",
            prompt_hash=record.prompt_hash or "",
            latency_ms=record.latency_ms if record.latency_ms is not None else 0.0,
            usage=dict(record.usage),
            # Reproduce the recorded value rather than asserting True: this says
            # whether the *original* call hit the cache, which is what the
            # overhead analysis needs. Replay itself is always free.
            cached=record.cached,
        )

    def _check_hash(self, record: TraceRecord, system: str, user: str) -> None:
        """Confirm the rebuilt request matches the one that was recorded.

        This is the substantive determinism check. The rendered prompt contains
        the full snapshot, so it only matches if response parsing and snapshot
        updating reproduced the original state exactly — an edit to the system
        prompt, the render function, or the parser all surface here rather than
        silently producing a subtly different trace.
        """
        if not record.prompt_hash or record.params is None or not record.model:
            log.warning(
                "trace %s seed %d turn %d lacks the fields needed to verify the "
                "request hash; skipping verification for this turn",
                record.trace_id,
                record.seed,
                record.turn,
            )
            return

        rebuilt = prompt_hash(system, user, record.model, record.params)
        if rebuilt != record.prompt_hash:
            raise ReplayError(
                f"trace {record.trace_id} seed {record.seed} turn {record.turn}: "
                f"rebuilt request hashes to {rebuilt[:12]} but the recording says "
                f"{record.prompt_hash[:12]}. The replay has diverged from the live "
                "run — the system prompt, prompt rendering, response parsing, or "
                "snapshot handling changed since this trace was recorded."
            )
