"""The refinement-loop driver (BUILD_PLAN step 1.2).

Takes a repo snapshot and an ordered list of prompts, calls the code-generation
LLM once per turn, and logs prompt / response / diff / timing to a JSONL trace.

No gate logic. This produces the raw traces that conditions A / B / C are later
replayed against.
"""

from __future__ import annotations

import logging
from typing import Callable

from graphgate.config import RunConfig
from graphgate.harness.diff import changed_paths, unified_diff
from graphgate.harness.injection import InjectionError, InjectionPlan
from graphgate.harness.protocol import (
    SYSTEM_PROMPT,
    ResponseParseError,
    parse_file_blocks,
    render_user_prompt,
)
from graphgate.harness.snapshot import Snapshot, load_snapshot
from graphgate.harness.trace import (
    KIND_ERROR,
    KIND_INIT,
    KIND_REFUSAL,
    KIND_TURN,
    SCHEMA_VERSION,
    TraceRecord,
    TraceWriter,
    utc_now_iso,
)
from graphgate.llm.base import CodeGenClient, CompletionError, RefusalError

log = logging.getLogger(__name__)


class ReplyCutOff(CompletionError):
    """The model's reply stopped at the output limit, so its last file is incomplete."""


class RefinementDriver:
    """Runs each seed's full prompt sequence and appends to one trace file."""

    def __init__(
        self,
        config: RunConfig,
        client: CodeGenClient,
        clock: Callable[[], str] = utc_now_iso,
        initial: Snapshot | None = None,
        injection: InjectionPlan | None = None,
        schema_version: int = SCHEMA_VERSION,
    ):
        if injection is not None and schema_version < 5:
            raise ValueError("an injection plan needs trace schema v5 or later")
        self.config = config
        self.client = client
        # The regression to place at one turn of every replication (BUILD_PLAN
        # 2.4). None for a plain refinement run.
        self._injection = injection
        # Replay passes the source trace's version so an archived v4 trace is
        # re-emitted as v4, byte for byte.
        self._schema_version = schema_version
        # Injectable so replay (step 1.3) can re-emit the *recorded* timestamps
        # rather than the wall clock. Without this, a replayed trace could never
        # be byte-identical to its source, which is M1.1's exit check.
        self._clock = clock
        # Replay supplies the starting snapshot straight from the trace, so a
        # recording is replayable without the original source directory.
        self._initial = initial
        # Outcome counters across all replications, for the run summary.
        self.refusals = 0
        self.errors = 0
        # The part of `errors` where the call itself failed (server down, rate
        # limit). Those are worth retrying; a reply the model did give but that
        # cannot be used is an outcome of the model and stays in the trace.
        self.call_failures = 0
        self.injections_applied = 0
        self.injections_failed = 0

    def run(self) -> int:
        """Execute every replication. Returns the number of turns recorded."""
        initial = self._initial
        if initial is None:
            if self.config.snapshot_dir is None:
                raise ValueError(
                    "no starting snapshot: RunConfig.snapshot_dir is None and no "
                    "initial snapshot was supplied"
                )
            initial = load_snapshot(self.config.snapshot_dir)
        log.info(
            "trace %s: %d file(s), %d prompt(s), seeds=%s",
            self.config.trace_id,
            len(initial.files),
            len(self.config.prompts),
            list(self.config.seeds),
        )

        turns_written = 0
        with TraceWriter(self.config.trace_path) as writer:
            for seed in self.config.seeds:
                turns_written += self._run_replication(writer, initial, seed)

        # Refusals are reported in their own right (CLAUDE.md, "Refusals"), so
        # the run summary separates them from genuine failures.
        log.info(
            "trace %s: %d turn(s) completed, %d refusal(s), %d error(s)",
            self.config.trace_id,
            turns_written,
            self.refusals,
            self.errors,
        )
        return turns_written

    def _record(self, seed: int, turn: int, kind: str, **fields) -> TraceRecord:
        return TraceRecord(
            schema_version=self._schema_version,
            trace_id=self.config.trace_id,
            seed=seed,
            turn=turn,
            kind=kind,
            timestamp=self._clock(),
            **fields,
        )

    def _run_replication(
        self, writer: TraceWriter, initial: Snapshot, seed: int
    ) -> int:
        """One independent pass over the prompt sequence.

        A failed turn ends this replication rather than continuing: carrying a
        stale snapshot forward would log later turns as no-ops and understate
        the degradation curve.
        """
        writer.write(
            self._record(
                seed,
                0,
                KIND_INIT,
                files_after=dict(initial.files),
                injection=None if self._injection is None else self._injection.to_dict(),
            )
        )

        snapshot = initial
        params = self.client.describe_params()
        turns = 0

        for turn, prompt in enumerate(self.config.prompts, start=1):
            user_prompt = render_user_prompt(snapshot.files, prompt)
            try:
                completion = self.client.complete(
                    SYSTEM_PROMPT, user_prompt, replication=seed
                )
                if completion.stop_reason == "max_tokens":
                    # A reply cut off mid-file would still parse: the unfinished
                    # block is dropped and the finished ones applied, recording
                    # a smaller change than the model made. A failure instead.
                    raise ReplyCutOff(
                        "response was cut off at max_tokens; the turn is not "
                        "usable (raise --max-tokens and rerun)"
                    )
                changes = parse_file_blocks(completion.text)
            except RefusalError as refusal:
                # Caught before CompletionError (its base class) so a refusal is
                # recorded as the model outcome it is, with the category needed
                # to report the refusal rate — not as a generic failure.
                self.refusals += 1
                log.warning(
                    "trace %s seed %d turn %d: model declined (category=%s)",
                    self.config.trace_id,
                    seed,
                    turn,
                    refusal.category or "unspecified",
                )
                writer.write(
                    self._record(
                        seed,
                        turn,
                        KIND_REFUSAL,
                        # Unchanged: the refused change never reached the code.
                        files_after=dict(snapshot.files),
                        prompt=prompt,
                        prompt_hash=refusal.prompt_hash,
                        model=refusal.model,
                        resolved_model=refusal.resolved_model,
                        params=params,
                        response_text=refusal.partial_text,
                        usage=dict(refusal.usage),
                        latency_ms=refusal.latency_ms,
                        refusal_category=refusal.category,
                        refusal_explanation=refusal.explanation,
                    )
                )
                return turns
            except (CompletionError, ResponseParseError) as exc:
                self.errors += 1
                if not isinstance(exc, (ResponseParseError, ReplyCutOff)):
                    self.call_failures += 1
                log.error(
                    "trace %s seed %d turn %d failed: %s",
                    self.config.trace_id,
                    seed,
                    turn,
                    exc,
                )
                writer.write(
                    self._record(
                        seed,
                        turn,
                        KIND_ERROR,
                        files_after=dict(snapshot.files),
                        prompt=prompt,
                        params=params,
                        error=str(exc),
                    )
                )
                return turns

            unknown = sorted(set(changes) - set(snapshot.files))
            if unknown:
                # Not an error — a refinement may legitimately add a module —
                # but it is worth surfacing, since a hallucinated path would
                # otherwise silently enter the snapshot.
                log.info(
                    "trace %s seed %d turn %d: model introduced new file(s): %s",
                    self.config.trace_id,
                    seed,
                    turn,
                    ", ".join(unknown),
                )

            new_snapshot = snapshot.updated(changes)
            outcome = None
            if self._injection is not None and turn == self._injection.turn:
                # Bundled injection: the model's own change for this turn stays,
                # and the regression is placed in the code it produced.
                try:
                    files, report = self._injection.apply(dict(new_snapshot.files))
                    new_snapshot = Snapshot(files=files)
                    outcome = {"status": "applied", **report}
                    self.injections_applied += 1
                except InjectionError as exc:
                    outcome = {"status": "failed", "reason": str(exc)}
                    self.injections_failed += 1
                    log.warning(
                        "trace %s seed %d turn %d: injection failed: %s",
                        self.config.trace_id,
                        seed,
                        turn,
                        exc,
                    )
            diff = unified_diff(snapshot, new_snapshot)
            if not diff:
                log.warning(
                    "trace %s seed %d turn %d produced no change",
                    self.config.trace_id,
                    seed,
                    turn,
                )

            writer.write(
                self._record(
                    seed,
                    turn,
                    KIND_TURN,
                    files_after=dict(new_snapshot.files),
                    diff=diff,
                    changed_paths=changed_paths(snapshot, new_snapshot),
                    prompt=prompt,
                    prompt_hash=completion.prompt_hash,
                    model=completion.model,
                    resolved_model=completion.resolved_model,
                    params=params,
                    response_text=completion.text,
                    usage=dict(completion.usage),
                    latency_ms=completion.latency_ms,
                    cached=completion.cached,
                    injection=outcome,
                )
            )
            snapshot = new_snapshot
            turns += 1
            if outcome is not None and outcome["status"] == "failed":
                # Without its regression this replication cannot be scored, so
                # it stops here rather than paying for turns nobody will use.
                # The turns already recorded are ordinary model turns.
                return turns

        return turns
