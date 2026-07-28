"""The refinement-loop driver (BUILD_PLAN step 1.2).

Takes a repo snapshot and an ordered list of prompts, calls the code-generation
LLM once per turn, and logs prompt / response / diff / timing to a JSONL trace.

No gate logic. This produces the raw traces that conditions A / B / C are later
replayed against.
"""

from __future__ import annotations

import logging

from graphgate.config import RunConfig
from graphgate.harness.diff import changed_paths, unified_diff
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
    KIND_TURN,
    SCHEMA_VERSION,
    TraceRecord,
    TraceWriter,
    utc_now_iso,
)
from graphgate.llm.base import CodeGenClient, CompletionError

log = logging.getLogger(__name__)


class RefinementDriver:
    """Runs each seed's full prompt sequence and appends to one trace file."""

    def __init__(self, config: RunConfig, client: CodeGenClient):
        self.config = config
        self.client = client

    def run(self) -> int:
        """Execute every replication. Returns the number of turns recorded."""
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
        return turns_written

    def _record(self, seed: int, turn: int, kind: str, **fields) -> TraceRecord:
        return TraceRecord(
            schema_version=SCHEMA_VERSION,
            trace_id=self.config.trace_id,
            seed=seed,
            turn=turn,
            kind=kind,
            timestamp=utc_now_iso(),
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
            self._record(seed, 0, KIND_INIT, files_after=dict(initial.files))
        )

        snapshot = initial
        params = self.client.describe_params()
        turns = 0

        for turn, prompt in enumerate(self.config.prompts, start=1):
            user_prompt = render_user_prompt(snapshot.files, prompt)
            try:
                completion = self.client.complete(SYSTEM_PROMPT, user_prompt)
                changes = parse_file_blocks(completion.text)
            except (CompletionError, ResponseParseError) as exc:
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
                    params=params,
                    response_text=completion.text,
                    usage=dict(completion.usage),
                    latency_ms=completion.latency_ms,
                )
            )
            snapshot = new_snapshot
            turns += 1

        return turns
