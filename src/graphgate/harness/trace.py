"""Trace records and JSONL persistence.

The trace is the project's primary artifact: step 1.3 replays it, step 1.4
caches against it, and M1.3's experiment runner derives every §7.2 metric from
it. Fields that later phases need are recorded now even though nothing reads
them yet — regenerating a trace means re-paying for the API calls.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Any, Iterator

SCHEMA_VERSION = 1

# Record kinds.
KIND_INIT = "init"  # turn 0: the starting snapshot, before any refinement
KIND_TURN = "turn"  # a completed refinement turn
KIND_ERROR = "error"  # a turn that failed; the replication stops here


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class TraceRecord:
    """One line of a trace file.

    ``files_after`` carries the full post-turn snapshot, not just the diff.
    That costs disk but makes replay lossless and independent of patch
    application, which is the whole point of step 1.3.
    """

    schema_version: int
    trace_id: str
    seed: int
    turn: int
    kind: str
    timestamp: str
    files_after: dict[str, str]
    diff: str = ""
    changed_paths: list[str] = field(default_factory=list)
    prompt: str | None = None
    prompt_hash: str | None = None
    model: str | None = None
    params: dict[str, Any] | None = None
    response_text: str | None = None
    usage: dict[str, int] = field(default_factory=dict)
    latency_ms: float | None = None
    error: str | None = None

    def to_json(self) -> str:
        # sort_keys so two runs producing the same record produce the same
        # bytes — the exit check for M1.1 is byte-identical trace files.
        return json.dumps(asdict(self), sort_keys=True, ensure_ascii=False)

    @classmethod
    def from_json(cls, line: str) -> TraceRecord:
        data = json.loads(line)
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"trace schema version {version!r} is not supported "
                f"(this build reads v{SCHEMA_VERSION})"
            )
        return cls(**data)


class TraceWriter:
    """Append-only JSONL writer.

    Flushes after every record so a crash or budget cut-off mid-run leaves the
    completed turns intact and readable.
    """

    def __init__(self, path: Path):
        self.path = path
        self._handle = None

    def __enter__(self) -> TraceWriter:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # newline="" keeps json.dumps output byte-identical across platforms;
        # without it Windows would rewrite \n as \r\n and break the
        # byte-identical-replay exit check.
        self._handle = self.path.open("a", encoding="utf-8", newline="")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def write(self, record: TraceRecord) -> None:
        if self._handle is None:
            raise RuntimeError("TraceWriter used outside its context manager")
        self._handle.write(record.to_json() + "\n")
        self._handle.flush()


def read_trace(path: Path) -> Iterator[TraceRecord]:
    """Stream records from a trace file, skipping blank lines."""
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield TraceRecord.from_json(line)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"{path}:{number}: malformed trace record: {exc}") from exc
