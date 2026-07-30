"""The refinement harness: drives the loop and records raw traces.

No gate logic lives here. This layer only produces the traces that conditions
A / B / C are later replayed against.
"""

from graphgate.harness.replay import (
    ReplayClient,
    ReplayError,
    ReplayTurn,
    replay_turns,
)
from graphgate.harness.snapshot import Snapshot, load_snapshot
from graphgate.harness.trace import TraceRecord, TraceWriter, read_trace

__all__ = [
    "Snapshot",
    "load_snapshot",
    "TraceRecord",
    "TraceWriter",
    "read_trace",
    "ReplayClient",
    "ReplayError",
    "ReplayTurn",
    "replay_turns",
]
