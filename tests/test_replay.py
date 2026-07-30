"""Tests for deterministic replay (BUILD_PLAN step 1.3).

The headline test is ``test_replayed_trace_is_byte_identical_to_source`` — that
is M1.1's exit check.

Shared fixtures (``snapshot_dir``, ``file_block``, ``record_live``,
``replay_into``) come from ``conftest.py``.
"""

from dataclasses import replace

import pytest

from graphgate.config import RunConfig
from graphgate.harness.driver import RefinementDriver
from graphgate.harness.replay import (
    ReplayClient,
    ReplayError,
    load_records,
    replay_turns,
)
from graphgate.harness.trace import KIND_ERROR, KIND_TURN, TraceWriter, read_trace
from graphgate.llm.base import CompletionError

from conftest import RecordingFakeClient


def tamper_prompt_hash(source, out):
    """Copy a trace, corrupting the recorded request hash on every turn."""
    with TraceWriter(out) as writer:
        for record in load_records(source):
            if record.kind == KIND_TURN:
                record = replace(record, prompt_hash="deadbeef")
            writer.write(record)
    return out


def drive_replay(source, out, prompts=None, verify_hash=True):
    """Replay with an overridable prompt list, for divergence tests."""
    client = ReplayClient.from_trace(source, verify_hash=verify_hash)
    config = RunConfig(
        prompts=client.prompts if prompts is None else tuple(prompts),
        trace_path=out,
        trace_id=client.trace_id,
        seeds=client.seeds,
    )
    driver = RefinementDriver(
        config, client, clock=client.clock, initial=client.initial_snapshot
    )
    return driver.run()


# --- The exit check ------------------------------------------------------


def test_replayed_trace_is_byte_identical_to_source(
    snapshot_dir, tmp_path, file_block, record_live, replay_into
):
    """M1.1 exit check: replay reproduces the trace exactly.

    The driver recomputes the parse and the diff rather than copying them, so
    equality here covers the whole pipeline, not just file round-tripping.
    """
    source = record_live(
        snapshot_dir,
        tmp_path / "source.jsonl",
        ["readability", "add a feature", "optimize"],
        [file_block("v = 2"), file_block("v = 3"), file_block("v = 4")],
    )
    replayed = tmp_path / "replayed.jsonl"

    replay_into(source, replayed)

    assert replayed.read_bytes() == source.read_bytes()


def test_replay_is_byte_identical_across_multiple_seeds(
    snapshot_dir, tmp_path, file_block, record_live, replay_into
):
    source = record_live(
        snapshot_dir,
        tmp_path / "source.jsonl",
        ["a", "b"],
        [file_block("v = 2"), file_block("v = 3"), file_block("v = 9"), file_block("v = 10")],
        seeds=(0, 1),
    )
    replayed = tmp_path / "replayed.jsonl"

    replay_into(source, replayed)

    assert replayed.read_bytes() == source.read_bytes()


def test_replaying_twice_gives_identical_output(
    snapshot_dir, tmp_path, file_block, record_live, replay_into
):
    """Replay must be idempotent — it is run once per gate condition."""
    source = record_live(
        snapshot_dir, tmp_path / "source.jsonl", ["a"], [file_block("v = 2")]
    )
    first, second = tmp_path / "one.jsonl", tmp_path / "two.jsonl"

    replay_into(source, first)
    replay_into(source, second)

    assert first.read_bytes() == second.read_bytes()


def test_replay_serves_every_turn_from_the_recording(
    snapshot_dir, tmp_path, file_block, record_live
):
    source = record_live(
        snapshot_dir,
        tmp_path / "source.jsonl",
        ["a", "b"],
        [file_block("v = 2"), file_block("v = 3")],
    )
    client = ReplayClient.from_trace(source)
    config = RunConfig(
        prompts=client.prompts,
        trace_path=tmp_path / "out.jsonl",
        trace_id=client.trace_id,
        seeds=client.seeds,
    )
    RefinementDriver(
        config, client, clock=client.clock, initial=client.initial_snapshot
    ).run()

    assert client.calls == 2


def test_replay_needs_no_source_directory(
    snapshot_dir, tmp_path, file_block, record_live, replay_into
):
    """A recording is replayable from the trace file alone (proposal §9 artifact
    release) — the original snapshot directory can be gone."""
    import shutil

    source = record_live(
        snapshot_dir, tmp_path / "source.jsonl", ["a"], [file_block("v = 2")]
    )
    shutil.rmtree(snapshot_dir)

    replay_into(source, tmp_path / "replayed.jsonl")

    assert (tmp_path / "replayed.jsonl").read_bytes() == source.read_bytes()


# --- replay_turns: the interface conditions A/B/C consume ----------------


def test_replay_turns_reconstructs_before_and_after(
    snapshot_dir, tmp_path, file_block, record_live
):
    source = record_live(
        snapshot_dir,
        tmp_path / "t.jsonl",
        ["a", "b"],
        [file_block("v = 2"), file_block("v = 3")],
    )
    turns = list(replay_turns(source))

    assert [t.turn for t in turns] == [1, 2]
    assert turns[0].before.files["app.py"] == "def run():\n    return 1\n"
    assert turns[0].after.files["app.py"] == "v = 2"
    # Turn 2's "before" is turn 1's "after", not the original snapshot.
    assert turns[1].before.files["app.py"] == "v = 2"
    assert turns[1].after.files["app.py"] == "v = 3"


def test_replay_turns_carries_diff_and_metrics(
    snapshot_dir, tmp_path, file_block, record_live
):
    source = record_live(
        snapshot_dir, tmp_path / "t.jsonl", ["readability"], [file_block("v = 2")]
    )
    turn = next(iter(replay_turns(source)))

    assert turn.prompt == "readability"
    assert turn.changed_paths == ["app.py"]
    assert "+v = 2" in turn.diff
    assert turn.usage == {"input_tokens": 5, "output_tokens": 7}
    assert turn.latency_ms == 1.5
    assert not turn.failed


def test_replay_turns_separates_seeds(snapshot_dir, tmp_path, file_block, record_live):
    source = record_live(
        snapshot_dir,
        tmp_path / "t.jsonl",
        ["a"],
        [file_block("v = 2"), file_block("v = 9")],
        seeds=(0, 1),
    )
    turns = list(replay_turns(source))

    assert [(t.seed, t.turn) for t in turns] == [(0, 1), (1, 1)]
    # Each seed restarts from the initial snapshot.
    assert turns[0].before.files == turns[1].before.files


def test_replay_turns_yields_error_records(snapshot_dir, tmp_path, record_live):
    """A condition must be able to see that a replication ended early, rather
    than silently receiving a short trace."""
    source = record_live(
        snapshot_dir,
        tmp_path / "t.jsonl",
        ["a", "b"],
        [CompletionError("model declined the request")],
    )
    turns = list(replay_turns(source))

    assert len(turns) == 1
    assert turns[0].failed
    assert "declined" in turns[0].error


def test_replay_turns_rejects_turn_before_init(tmp_path, make_trace_record):
    path = tmp_path / "bad.jsonl"
    with TraceWriter(path) as writer:
        writer.write(make_trace_record(turn=1, kind=KIND_TURN))

    with pytest.raises(ReplayError, match="before any 'init' record"):
        list(replay_turns(path))


def test_load_records_rejects_empty_trace(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ReplayError, match="trace is empty"):
        load_records(path)


# --- Integrity checks ----------------------------------------------------


def test_hash_mismatch_is_fatal(snapshot_dir, tmp_path, file_block, record_live):
    """A divergent replay must fail loudly, not emit a trace that looks valid."""
    source = record_live(
        snapshot_dir, tmp_path / "source.jsonl", ["a"], [file_block("v = 2")]
    )
    tampered = tamper_prompt_hash(source, tmp_path / "tampered.jsonl")

    with pytest.raises(ReplayError, match="has diverged from the live run"):
        drive_replay(tampered, tmp_path / "out.jsonl")


def test_hash_verification_can_be_disabled(
    snapshot_dir, tmp_path, file_block, record_live
):
    """Escape hatch for reading a trace recorded before a format change."""
    source = record_live(
        snapshot_dir, tmp_path / "source.jsonl", ["a"], [file_block("v = 2")]
    )
    tampered = tamper_prompt_hash(source, tmp_path / "tampered.jsonl")

    assert drive_replay(tampered, tmp_path / "out.jsonl", verify_hash=False) == 1


def test_exhausted_replay_raises(snapshot_dir, tmp_path, file_block, record_live):
    """Asking for more turns than were recorded means the caller diverged."""
    source = record_live(
        snapshot_dir, tmp_path / "source.jsonl", ["a"], [file_block("v = 2")]
    )

    with pytest.raises(ReplayError, match="more turns than the source trace"):
        drive_replay(source, tmp_path / "out.jsonl", prompts=["a", "extra"])


def test_replay_recovers_run_parameters(
    snapshot_dir, tmp_path, file_block, record_live
):
    source = record_live(
        snapshot_dir,
        tmp_path / "source.jsonl",
        ["readability", "optimize"],
        [file_block("v = 2"), file_block("v = 3"), file_block("v = 9"), file_block("v = 10")],
        seeds=(0, 1),
    )
    client = ReplayClient.from_trace(source)

    assert client.trace_id == "src-trace"
    assert client.seeds == (0, 1)
    assert client.prompts == ("readability", "optimize")
    assert client.initial_snapshot.files["app.py"] == "def run():\n    return 1\n"
    assert client.describe_params() == RecordingFakeClient.PARAMS


def test_prompts_tolerate_a_short_errored_replication(
    snapshot_dir, tmp_path, file_block, record_live
):
    """Seed 1 stopping early is legitimate; it must not read as a divergence."""
    source = record_live(
        snapshot_dir,
        tmp_path / "source.jsonl",
        ["a", "b"],
        [file_block("v = 2"), file_block("v = 3"), CompletionError("transient")],
        seeds=(0, 1),
    )
    client = ReplayClient.from_trace(source)

    assert client.prompts == ("a", "b")
    assert list(read_trace(source))[-1].kind == KIND_ERROR
