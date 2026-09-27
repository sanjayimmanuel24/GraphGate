"""Refusals are recorded and reported as their own outcome (CLAUDE.md, "Refusals").

Covers the full path: the real client turning an SDK refusal into RefusalError,
the driver recording it, replay reproducing it byte-for-byte, and the cache
declining to store it.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from anthropic.types import Message

from graphgate.config import ModelConfig, RunConfig
from graphgate.harness.driver import RefinementDriver
from graphgate.harness.replay import ReplayError, load_records, replay_turns
from graphgate.harness.trace import (
    KIND_ERROR,
    KIND_INIT,
    KIND_REFUSAL,
    KIND_TURN,
    TraceWriter,
    read_trace,
)
from graphgate.llm.anthropic_client import AnthropicCodeGenClient
from graphgate.llm.base import CompletionError, RefusalError
from graphgate.llm.cache import CachingClient, ResponseCache

from conftest import RecordingFakeClient


def refusal(category="cyber", explanation="declined by classifier"):
    """A refusal to feed the fake client; it fills in the real request hash."""
    return RefusalError(
        prompt_hash="",
        model="",
        category=category,
        explanation=explanation,
        usage={"input_tokens": 40, "output_tokens": 0},
        latency_ms=2.5,
    )


# --- The real client, against genuine SDK objects -----------------------


def sdk_message(**overrides) -> Message:
    """A validated SDK Message — model_validate, not model_construct, so nested
    fields become the same typed objects a live response carries."""
    data = {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "content": [{"type": "text", "text": "### FILE: app.py\n```python\nv = 2\n```\n"}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 120, "output_tokens": 30},
    }
    data.update(overrides)
    return Message.model_validate(data)


def client_returning(message: Message) -> AnthropicCodeGenClient:
    fake_sdk = SimpleNamespace(messages=SimpleNamespace(create=lambda **_: message))
    return AnthropicCodeGenClient(ModelConfig(), client=fake_sdk)


def test_real_client_returns_a_completion_for_a_normal_response():
    completion = client_returning(sdk_message()).complete("sys", "user", replication=0)

    assert "v = 2" in completion.text
    assert completion.stop_reason == "end_turn"
    assert completion.usage["input_tokens"] == 120
    assert completion.usage["output_tokens"] == 30
    assert completion.cached is False


def test_real_client_turns_a_refusal_into_refusal_error():
    message = sdk_message(
        content=[],
        stop_reason="refusal",
        stop_details={
            "type": "refusal",
            "category": "cyber",
            "explanation": "request resembles exploit development",
        },
        usage={"input_tokens": 90, "output_tokens": 0},
    )
    client = client_returning(message)

    with pytest.raises(RefusalError) as caught:
        client.complete("sys", "user", replication=0)

    err = caught.value
    assert err.category == "cyber"
    assert err.explanation == "request resembles exploit development"
    assert err.usage["input_tokens"] == 90
    assert err.latency_ms is not None
    # The recorded hash must be the real request hash, or replay can't verify it.
    assert err.prompt_hash == client.request_hash("sys", "user")


def test_real_client_handles_a_refusal_with_no_stop_details():
    """The API documents stop_details as informational — it can be null even on
    a genuine refusal. Must still be recorded as a refusal, not crash."""
    message = sdk_message(content=[], stop_reason="refusal", stop_details=None)

    with pytest.raises(RefusalError) as caught:
        client_returning(message).complete("sys", "user", replication=0)

    assert caught.value.category is None
    assert caught.value.explanation is None


def test_real_client_keeps_partial_output_from_a_mid_generation_refusal():
    message = sdk_message(
        content=[{"type": "text", "text": "### FILE: app.py\n```python\npartial"}],
        stop_reason="refusal",
        stop_details={"type": "refusal", "category": "cyber", "explanation": None},
    )

    with pytest.raises(RefusalError) as caught:
        client_returning(message).complete("sys", "user", replication=0)

    assert caught.value.partial_text.startswith("### FILE: app.py")


def test_refusal_is_still_a_completion_error():
    """Generic handlers written against CompletionError must keep catching it."""
    assert issubclass(RefusalError, CompletionError)


# --- The driver records a refusal as its own outcome ---------------------


def test_refusal_is_recorded_as_its_own_kind(snapshot_dir, tmp_path, file_block, record_live):
    source = record_live(
        snapshot_dir,
        tmp_path / "t.jsonl",
        ["readability", "optimize"],
        [file_block("v = 2"), refusal(category="cyber")],
    )
    records = list(read_trace(source))

    assert [r.kind for r in records] == [KIND_INIT, KIND_TURN, KIND_REFUSAL]
    refused = records[-1]
    assert refused.refusal_category == "cyber"
    assert refused.refusal_explanation == "declined by classifier"
    # A refusal is a model outcome, not a harness failure.
    assert refused.error is None
    # It still costs something, and that belongs in the overhead figures.
    assert refused.usage == {"input_tokens": 40, "output_tokens": 0}
    assert refused.latency_ms == 2.5
    assert refused.prompt == "optimize"
    assert len(refused.prompt_hash) == 64


def test_refused_change_never_reaches_the_snapshot(
    snapshot_dir, tmp_path, file_block, record_live
):
    source = record_live(
        snapshot_dir,
        tmp_path / "t.jsonl",
        ["a", "b"],
        [file_block("v = 2"), refusal()],
    )
    records = list(read_trace(source))

    assert records[-1].files_after == records[-2].files_after
    assert records[-1].diff == ""
    assert records[-1].changed_paths == []


def test_refusal_ends_the_replication(snapshot_dir, tmp_path, file_block, record_live):
    source = record_live(
        snapshot_dir,
        tmp_path / "t.jsonl",
        ["a", "b", "c"],
        [refusal(), file_block("never sent"), file_block("never sent")],
    )
    kinds = [r.kind for r in read_trace(source)]

    assert kinds == [KIND_INIT, KIND_REFUSAL]


def test_refusal_in_one_seed_does_not_stop_the_others(
    snapshot_dir, tmp_path, file_block, record_live
):
    source = record_live(
        snapshot_dir,
        tmp_path / "t.jsonl",
        ["a"],
        [refusal(), file_block("v = 2")],
        seeds=(0, 1),
    )
    outcomes = [(r.seed, r.kind) for r in read_trace(source)]

    assert outcomes == [(0, KIND_INIT), (0, KIND_REFUSAL), (1, KIND_INIT), (1, KIND_TURN)]


def test_run_summary_counts_refusals_separately_from_errors(
    snapshot_dir, tmp_path, file_block
):
    config = RunConfig(
        prompts=("a",),
        trace_path=tmp_path / "t.jsonl",
        trace_id="counts",
        snapshot_dir=snapshot_dir,
        seeds=(0, 1, 2),
    )
    client = RecordingFakeClient(
        [refusal(), CompletionError("network down"), file_block("v = 2")]
    )
    driver = RefinementDriver(config, client, clock=client.clock)

    assert driver.run() == 1
    assert driver.refusals == 1
    assert driver.errors == 1


# --- Replay reproduces refusals exactly -----------------------------------


def test_trace_with_a_refusal_replays_byte_identically(
    snapshot_dir, tmp_path, file_block, record_live, replay_into
):
    source = record_live(
        snapshot_dir,
        tmp_path / "source.jsonl",
        ["readability", "feature", "optimize"],
        [file_block("v = 2"), file_block("v = 3"), refusal()],
    )
    replayed = tmp_path / "replayed.jsonl"

    replay_into(source, replayed)

    assert replayed.read_bytes() == source.read_bytes()


def test_trace_of_nothing_but_refusals_still_replays(
    snapshot_dir, tmp_path, record_live, replay_into
):
    """Regression: replay used to look for request params on successful turns
    only, so a trace where the model declined turn 1 on every seed could not be
    replayed at all."""
    source = record_live(
        snapshot_dir,
        tmp_path / "source.jsonl",
        ["optimize"],
        [refusal(), refusal()],
        seeds=(0, 1),
    )
    replayed = tmp_path / "replayed.jsonl"

    replay_into(source, replayed)

    assert replayed.read_bytes() == source.read_bytes()


def test_replay_turns_exposes_the_refusal(snapshot_dir, tmp_path, file_block, record_live):
    source = record_live(
        snapshot_dir, tmp_path / "t.jsonl", ["a", "b"], [file_block("v = 2"), refusal()]
    )
    turns = list(replay_turns(source))

    assert [t.refused for t in turns] == [False, True]
    assert [t.failed for t in turns] == [False, False]
    assert turns[-1].refusal_category == "cyber"


def test_replay_verifies_the_hash_of_a_refused_request(
    snapshot_dir, tmp_path, file_block, record_live, replay_into
):
    """Reaching a recorded refusal through a different request is divergence."""
    source = record_live(
        snapshot_dir, tmp_path / "source.jsonl", ["a"], [refusal()]
    )
    tampered = tmp_path / "tampered.jsonl"
    with TraceWriter(tampered) as writer:
        for record in load_records(source):
            if record.kind == KIND_REFUSAL:
                record = replace(record, prompt_hash="deadbeef" * 8)
            writer.write(record)

    with pytest.raises(ReplayError, match="has diverged from the live run"):
        replay_into(tampered, tmp_path / "out.jsonl")


def test_error_records_are_still_errors_not_refusals(
    snapshot_dir, tmp_path, file_block, record_live
):
    source = record_live(
        snapshot_dir, tmp_path / "t.jsonl", ["a"], [CompletionError("network down")]
    )
    last = list(read_trace(source))[-1]

    assert last.kind == KIND_ERROR
    assert last.refusal_category is None


# --- The cache never stores a refusal -------------------------------------


def test_refusals_are_not_cached(tmp_path, file_block):
    """Caching one would lock a possibly-false-positive refusal into every
    future live run of that request."""
    with ResponseCache(tmp_path / "cache.sqlite") as store:
        inner = RecordingFakeClient([refusal(), file_block("v = 2")])
        client = CachingClient(inner, store)

        with pytest.raises(RefusalError):
            client.complete("sys", "user", replication=0)
        assert store.stats().entries == 0

        # The identical request goes back to the provider and can succeed.
        assert "v = 2" in client.complete("sys", "user", replication=0).text
        assert inner.calls == 2
