"""Tests for trace records and JSONL persistence."""

import pytest

from graphgate.harness.trace import TraceRecord, TraceWriter, read_trace
from graphgate.llm.base import prompt_hash


@pytest.fixture
def make_record(make_trace_record):
    """Alias for the shared record factory (see conftest.py)."""
    return make_trace_record


def test_record_round_trips_through_json(make_record):
    record = make_record()
    assert TraceRecord.from_json(record.to_json()) == record


def test_json_is_byte_stable_across_field_order(make_record):
    """M1.1's exit check is byte-identical trace files, so serialization must
    not depend on dict ordering."""
    a = make_record(usage={"input_tokens": 10, "output_tokens": 20})
    b = make_record(usage={"output_tokens": 20, "input_tokens": 10})
    assert a.to_json() == b.to_json()


def test_from_json_rejects_unknown_schema_version():
    line = '{"schema_version": 99, "trace_id": "t"}'
    with pytest.raises(ValueError, match="schema version"):
        TraceRecord.from_json(line)


def test_writer_appends_and_reader_streams(tmp_path, make_record):
    path = tmp_path / "trace.jsonl"
    with TraceWriter(path) as writer:
        writer.write(make_record(turn=1))
        writer.write(make_record(turn=2))

    records = list(read_trace(path))
    assert [r.turn for r in records] == [1, 2]


def test_writer_appends_to_an_existing_file(tmp_path, make_record):
    path = tmp_path / "trace.jsonl"
    with TraceWriter(path) as writer:
        writer.write(make_record(turn=1))
    with TraceWriter(path) as writer:
        writer.write(make_record(turn=2))

    assert len(list(read_trace(path))) == 2


def test_writer_creates_parent_directories(tmp_path, make_record):
    path = tmp_path / "runs" / "nested" / "trace.jsonl"
    with TraceWriter(path) as writer:
        writer.write(make_record())
    assert path.exists()


def test_writer_rejects_use_outside_context_manager(tmp_path, make_record):
    writer = TraceWriter(tmp_path / "trace.jsonl")
    with pytest.raises(RuntimeError, match="context manager"):
        writer.write(make_record())


def test_reader_reports_the_offending_line_number(tmp_path, make_record):
    path = tmp_path / "trace.jsonl"
    path.write_text(make_record().to_json() + "\nnot json\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r":2: malformed"):
        list(read_trace(path))


def test_prompt_hash_is_stable_and_input_sensitive():
    params = {"effort": "medium", "max_tokens": 100}
    base = prompt_hash("sys", "user", "claude-opus-5", params)

    # Same inputs, differently ordered dict -> same hash (cache must still hit).
    assert base == prompt_hash(
        "sys", "user", "claude-opus-5", {"max_tokens": 100, "effort": "medium"}
    )
    # Any change to a field that affects output -> different hash.
    assert base != prompt_hash("sys", "user2", "claude-opus-5", params)
    assert base != prompt_hash("sys", "user", "claude-haiku-4-5", params)
    assert base != prompt_hash("sys", "user", "claude-opus-5", {**params, "effort": "high"})
