"""End-to-end driver tests against a fake client — no network, no API key."""

from pathlib import Path

import pytest

from graphgate.config import ModelConfig, RunConfig
from graphgate.harness.driver import RefinementDriver
from graphgate.harness.trace import KIND_ERROR, KIND_INIT, KIND_TURN, read_trace
from graphgate.llm.base import Completion, CompletionError


class FakeClient:
    """Replays canned responses, one per call, and records prompts it saw."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0
        self.prompts_seen: list[str] = []

    def describe_params(self):
        return {"model": "fake-model", "effort": "medium"}

    def complete(self, system: str, user: str) -> Completion:
        self.prompts_seen.append(user)
        if self.calls >= len(self._responses):
            raise AssertionError("driver requested more turns than expected")
        item = self._responses[self.calls]
        self.calls += 1
        if isinstance(item, Exception):
            raise item
        return Completion(
            text=item,
            model="fake-model",
            stop_reason="end_turn",
            prompt_hash=f"hash{self.calls}",
            latency_ms=1.0,
            usage={"input_tokens": 5, "output_tokens": 7},
        )


@pytest.fixture
def snapshot_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "snap"
    directory.mkdir()
    (directory / "app.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    return directory


def make_config(snapshot_dir: Path, tmp_path: Path, prompts, seeds=(0,)) -> RunConfig:
    return RunConfig(
        snapshot_dir=snapshot_dir,
        prompts=tuple(prompts),
        trace_path=tmp_path / "trace.jsonl",
        trace_id="test-trace",
        seeds=tuple(seeds),
        model=ModelConfig(),
    )


def block(body: str, path: str = "app.py") -> str:
    return f"### FILE: {path}\n```python\n{body}\n```\n"


def test_records_init_then_one_record_per_turn(snapshot_dir, tmp_path):
    config = make_config(snapshot_dir, tmp_path, ["readability", "optimize"])
    client = FakeClient([block("def run():\n    return 2"), block("def run():\n    return 3")])

    turns = RefinementDriver(config, client).run()

    assert turns == 2
    records = list(read_trace(config.trace_path))
    assert [r.kind for r in records] == [KIND_INIT, KIND_TURN, KIND_TURN]
    assert [r.turn for r in records] == [0, 1, 2]


def test_snapshot_evolves_across_turns(snapshot_dir, tmp_path):
    config = make_config(snapshot_dir, tmp_path, ["a", "b"])
    client = FakeClient([block("v = 2"), block("v = 3")])

    RefinementDriver(config, client).run()
    records = list(read_trace(config.trace_path))

    assert records[0].files_after["app.py"] == "def run():\n    return 1\n"
    assert records[1].files_after["app.py"] == "v = 2"
    assert records[2].files_after["app.py"] == "v = 3"
    # Turn 2's prompt must carry turn 1's output, not the original file.
    assert "v = 2" in client.prompts_seen[1]


def test_turn_record_captures_diff_and_metrics(snapshot_dir, tmp_path):
    config = make_config(snapshot_dir, tmp_path, ["readability"])
    client = FakeClient([block("def run():\n    return 2")])

    RefinementDriver(config, client).run()
    turn = list(read_trace(config.trace_path))[1]

    assert "-    return 1" in turn.diff
    assert "+    return 2" in turn.diff
    assert turn.changed_paths == ["app.py"]
    assert turn.prompt == "readability"
    assert turn.prompt_hash == "hash1"
    assert turn.usage == {"input_tokens": 5, "output_tokens": 7}
    assert turn.latency_ms == 1.0
    assert turn.params == {"model": "fake-model", "effort": "medium"}


def test_each_seed_restarts_from_the_initial_snapshot(snapshot_dir, tmp_path):
    config = make_config(snapshot_dir, tmp_path, ["a"], seeds=(0, 1))
    client = FakeClient([block("v = 2"), block("v = 9")])

    RefinementDriver(config, client).run()
    records = list(read_trace(config.trace_path))

    assert [(r.seed, r.turn) for r in records] == [(0, 0), (0, 1), (1, 0), (1, 1)]
    # Both replications start from the same code, not from seed 0's result.
    assert records[0].files_after == records[2].files_after


def test_new_files_are_added_to_the_snapshot(snapshot_dir, tmp_path):
    config = make_config(snapshot_dir, tmp_path, ["split it up"])
    client = FakeClient([block("def helper():\n    return 0", path="helpers.py")])

    RefinementDriver(config, client).run()
    turn = list(read_trace(config.trace_path))[1]

    assert set(turn.files_after) == {"app.py", "helpers.py"}
    assert turn.changed_paths == ["helpers.py"]


def test_unparseable_response_is_recorded_and_stops_that_replication(
    snapshot_dir, tmp_path
):
    """A bad turn must not advance silently — later turns would log as no-ops
    and understate the degradation curve."""
    config = make_config(snapshot_dir, tmp_path, ["a", "b"])
    client = FakeClient(["I have updated the file.", block("never reached")])

    turns = RefinementDriver(config, client).run()

    assert turns == 0
    records = list(read_trace(config.trace_path))
    assert [r.kind for r in records] == [KIND_INIT, KIND_ERROR]
    assert "no '### FILE:" in records[1].error
    assert client.calls == 1  # the second prompt was never sent


def test_api_failure_is_recorded_and_stops_that_replication(snapshot_dir, tmp_path):
    config = make_config(snapshot_dir, tmp_path, ["a", "b"])
    client = FakeClient([CompletionError("model declined the request")])

    RefinementDriver(config, client).run()
    records = list(read_trace(config.trace_path))

    assert records[-1].kind == KIND_ERROR
    assert "declined" in records[-1].error


def test_one_seed_failing_does_not_abort_the_others(snapshot_dir, tmp_path):
    config = make_config(snapshot_dir, tmp_path, ["a"], seeds=(0, 1))
    client = FakeClient([CompletionError("transient"), block("v = 2")])

    turns = RefinementDriver(config, client).run()

    assert turns == 1
    records = list(read_trace(config.trace_path))
    assert [(r.seed, r.kind) for r in records] == [
        (0, KIND_INIT),
        (0, KIND_ERROR),
        (1, KIND_INIT),
        (1, KIND_TURN),
    ]


def test_no_op_turn_is_still_recorded(snapshot_dir, tmp_path):
    """A refinement that changes nothing is a real outcome worth measuring."""
    config = make_config(snapshot_dir, tmp_path, ["a"])
    client = FakeClient([block("def run():\n    return 1\n")])

    RefinementDriver(config, client).run()
    turn = list(read_trace(config.trace_path))[1]

    assert turn.kind == KIND_TURN
    assert turn.diff == ""
    assert turn.changed_paths == []
