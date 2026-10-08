"""Shared test fixtures.

Lives here so test modules never import from each other — pytest discovers
conftest automatically, which keeps the helpers available without depending on
how the test package happens to be on sys.path.
"""

from __future__ import annotations

from collections import deque
from pathlib import Path

import pytest

from graphgate.config import RunConfig
from graphgate.gate.analysers import ChangeScan
from graphgate.gate.findings import ChangeFindings, Finding
from graphgate.harness.driver import RefinementDriver
from graphgate.harness.replay import ReplayClient
from graphgate.harness.trace import KIND_TURN, SCHEMA_VERSION, TraceRecord
from graphgate.llm.base import Completion, RefusalError, prompt_hash


class RecordingFakeClient:
    """Stands in for the live client, but computes *real* prompt hashes.

    Using a real hash matters: replay verifies the request it rebuilds against
    the recorded hash, so a stub value would leave that check untested.
    """

    MODEL = "fake-model"
    PARAMS = {
        "max_tokens": 100,
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": "medium"},
    }

    def __init__(
        self,
        responses,
        params: dict | None = None,
        model: str | None = None,
        resolved_model: str | None = None,
    ):
        self._responses = deque(responses)
        self._tick = 0
        self.calls = 0
        self.prompts_seen: list[str] = []
        self.replications_seen: list[int] = []
        # Overridable so tests can vary the request and check the key changes.
        self.params = dict(self.PARAMS if params is None else params)
        self.model = self.MODEL if model is None else model
        # What the API reports back; defaults to the requested ID (Opus IDs are
        # dateless). Set a dated snapshot to mimic Haiku 4.5.
        self.resolved_model = self.model if resolved_model is None else resolved_model

    def describe_params(self) -> dict:
        return dict(self.params)

    def request_hash(self, system: str, user: str) -> str:
        return prompt_hash(system, user, self.model, self.params)

    def clock(self) -> str:
        """Deterministic timestamps, so a live run is comparable to its replay."""
        self._tick += 1
        return f"2026-07-28T12:00:{self._tick:02d}+00:00"

    def complete(self, system: str, user: str, *, replication: int) -> Completion:
        self.prompts_seen.append(user)
        self.replications_seen.append(replication)
        if not self._responses:
            raise AssertionError("driver requested more turns than expected")
        item = self._responses.popleft()
        self.calls += 1
        if isinstance(item, RefusalError):
            # A test can't know the request hash in advance — it depends on the
            # rendered prompt — so fill in the real one, as the live client
            # would. Replay verifies it, so a placeholder would fail there.
            raise RefusalError(
                prompt_hash=self.request_hash(system, user),
                model=self.model,
                resolved_model=self.resolved_model,
                category=item.category,
                explanation=item.explanation,
                partial_text=item.partial_text,
                usage=item.usage,
                latency_ms=item.latency_ms,
            )
        if isinstance(item, Exception):
            raise item
        stop_reason = "end_turn"
        if isinstance(item, tuple):  # (text, stop_reason), for a reply that was cut off
            item, stop_reason = item
        return Completion(
            text=item,
            model=self.model,
            resolved_model=self.resolved_model,
            stop_reason=stop_reason,
            prompt_hash=self.request_hash(system, user),
            latency_ms=1.5,
            usage={"input_tokens": 5, "output_tokens": 7},
        )


class StubScanner:
    """Stands in for the Semgrep and Bandit wrapper in gate tests.

    Reports one shell finding for every line that calls os.system, and counts
    how often a change was scanned.
    """

    config = "stub-scanner"      # the real scanner's is its versions and rule set

    def __init__(self, errors=()):
        self.calls = 0
        self.errors = tuple(errors)

    def scan(self, versions):
        """Warming the scanner up front needs nothing here."""
        list(versions)

    def scan_change(self, before, after, changed_paths):
        self.calls += 1

        def findings(files):
            return tuple(
                Finding(tool="bandit", rule_id="B605", cwes=(78,), severity="high", confidence="high",
                        path=path, start_line=number, end_line=number,
                        message="Starting a process with a shell.", code=line)
                for path in sorted(changed_paths) for number, line in enumerate(files.get(path, "").splitlines(), 1)
                if "os.system(" in line)

        return ChangeScan(ChangeFindings(before=findings(before), after=findings(after)), self.errors)


def _file_block(body: str, path: str = "app.py") -> str:
    """A model reply in the file-block format the protocol expects."""
    return f"### FILE: {path}\n```python\n{body}\n```\n"


def _make_trace_record(**overrides) -> TraceRecord:
    """A fully-populated turn record, with fields overridable per test."""
    fields = dict(
        schema_version=SCHEMA_VERSION,
        trace_id="t1",
        seed=0,
        turn=1,
        kind=KIND_TURN,
        timestamp="2026-07-28T00:00:00+00:00",
        files_after={"a.py": "a = 1"},
        diff="--- a/a.py",
        changed_paths=["a.py"],
        prompt="improve readability",
        prompt_hash="abc123",
        model="claude-opus-5",
        params={"effort": "medium"},
        response_text="### FILE: a.py",
        usage={"input_tokens": 10, "output_tokens": 20},
        latency_ms=123.4,
    )
    fields.update(overrides)
    return TraceRecord(**fields)


@pytest.fixture
def make_trace_record():
    return _make_trace_record


@pytest.fixture
def file_block():
    return _file_block


@pytest.fixture
def fake_client():
    """Factory for a client that replays canned responses."""
    return RecordingFakeClient


@pytest.fixture
def snapshot_dir(tmp_path: Path) -> Path:
    """A one-file starting snapshot."""
    directory = tmp_path / "snap"
    directory.mkdir()
    (directory / "app.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    return directory


@pytest.fixture
def record_live():
    """Produce a source trace with the fake client, as a live run would."""

    def _record(
        snapshot_dir, out, prompts, responses, seeds=(0,), trace_id="src-trace", **client_kwargs
    ):
        config = RunConfig(
            prompts=tuple(prompts),
            trace_path=out,
            trace_id=trace_id,
            snapshot_dir=snapshot_dir,
            seeds=tuple(seeds),
        )
        client = RecordingFakeClient(responses, **client_kwargs)
        RefinementDriver(config, client, clock=client.clock).run()
        return out

    return _record


@pytest.fixture
def replay_into():
    """Replay a saved trace into a new file through the unmodified driver."""

    def _replay(source: Path, out: Path, verify_hash: bool = True) -> int:
        client = ReplayClient.from_trace(source, verify_hash=verify_hash)
        config = RunConfig(
            prompts=client.prompts,
            trace_path=out,
            trace_id=client.trace_id,
            seeds=client.seeds,
        )
        driver = RefinementDriver(
            config,
            client,
            clock=client.clock,
            initial=client.initial_snapshot,
            injection=client.injection,
            schema_version=client.schema_version,
        )
        return driver.run()

    return _replay
