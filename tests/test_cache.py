"""Tests for the response cache (BUILD_PLAN step 1.4)."""

import sqlite3

import pytest

from graphgate.config import ModelConfig, RunConfig
from graphgate.harness.driver import RefinementDriver
from graphgate.harness.trace import KIND_TURN, read_trace
from graphgate.llm.base import Completion
from graphgate.llm.cache import (
    CACHE_SCHEMA_VERSION,
    CacheError,
    CachingClient,
    ResponseCache,
)

from conftest import RecordingFakeClient

SYSTEM = "you are a code assistant"
USER = "rewrite app.py"


@pytest.fixture
def cache(tmp_path):
    with ResponseCache(tmp_path / "cache.sqlite") as store:
        yield store


# --- Store behaviour -----------------------------------------------------


def test_miss_returns_none_and_counts(cache):
    assert cache.get("nosuchkey") is None
    assert cache.stats().misses == 1
    assert cache.stats().hits == 0


def test_put_then_get_round_trips(cache, file_block):
    inner = RecordingFakeClient([file_block("v = 2")])
    completion = inner.complete(SYSTEM, USER)
    key = inner.cache_key(SYSTEM, USER)

    cache.put(key, completion, SYSTEM, USER, inner.describe_params())
    hit = cache.get(key)

    assert hit is not None
    assert hit.text == completion.text
    assert hit.model == completion.model
    assert hit.prompt_hash == key


def test_hit_reports_original_latency_and_usage(cache, file_block):
    """A hit must not report zero cost — the overhead metrics answer 'what would
    this cost in a real deployment', where you pay full latency and tokens."""
    inner = RecordingFakeClient([file_block("v = 2")])
    completion = inner.complete(SYSTEM, USER)
    key = inner.cache_key(SYSTEM, USER)
    cache.put(key, completion, SYSTEM, USER, inner.describe_params())

    hit = cache.get(key)

    assert hit.latency_ms == 1.5
    assert hit.usage == {"input_tokens": 5, "output_tokens": 7}
    # ...but it is flagged, so actual spend can be computed separately.
    assert hit.cached is True
    assert completion.cached is False


def test_cache_persists_across_reopen(tmp_path, file_block):
    path = tmp_path / "cache.sqlite"
    inner = RecordingFakeClient([file_block("v = 2")])
    completion = inner.complete(SYSTEM, USER)
    key = inner.cache_key(SYSTEM, USER)

    with ResponseCache(path) as store:
        store.put(key, completion, SYSTEM, USER, inner.describe_params())
    with ResponseCache(path) as store:
        assert store.get(key) is not None


def test_stats_report_hit_rate_and_entry_count(cache, file_block):
    inner = RecordingFakeClient([file_block("v = 2")])
    key = inner.cache_key(SYSTEM, USER)
    cache.put(key, inner.complete(SYSTEM, USER), SYSTEM, USER, inner.describe_params())

    cache.get(key)
    cache.get(key)
    cache.get("missing")

    stats = cache.stats()
    assert (stats.hits, stats.misses, stats.entries) == (2, 1, 1)
    assert stats.hit_rate == pytest.approx(2 / 3)


def test_hit_rate_is_zero_before_any_lookup(cache):
    assert cache.stats().hit_rate == 0.0


def test_rejects_a_foreign_schema_version(tmp_path):
    path = tmp_path / "cache.sqlite"
    with ResponseCache(path):
        pass
    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE meta SET value = ? WHERE key = 'schema_version'",
        (str(CACHE_SCHEMA_VERSION + 1),),
    )
    conn.commit()
    conn.close()

    with pytest.raises(CacheError, match="schema version"):
        ResponseCache(path)


# --- Key sensitivity -----------------------------------------------------


def test_different_prompt_is_a_different_key(cache, file_block):
    inner = RecordingFakeClient([file_block("v = 2")])
    key = inner.cache_key(SYSTEM, USER)
    cache.put(key, inner.complete(SYSTEM, USER), SYSTEM, USER, inner.describe_params())

    assert cache.get(inner.cache_key(SYSTEM, "a different instruction")) is None


def test_different_params_is_a_different_key(file_block):
    """Changing effort changes the request, so it must not reuse the old answer."""
    a = RecordingFakeClient([file_block("v = 2")])
    b = RecordingFakeClient(
        [file_block("v = 2")],
        params={**RecordingFakeClient.PARAMS, "output_config": {"effort": "high"}},
    )
    assert a.cache_key(SYSTEM, USER) != b.cache_key(SYSTEM, USER)


def test_different_model_is_a_different_key(file_block):
    """The §9 small-model ablation must not read the primary model's cache."""
    a = RecordingFakeClient([file_block("v = 2")])
    b = RecordingFakeClient([file_block("v = 2")], model="claude-haiku-4-5")
    assert a.cache_key(SYSTEM, USER) != b.cache_key(SYSTEM, USER)


# --- CachingClient -------------------------------------------------------


def test_second_identical_request_does_not_reach_the_provider(cache, file_block):
    inner = RecordingFakeClient([file_block("v = 2")])
    client = CachingClient(inner, cache)

    first = client.complete(SYSTEM, USER)
    second = client.complete(SYSTEM, USER)

    assert inner.calls == 1
    assert first.text == second.text
    assert first.cached is False
    assert second.cached is True


def test_distinct_requests_each_reach_the_provider(cache, file_block):
    inner = RecordingFakeClient([file_block("v = 2"), file_block("v = 3")])
    client = CachingClient(inner, cache)

    client.complete(SYSTEM, USER)
    client.complete(SYSTEM, "something else")

    assert inner.calls == 2


def test_read_only_refuses_to_spend_on_a_miss(cache, file_block):
    inner = RecordingFakeClient([file_block("v = 2")])
    client = CachingClient(inner, cache, read_only=True)

    with pytest.raises(CacheError, match="refusing to make a billable call"):
        client.complete(SYSTEM, USER)
    assert inner.calls == 0


def test_read_only_still_serves_hits(cache, file_block):
    inner = RecordingFakeClient([file_block("v = 2")])
    CachingClient(inner, cache).complete(SYSTEM, USER)

    frozen = CachingClient(RecordingFakeClient([]), cache, read_only=True)
    assert frozen.complete(SYSTEM, USER).cached is True


def test_key_disagreement_is_fatal(cache):
    """A client that hashes its request differently from cache_key() would
    poison the store: entries written under one key, looked up under another.

    The real client derives both from one method so this cannot happen — the
    guard exists to catch a future refactor that separates them again.
    """

    class Inconsistent:
        def describe_params(self):
            return {}

        def cache_key(self, system, user):
            return "key-the-cache-will-look-under"

        def complete(self, system, user):
            return Completion(
                text="x",
                model="m",
                stop_reason="end_turn",
                prompt_hash="key-the-client-actually-used",
                latency_ms=1.0,
                usage={},
            )

    with pytest.raises(CacheError, match="must agree"):
        CachingClient(Inconsistent(), cache).complete(SYSTEM, USER)


def test_caching_client_passes_params_through(cache, file_block):
    inner = RecordingFakeClient([file_block("v = 2")])
    assert CachingClient(inner, cache).describe_params() == inner.describe_params()


# --- End to end through the driver ---------------------------------------


def test_rerunning_a_whole_trace_makes_no_provider_calls(
    snapshot_dir, tmp_path, file_block
):
    """The point of the cache: a repeated run costs nothing."""
    prompts = ["readability", "optimize"]
    responses = [file_block("v = 2"), file_block("v = 3")]

    def run(out, responses):
        config = RunConfig(
            prompts=tuple(prompts),
            trace_path=out,
            trace_id="cached-run",
            snapshot_dir=snapshot_dir,
            model=ModelConfig(),
            seeds=(0,),
        )
        inner = RecordingFakeClient(responses)
        with ResponseCache(tmp_path / "cache.sqlite") as store:
            RefinementDriver(
                config, CachingClient(inner, store), clock=inner.clock
            ).run()
        return inner

    first = run(tmp_path / "first.jsonl", responses)
    # An empty response list means any provider call raises — proving none happen.
    second = run(tmp_path / "second.jsonl", [])

    assert first.calls == 2
    assert second.calls == 0


def test_cached_flag_is_recorded_on_every_turn(snapshot_dir, tmp_path, file_block):
    config_kwargs = dict(
        prompts=("readability",),
        trace_id="cached-run",
        snapshot_dir=snapshot_dir,
        model=ModelConfig(),
        seeds=(0,),
    )
    with ResponseCache(tmp_path / "cache.sqlite") as store:
        inner = RecordingFakeClient([file_block("v = 2")])
        RefinementDriver(
            RunConfig(trace_path=tmp_path / "a.jsonl", **config_kwargs),
            CachingClient(inner, store),
            clock=inner.clock,
        ).run()

        inner2 = RecordingFakeClient([])
        RefinementDriver(
            RunConfig(trace_path=tmp_path / "b.jsonl", **config_kwargs),
            CachingClient(inner2, store),
            clock=inner2.clock,
        ).run()

    live = [r for r in read_trace(tmp_path / "a.jsonl") if r.kind == KIND_TURN]
    cached = [r for r in read_trace(tmp_path / "b.jsonl") if r.kind == KIND_TURN]

    assert [r.cached for r in live] == [False]
    assert [r.cached for r in cached] == [True]
    # Same measured cost either way — only the flag distinguishes them.
    assert live[0].latency_ms == cached[0].latency_ms
    assert live[0].usage == cached[0].usage
