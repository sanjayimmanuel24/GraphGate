"""Persistent response cache (BUILD_PLAN step 1.4).

The key is ``(prompt_hash, replication)``.

``prompt_hash`` already hashes the model and params along with the system and
user text (see :func:`graphgate.llm.base.prompt_hash`), so the
``(prompt_hash, model, params)`` key written in proposal §9 reduces to the hash
alone. Model and params are still stored as columns, for inspecting the cache
and evicting a model's entries.

``replication`` is the seed, and leaving it out was a bug. The API accepts no
seed, so every seed of a trace sends byte-identical requests; keyed on the hash
alone, seed 0's live answer was served to every later seed, and N "independent
replications" collapsed into one trajectory copied N times. The §7.2 confidence
intervals and paired Wilcoxon tests would then have run over duplicates — zero
variance, silently. With the seed in the key, each replication is its own live
sample, and rerunning the *same* seed still hits the cache, which is what keeps
reruns reproducible.

SQLite because it is already in the stack for graph persistence, is stdlib, and
gives a single shareable file for the artifact release (proposal §9).

On what a cache hit reports
---------------------------
A hit returns the **originally measured** ``latency_ms`` and ``usage``, not
zeroes. Those fields exist to answer "what would this gate cost in a real CI
deployment" (proposal §7.2), and in a real deployment you pay full latency and
full tokens. Reporting zeroes would silently make every cached rerun look free
and drive the median-latency figure toward zero.

The trade-off is that summing ``usage`` across a cached run overstates what that
particular run actually spent. Both readings are legitimate and they answer
different questions, so every turn records a ``cached`` flag and the analysis
picks: include cached turns for deployment cost, exclude them for actual spend.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Deliberately does not import from graphgate.harness: llm/ is the lower layer,
# and depending upward would make the package __init__s import circularly.
from graphgate.llm.base import CacheableClient, Completion

log = logging.getLogger(__name__)

# v2 added `replication` to the key (see module docstring).
# v3 added `resolved_model`, so a cache hit records the same snapshot a live call would.
CACHE_SCHEMA_VERSION = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS responses (
    prompt_hash   TEXT NOT NULL,
    replication   INTEGER NOT NULL,
    model         TEXT NOT NULL,
    params_json   TEXT NOT NULL,
    response_text TEXT NOT NULL,
    stop_reason   TEXT,
    usage_json    TEXT NOT NULL,
    latency_ms    REAL,
    created_at    TEXT NOT NULL,
    system_prompt TEXT NOT NULL,
    user_prompt   TEXT NOT NULL,
    resolved_model TEXT,
    PRIMARY KEY (prompt_hash, replication)
);
CREATE INDEX IF NOT EXISTS responses_model ON responses (model);
"""


class CacheError(RuntimeError):
    """The cache cannot be used as asked."""


@dataclass(frozen=True)
class CacheStats:
    """Per-run counters plus the total entry count on disk."""

    hits: int
    misses: int
    entries: int

    @property
    def hit_rate(self) -> float:
        looked_up = self.hits + self.misses
        return self.hits / looked_up if looked_up else 0.0


class ResponseCache:
    """SQLite-backed store of LLM responses, keyed by request hash."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._check_version()
        self.hits = 0
        self.misses = 0

    def _check_version(self) -> None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(CACHE_SCHEMA_VERSION),),
            )
            self._conn.commit()
            return
        found = int(row["value"])
        if found != CACHE_SCHEMA_VERSION:
            raise CacheError(
                f"{self.path}: cache schema version {found} is not supported "
                f"(this build uses v{CACHE_SCHEMA_VERSION}). Point --cache at a "
                "new file rather than mixing schema versions."
            )

    def __enter__(self) -> ResponseCache:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def get(self, key: str, replication: int) -> Completion | None:
        row = self._conn.execute(
            "SELECT * FROM responses WHERE prompt_hash = ? AND replication = ?",
            (key, replication),
        ).fetchone()
        if row is None:
            self.misses += 1
            return None
        self.hits += 1
        return Completion(
            text=row["response_text"],
            model=row["model"],
            resolved_model=row["resolved_model"],
            stop_reason=row["stop_reason"],
            prompt_hash=key,
            latency_ms=row["latency_ms"],
            usage=json.loads(row["usage_json"]),
            cached=True,
        )

    def put(
        self,
        key: str,
        replication: int,
        completion: Completion,
        system: str,
        user: str,
        params: dict[str, Any],
    ) -> None:
        # The prompts are stored for provenance: when a replay's hash check
        # fails, having the exact recorded request is what makes the divergence
        # diagnosable instead of guesswork.
        self._conn.execute(
            """
            INSERT OR REPLACE INTO responses (
                prompt_hash, replication, model, params_json, response_text,
                stop_reason, usage_json, latency_ms, created_at, system_prompt,
                user_prompt, resolved_model
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                replication,
                completion.model,
                json.dumps(params, sort_keys=True, ensure_ascii=False),
                completion.text,
                completion.stop_reason,
                json.dumps(completion.usage, sort_keys=True),
                completion.latency_ms,
                datetime.now(timezone.utc).isoformat(),
                system,
                user,
                completion.resolved_model,
            ),
        )
        self._conn.commit()

    def stats(self) -> CacheStats:
        count = self._conn.execute("SELECT COUNT(*) AS n FROM responses").fetchone()["n"]
        return CacheStats(hits=self.hits, misses=self.misses, entries=count)


class CachingClient:
    """Wraps a client so identical requests are only paid for once.

    Satisfies :class:`~graphgate.llm.base.CodeGenClient`, so the driver is
    unchanged — this sits transparently between it and the provider.
    """

    def __init__(
        self,
        inner: CacheableClient,
        cache: ResponseCache,
        read_only: bool = False,
    ):
        self.inner = inner
        self.cache = cache
        # read_only enforces the pre-set API budget ceiling (proposal §9): a
        # miss fails loudly rather than quietly spending money on a rerun that
        # was expected to be fully cached.
        self.read_only = read_only

    def describe_params(self) -> dict[str, Any]:
        return self.inner.describe_params()

    def request_hash(self, system: str, user: str) -> str:
        return self.inner.request_hash(system, user)

    def complete(self, system: str, user: str, *, replication: int) -> Completion:
        key = self.inner.request_hash(system, user)

        hit = self.cache.get(key, replication)
        if hit is not None:
            log.debug("cache hit %s (replication %d)", key[:12], replication)
            return hit

        if self.read_only:
            raise CacheError(
                f"cache miss for {key[:12]} (replication {replication}) and the "
                "cache is read-only; refusing to make a billable call. Drop "
                "--cache-only to allow live calls."
            )

        # A refusal (RefusalError) propagates from here without being stored.
        # Deliberate: caching one would lock a possibly-false-positive refusal
        # into every future live run of that request. Reproducing a recorded
        # refusal is replay's job, and replay does reproduce it exactly.
        completion = self.inner.complete(system, user, replication=replication)
        if completion.prompt_hash != key:
            # Would poison the cache: a later lookup computing the key this way
            # would never find the entry the client stored under its own.
            raise CacheError(
                f"client hashed its request to {completion.prompt_hash[:12]} but "
                f"request_hash() returned {key[:12]}; the two must agree"
            )
        self.cache.put(
            key, replication, completion, system, user, self.inner.describe_params()
        )
        return completion
