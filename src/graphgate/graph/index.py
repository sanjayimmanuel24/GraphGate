"""The stored graph, re-parsing only the files that changed (BUILD_PLAN 4.4).

Parsing is the expensive part of building a graph, and a refinement turn
touches a few files. The index keeps each file's facts in SQLite under the
hash of its text and parses a file again only when that hash changes. Linking
is redone over all facts every time: it is cheap, and a change in one file can
change how a call in another file resolves, so nothing is patched in place.
That makes the result equal to a graph built from scratch, which the tests
check.

The linked graph is stored too, so the next iteration, or another process,
can read the graph before the change without building it.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

import networkx as nx

from graphgate.graph.catalog import DEFAULT, Catalog
from graphgate.graph.extract import FACTS_VERSION, extract
from graphgate.graph.link import GraphConfig, link
from graphgate.graph.model import from_json, to_json

_SCHEMA = """
CREATE TABLE IF NOT EXISTS facts (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, facts TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


@dataclass(frozen=True)
class Update:
    parsed: tuple[str, ...]       # files read again because they are new or changed
    reused: int                   # files whose stored facts were kept
    removed: tuple[str, ...]      # files no longer in the revision


class GraphIndex:
    """A repository's graph, kept up to date one revision at a time."""

    def __init__(self, path: Path | str, *, catalog: Catalog = DEFAULT, config: GraphConfig = GraphConfig()):
        self.catalog, self.config = catalog, config
        self._db = sqlite3.connect(str(path))
        self._db.executescript(_SCHEMA)
        if self._meta("facts_version") != str(FACTS_VERSION):
            # Facts written by another version of the extractor cannot be mixed with new ones.
            self._db.execute("DELETE FROM facts")
            self._db.execute("DELETE FROM meta")
            self._set_meta("facts_version", str(FACTS_VERSION))
            self._db.commit()
        self._graph: nx.MultiDiGraph | None = None

    def __enter__(self) -> GraphIndex:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._db.close()

    def _meta(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def _set_meta(self, key: str, value: str) -> None:
        self._db.execute("INSERT INTO meta VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                         (key, value))

    def update(self, files: Mapping[str, str], *, exclude: Iterable[str] = ()) -> Update:
        """Bring the index to a revision, given as all its files (path to text)."""
        stored = dict(self._db.execute("SELECT path, sha256 FROM facts"))
        parsed = []
        for path in sorted(files):
            digest = hashlib.sha256(files[path].encode("utf-8")).hexdigest()
            if stored.get(path) != digest:
                self._db.execute(
                    "INSERT INTO facts VALUES (?, ?, ?) ON CONFLICT(path) DO UPDATE SET "
                    "sha256 = excluded.sha256, facts = excluded.facts",
                    (path, digest, json.dumps(extract(path, files[path]))))
                parsed.append(path)
        removed = sorted(set(stored) - set(files))
        self._db.executemany("DELETE FROM facts WHERE path = ?", [(path,) for path in removed])
        return self._relink(Update(tuple(parsed), len(files) - len(parsed), tuple(removed)), exclude)

    def apply(self, changed: Mapping[str, str | None], *, exclude: Iterable[str] = ()) -> Update:
        """Bring the index forward by a change: new text per changed file, None for a deleted one."""
        stored = dict(self._db.execute("SELECT path, sha256 FROM facts"))
        files = {path: text for path, text in changed.items() if text is not None}
        untouched = len(set(stored) - set(changed))
        parsed, removed = [], []
        for path in sorted(changed):
            text = changed[path]
            if text is None:
                self._db.execute("DELETE FROM facts WHERE path = ?", (path,))
                removed += [path] if path in stored else []
                continue
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if stored.get(path) == digest:
                untouched += 1
                continue
            self._db.execute(
                "INSERT INTO facts VALUES (?, ?, ?) ON CONFLICT(path) DO UPDATE SET "
                "sha256 = excluded.sha256, facts = excluded.facts",
                (path, digest, json.dumps(extract(path, files[path]))))
            parsed.append(path)
        return self._relink(Update(tuple(parsed), untouched, tuple(removed)), exclude)

    def _relink(self, update: Update, exclude: Iterable[str]) -> Update:
        facts = {path: json.loads(text) for path, text in self._db.execute("SELECT path, facts FROM facts")}
        self._graph = link(facts, catalog=self.catalog, config=self.config, exclude=exclude)
        self._set_meta("graph", json.dumps(to_json(self._graph), sort_keys=True))
        self._db.commit()
        return update

    def graph(self) -> nx.MultiDiGraph:
        """The graph of the revision the index was last brought to."""
        if self._graph is None:
            stored = self._meta("graph")
            graph = from_json(json.loads(stored)) if stored else None
            # A graph linked under other settings is not this index's graph: link again from the facts.
            if graph is None or graph.graph.get("config") != json.loads(json.dumps(self.config.to_dict())):
                excluded = graph.graph.get("excluded", ()) if graph is not None else ()
                self._relink(Update((), 0, ()), excluded)
            else:
                self._graph = graph
        return self._graph
