"""Leakage control for the regression events (BUILD_PLAN 2.6, proposal §6.3).

Condition C builds its graph over an event's repository with the event's slice
laid over it. Anything else in that repository that gives the regression away
would hand the gate its answer through retrieval, and the comparison with the
diff-only gate would no longer be fair. Two kinds of give-away are looked for,
in the repository at the event's clean commit, outside the slice's own files:

- **Near-duplicates.** Every function or assignment the regression changes,
  adds or removes is compared, in its clean and its regressed version, with
  every function or assignment elsewhere in the repository. A unit at least
  ``THRESHOLD`` similar to either version is a near-duplicate: a twin that
  shows what the code looks like with, or without, its guard.
- **Tests the fix changed.** Test files outside the slice that differ between
  the event's regressed and clean commits. They were written to pin down the
  guard the regression removes, so they describe the answer.

Both become entries in the event's exclusion list, which the retrieval layer
must keep out of scope. Every entry carries its reason and its evidence, and
units too short to compare are listed, not skipped.

Source files the fix changed outside the slice are listed too, but stay in
scope. One of them can hold the very sanitizer the slice calls, and seeing
that definition from another file is the cross-file context the study is
about. A twin among them is caught by the near-duplicate rule.

Similarity is the share of tokens two units have in common, in order
(``difflib.SequenceMatcher.ratio`` over code tokens with comments, docstrings
and layout removed). Identifiers are compared as written, so a copy whose
names were all changed is not detected; that is a known limit of the check.
"""

from __future__ import annotations

import ast
import difflib
import io
import json
import os
import re
import subprocess
import textwrap
import tokenize
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from graphgate.dataset.events import BlobMissing
from graphgate.dataset.fix_pairs import classify_path
from graphgate.dataset.labels import _normalise, parse_unit
from graphgate.harness.injection import units
from graphgate.harness.snapshot import load_snapshot

SCHEMA_VERSION = 1

# Fixed before any gate result exists; do not tune against results.
THRESHOLD = 0.8      # similarity at or above which a unit is a near-duplicate
MIN_TOKENS = 30      # shorter units match by chance; they are listed as not compared
NEAREST_CANDIDATES = 5

NEAR_DUPLICATE = "near-duplicate"
FIX_TEST = "test-changed-by-fix"

_KINDS = ("def", "assign")
_LAYOUT = frozenset({tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
                     tokenize.DEDENT, tokenize.ENCODING, tokenize.ENDMARKER})


def code_tokens(text: str) -> tuple[str, ...]:
    """A unit's code as tokens, with comments, docstrings and layout removed."""
    tree = parse_unit(text)
    if tree is None:
        # Code Python 3 cannot parse: split on words and symbols instead.
        bare = re.sub(r"#[^\n]*", "", textwrap.dedent(text))
        return tuple(re.findall(r"[A-Za-z_]\w*|\d+(?:\.\d+)?|\S", bare))
    source = ast.unparse(tree)  # one layout and one quoting style for every unit
    return tuple(t.string for t in tokenize.generate_tokens(io.StringIO(source).readline)
                 if t.type not in _LAYOUT and t.string)


def similarity(a: tuple[str, ...], b: tuple[str, ...]) -> float:
    """Share of tokens in common, in order: 1.0 for identical code."""
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def _reaches(a: tuple[str, ...], b: tuple[str, ...], threshold: float) -> float | None:
    """The similarity if it is at least ``threshold``, else None.

    Two cheap upper bounds rule most pairs out before the exact comparison:
    the lengths alone, then the tokens ignoring their order.
    """
    if 2 * min(len(a), len(b)) < threshold * (len(a) + len(b)):
        return None
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if matcher.quick_ratio() < threshold:
        return None
    exact = matcher.ratio()
    return exact if exact >= threshold else None


def _trigrams(tokens: tuple[str, ...]) -> Counter:
    return Counter(zip(tokens, tokens[1:], tokens[2:]))


def _resemblance(a: Counter, b: Counter) -> float:
    union = sum((a | b).values())
    return sum((a & b).values()) / union if union else 0.0


@dataclass(frozen=True)
class CodeUnit:
    """A function, method or assignment somewhere in a repository."""

    path: str
    kind: str
    symbol: str
    tokens: tuple[str, ...]

    @property
    def name(self) -> str:
        return f"{self.path}::{self.symbol}"


def _symbol(key: tuple) -> str:
    return key[1] + (f"#{key[-1]}" if key[-1] else "")  # a repeated name gets its position


def code_units(path: str, text: str) -> list[CodeUnit]:
    return [CodeUnit(path, u.key[0], _symbol(u.key), code_tokens(u.text))
            for u in units(text) if u.key[0] in _KINDS]


@dataclass(frozen=True)
class RegressionUnit:
    """A unit the regression changes, adds or removes, in the versions it has."""

    path: str
    kind: str
    symbol: str
    versions: dict[str, tuple[str, ...]]  # "clean" and/or "regressed" -> tokens

    @property
    def name(self) -> str:
        return f"{self.path}::{self.symbol}"


def regression_units(clean: dict[str, str], regressed: dict[str, str]) -> list[RegressionUnit]:
    found = []
    for path in sorted(set(clean) | set(regressed)):
        if clean.get(path) == regressed.get(path):
            continue
        before = {u.key: u for u in units(clean.get(path, ""))}
        after = {u.key: u for u in units(regressed.get(path, ""))}
        for key in sorted(before.keys() | after.keys(), key=lambda k: (k[0], k[1], k[-1])):
            c, r = before.get(key), after.get(key)
            if key[0] not in _KINDS or (c and r and _normalise(c) == _normalise(r)):
                continue
            versions = {name: code_tokens(unit.text)
                        for name, unit in (("clean", c), ("regressed", r)) if unit}
            found.append(RegressionUnit(path, key[0], _symbol(key), versions))
    return found


# --- Reading a repository without touching the network -------------------------


def _git(repo_dir: Path, *args: str, stdin: bytes | None = None) -> bytes:
    # Lazy fetching is off: a blob the clone does not hold is an error to
    # report, never a download made behind the caller's back.
    done = subprocess.run(["git", "-C", str(repo_dir), "-c", "core.quotepath=off", *args],
                          input=stdin, capture_output=True,
                          env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})
    if done.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:3])}: {done.stderr.decode(errors='replace').strip()[:300]}")
    return done.stdout


def read_tree(repo_dir: Path, commit: str) -> Iterator[tuple[str, str, str]]:
    """``(path, blob id, text)`` for every Python file at ``commit``."""
    entries = []
    for line in _git(repo_dir, "ls-tree", "-r", commit).decode("utf-8", errors="replace").splitlines():
        meta, path = line.split("\t", 1)
        _mode, kind, blob = meta.split()
        if kind == "blob" and path.endswith(".py"):
            entries.append((path, blob))
    out = _git(repo_dir, "cat-file", "--batch", stdin="".join(f"{b}\n" for _, b in entries).encode())
    position = 0
    for path, blob in entries:
        end = out.index(b"\n", position)
        header = out[position:end].split()
        if header[-1] == b"missing":
            raise BlobMissing(f"{path} at {commit[:10]} is not in the local clone of {repo_dir.name}")
        size = int(header[2])
        text = out[end + 1:end + 1 + size].decode("utf-8", errors="replace").replace("\r\n", "\n")
        position = end + 1 + size + 1
        yield path, blob, text


def _is_test(path: str) -> bool:
    # classify_path knows test directories and test_*.py; a suite kept in one
    # top-level test.py (xml2rfc) is a test file as well.
    return classify_path(path) == "py-test" or PurePosixPath(path).name in ("test.py", "tests.py")


def fix_changed_files(repo_dir: Path, regressed_commit: str, clean_commit: str) -> list[dict[str, str]]:
    """Python files the fix added or modified, as they stand at the clean commit."""
    listing = _git(repo_dir, "diff", "--name-status", "--no-renames", regressed_commit, clean_commit)
    files = []
    for line in listing.decode("utf-8", errors="replace").splitlines():
        status, path = line.split("\t", 1)
        if status in ("A", "M") and path.endswith(".py"):
            files.append({"path": path, "status": status, "kind": "test" if _is_test(path) else "source"})
    return sorted(files, key=lambda f: f["path"])


# --- The scan --------------------------------------------------------------------


class UnitCache:
    """Units of each file, kept by blob id: events of one repository share most files."""

    def __init__(self) -> None:
        self._units: dict[str, list[tuple[CodeUnit, Counter]]] = {}

    def units(self, path: str, blob: str, text: str) -> list[tuple[CodeUnit, Counter]]:
        if blob not in self._units:
            self._units[blob] = [(u, _trigrams(u.tokens)) for u in code_units("", text)]
        return [(CodeUnit(path, u.kind, u.symbol, u.tokens), grams) for u, grams in self._units[blob]]


def scan_event(event_dir: Path, repo_dir: Path, *, threshold: float = THRESHOLD,
               min_tokens: int = MIN_TOKENS, cache: UnitCache | None = None) -> dict[str, Any]:
    """Everything in the event's repository that the retrieval layer must not see."""
    cache = cache or UnitCache()
    event = json.loads((event_dir / "event.json").read_text(encoding="utf-8"))
    clean = load_snapshot(event_dir / "clean").files
    regressed = load_snapshot(event_dir / "regressed").files
    slice_paths = set(clean) | set(regressed)

    elsewhere: list[tuple[CodeUnit, Counter]] = []
    files_scanned = 0
    for path, blob, text in read_tree(repo_dir, event["clean_commit"]):
        if path in slice_paths:
            continue  # the slice replaces these files; they are the trace itself
        files_scanned += 1
        elsewhere.extend(cache.units(path, blob, text))

    reported, duplicates = [], {}
    for unit in regression_units(clean, regressed):
        entry: dict[str, Any] = {"path": unit.path, "symbol": unit.symbol, "kind": unit.kind,
                                 "tokens": {v: len(t) for v, t in unit.versions.items()}}
        versions = {v: t for v, t in unit.versions.items() if len(t) >= min_tokens}
        entry["compared"] = bool(versions)
        if not versions:
            entry["note"] = f"under {min_tokens} tokens: too short to tell a copy from a coincidence"
            reported.append(entry)
            continue
        candidates = [(c, grams) for c, grams in elsewhere
                      if c.kind == unit.kind and len(c.tokens) >= min_tokens]
        closest: list[tuple[float, str, str]] = []
        for version, tokens in versions.items():
            for candidate, _ in candidates:
                score = _reaches(tokens, candidate.tokens, threshold)
                if score is None:
                    continue
                key = (candidate.path, candidate.symbol)
                if key not in duplicates or score > duplicates[key]["similarity"]:
                    duplicates[key] = {"path": candidate.path, "symbol": candidate.symbol,
                                       "kind": candidate.kind, "similarity": round(score, 3),
                                       "of": unit.name, "version": version}
            # The closest unit found, duplicate or not, so a reader can see how
            # far the rest of the repository is from the threshold.
            grams = _trigrams(tokens)
            ranked = sorted(candidates, key=lambda c: (-_resemblance(grams, c[1]), c[0].name))
            closest.extend((round(similarity(tokens, candidate.tokens), 3), candidate.name, version)
                           for candidate, _ in ranked[:NEAREST_CANDIDATES])
        nearest = min(closest, key=lambda f: (-f[0], f[1], f[2]), default=None)
        entry["nearest"] = (None if nearest is None else
                            {"similarity": nearest[0], "unit": nearest[1], "version": nearest[2]})
        reported.append(entry)

    fix_files = [{**f, "excluded": f["kind"] == "test"}
                 for f in fix_changed_files(repo_dir, event["regressed_commit"], event["clean_commit"])
                 if f["path"] not in slice_paths]
    near = sorted(duplicates.values(), key=lambda d: (d["path"], d["symbol"]))
    whole_files = {f["path"] for f in fix_files if f["excluded"]}
    exclusions = ([{"path": path, "symbol": None, "reason": FIX_TEST} for path in sorted(whole_files)]
                  + [{"path": d["path"], "symbol": d["symbol"], "reason": NEAR_DUPLICATE}
                     for d in near if d["path"] not in whole_files])
    return {
        "repo": event["repo"],
        "commit": event["clean_commit"],
        "scanned": {"files": files_scanned, "units": len(elsewhere)},
        "regression_units": reported,
        "near_duplicates": near,
        "fix_files": fix_files,
        "exclusions": exclusions,
    }


def build_report(events: dict[str, dict[str, Any]], *, threshold: float, min_tokens: int) -> dict[str, Any]:
    units_ = [u for e in events.values() for u in e["regression_units"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "method": {
            "similarity": "share of code tokens in common, in order (difflib.SequenceMatcher.ratio); "
                          "comments, docstrings and layout removed; identifiers as written",
            "threshold": threshold,
            "min_tokens": min_tokens,
            "scope": "Python files at the event's clean commit, outside the slice's own files",
        },
        "summary": {
            "events": len(events),
            "events_with_exclusions": sum(bool(e["exclusions"]) for e in events.values()),
            "events_with_near_duplicates": sum(bool(e["near_duplicates"]) for e in events.values()),
            "near_duplicates": sum(len(e["near_duplicates"]) for e in events.values()),
            "fix_tests_excluded": sum(f["excluded"] for e in events.values() for f in e["fix_files"]),
            "fix_sources_left_in_scope": sum(not f["excluded"] for e in events.values()
                                             for f in e["fix_files"]),
            "exclusions": sum(len(e["exclusions"]) for e in events.values()),
            "regression_units": len(units_),
            "regression_units_not_compared": sum(not u["compared"] for u in units_),
        },
        "events": {event_id: events[event_id] for event_id in sorted(events)},
    }


# --- What the retrieval layer reads --------------------------------------------------


@dataclass(frozen=True)
class Exclusions:
    """What retrieval must leave out for one event."""

    files: frozenset[str]
    symbols: frozenset[tuple[str, str]]

    def covers(self, path: str, symbol: str | None = None) -> bool:
        return path in self.files or (symbol is not None and (path, symbol) in self.symbols)


def load_exclusions(path: Path) -> dict[str, Exclusions]:
    report = json.loads(path.read_text(encoding="utf-8"))
    out = {}
    for event_id, event in report["events"].items():
        entries = event["exclusions"]
        out[event_id] = Exclusions(
            files=frozenset(e["path"] for e in entries if e["symbol"] is None),
            symbols=frozenset((e["path"], e["symbol"]) for e in entries if e["symbol"] is not None),
        )
    return out
