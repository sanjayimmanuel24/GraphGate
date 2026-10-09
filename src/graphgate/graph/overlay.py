"""The repository around a slice: Condition C's registered view (BUILD_PLAN 5.2).

A trace holds an event's *slice*: the files on the vulnerable flow, cut down
to the functions that matter. The proposal's graph covers the repository. A
``RepositoryView`` puts the two together for one event. The graph of a code
state then holds

1. every file of the repository at the event's fix commit that is not a slice
   file, as it is there;
2. the slice files as the trace has them at that moment;
3. for each slice file, the code the slicer cut out of it, from the
   repository's copy of the file.

Part 3 is what brings back a sink that was too large for the slice. It works
on facts, not text, because the model rewrites a slice file as a whole and
there is no place in its text to paste the cut code back. The rules, fixed
before the view was run on any event:

- *Cut* means: defined in the repository's file and not in the event's clean
  slice. Whatever the slice held at the start belongs to the trace from then
  on: if the model deletes it, it is gone, and it is never restored from the
  repository.
- A cut function, method or class is added unless the code state defines
  something of that name, or the class or function it sat in is no longer
  there.
- A slice file's own module-level and class-level code is the trace's. From
  the repository's copy come only the cut definitions, the module-level
  assignments to names the slice never assigned, and the imports the trace's
  copy lacks. Other cut module-level statements are not brought back.
- A file the model deletes from the slice is gone, cut code included. A file
  the model adds is taken as it is.

The event's leakage exclusions are applied here (CLAUDE.md, leakage control):
an excluded file is left out, an excluded function is removed from its file.

Everything taken from the repository is marked ``origin: "repository"``, so
code shown to the triage model is read from the right text. The repository is
the same before and after a turn, so nothing in it counts as changed.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from graphgate.graph.extract import extract
from graphgate.graph.model import MODULE_QUALNAME

REPOSITORY = "repository"

Facts = dict[str, Any]


def _qualnames(facts: Facts) -> set[str]:
    return {s["qualname"] for s in facts["symbols"]}


def _under(qualname: str, roots: Iterable[str]) -> bool:
    return any(qualname == root or qualname.startswith(root + ".") for root in roots)


def without_symbols(facts: Facts, qualnames: Iterable[str]) -> Facts:
    """The facts of a file with some definitions, and everything inside them, removed."""
    gone = set(qualnames)
    if not gone:
        return facts
    kept = copy.deepcopy(facts)
    kept["symbols"] = [s for s in kept["symbols"] if not _under(s["qualname"], gone)]
    for symbol in kept["symbols"]:
        symbol["defs"] = {name: q for name, q in symbol["defs"].items() if not _under(q, gone)}
    return kept


def _graft_assignments(target: Facts, source: Facts, names: set[str]) -> None:
    """Add ``source``'s assignments to ``names`` to the symbol ``target``, with the calls they use."""
    moved: dict[int, int] = {}

    def atom(value: str) -> str:
        return f"c:{call(int(value[2:]))}" if value.startswith("c:") else value

    def call(index: int) -> int:
        if index not in moved:
            moved[index] = len(target["calls"])
            target["calls"].append(None)                 # holds the place while the arguments are moved
            original = source["calls"][index]
            target["calls"][moved[index]] = {
                **original,
                "args": [[atom(a) for a in group] for group in original["args"]],
                "kwargs": {name: [atom(a) for a in group] for name, group in original["kwargs"].items()},
                "star": [atom(a) for a in original["star"]],
                "receiver": [atom(a) for a in original["receiver"]],
            }
        return moved[index]

    for assigned, atoms in source["assigns"]:
        if assigned.startswith("v:") and assigned[2:] in names:
            target["assigns"].append([assigned, [atom(a) for a in atoms]])


def merge(current: Facts, repository: Facts, initial: Facts) -> Facts:
    """Facts of a slice file as the trace has it, with the code the slicer cut put back."""
    merged = copy.deepcopy(current)
    here = _qualnames(current)
    by_name = {s["qualname"]: s for s in merged["symbols"]}
    cut = [copy.deepcopy(s) for s in repository["symbols"]
           if s["qualname"] not in _qualnames(initial) and s["qualname"] not in here]
    # Outer definitions first, so that a nested one can see whether its holder made it.
    for symbol in sorted(cut, key=lambda s: s["qualname"].count(".")):
        holder = by_name.get(symbol["parent"])
        if holder is None:
            continue                                     # what it sat in is no longer there
        symbol["origin"] = REPOSITORY
        merged["symbols"].append(symbol)
        by_name[symbol["qualname"]] = symbol
        holder["defs"].setdefault(symbol["qualname"].split(".")[-1], symbol["qualname"])

    module, theirs, at_start = by_name[MODULE_QUALNAME], repository["symbols"][0], initial["symbols"][0]
    assigned = lambda symbol: {t[2:] for t, _ in symbol["assigns"] if t.startswith("v:")}
    _graft_assignments(module, theirs, assigned(theirs) - assigned(at_start) - assigned(module) - set(module["defs"]))
    merged["imports"] = {**repository["imports"], **current["imports"]}
    merged["star_imports"] = sorted(set(current["star_imports"]) | set(repository["star_imports"]))
    return merged


class RepositoryView:
    """One event's repository, ready to be laid around any state of its slice."""

    def __init__(self, repo_files: Mapping[str, str], slice_files: Mapping[str, str], *,
                 exclude_files: Iterable[str] = (), exclude_symbols: Iterable[tuple[str, str]] = (),
                 extractor: Callable[[str, str], Facts] = extract):
        self.repo_files = {path: text for path, text in repo_files.items() if path.endswith(".py")}
        self.excluded_files = frozenset(exclude_files)
        self._slice_paths = frozenset(p for p in slice_files if p.endswith(".py"))
        self._extract = extractor
        excluded: dict[str, set[str]] = {}
        for path, symbol in exclude_symbols:
            excluded.setdefault(path, set()).add(symbol)
        self._repo_facts: dict[str, Facts] = {}
        for path, text in self.repo_files.items():
            if path in self.excluded_files:
                continue
            facts = without_symbols(copy.deepcopy(extractor(path, text)), excluded.get(path, ()))
            for symbol in facts["symbols"]:
                symbol["origin"] = REPOSITORY
            self._repo_facts[path] = facts
        self._initial = {path: extractor(path, slice_files[path]) for path in self._slice_paths}
        self.missing_from_repository = sorted(self._slice_paths - set(self.repo_files))

    def facts(self, files: Mapping[str, str]) -> dict[str, Facts]:
        """Facts of the repository with the slice in the state ``files``."""
        out = {path: facts for path, facts in self._repo_facts.items() if path not in self._slice_paths}
        for path, text in files.items():
            if not path.endswith(".py"):
                continue
            current = self._extract(path, text)
            if path in self._slice_paths and path in self._repo_facts:
                out[path] = merge(current, self._repo_facts[path], self._initial[path])
            else:
                out[path] = current
        return out

    def key(self, files: Mapping[str, str]) -> str:
        """Names a code state: two states with the same slice files give the same graph."""
        digest = hashlib.sha256()
        for path in sorted(files):
            digest.update(path.encode("utf-8") + b"\0" + hashlib.sha256(files[path].encode("utf-8")).digest())
        return digest.hexdigest()


# --- repository snapshots on disk -----------------------------------------------------
#
# One JSON file per event lists the repository's Python files at the fix commit
# by git blob id; the texts are stored once per blob, since events of one
# repository share most files. Written by scripts/build_repo_snapshots.py into
# an ignored directory: it is other projects' code, rebuilt from the clones.

class SnapshotMissing(RuntimeError):
    """An event has no repository snapshot. Never worked around by using the slice alone."""


def write_snapshot(directory: Path, event_id: str, repo: str, commit: str,
                   files: Iterable[tuple[str, str, str]]) -> int:
    """Store ``(path, blob id, text)`` for one event; returns the number of files."""
    blobs = directory / "blobs"
    blobs.mkdir(parents=True, exist_ok=True)
    index = {}
    for path, blob, text in files:
        index[path] = blob
        target = blobs / f"{blob}.py"
        if not target.exists():
            target.write_text(text, encoding="utf-8", newline="\n")
    (directory / f"{event_id}.json").write_text(
        json.dumps({"event_id": event_id, "repo": repo, "commit": commit, "files": dict(sorted(index.items()))},
                   indent=1) + "\n", encoding="utf-8", newline="\n")
    return len(index)


def read_snapshot(directory: Path, event_id: str) -> dict[str, str]:
    """Repository path to text for one event's snapshot."""
    index = directory / f"{event_id}.json"
    if not index.exists():
        raise SnapshotMissing(f"no repository snapshot for {event_id} in {directory.as_posix()}; "
                              "build them with scripts/build_repo_snapshots.py")
    files = json.loads(index.read_text(encoding="utf-8"))["files"]
    return {path: (directory / "blobs" / f"{blob}.py").read_text(encoding="utf-8") for path, blob in files.items()}


def view_for_event(event_dir: Path, snapshots: Path, *, exclude_files: Iterable[str] = (),
                   exclude_symbols: Iterable[tuple[str, str]] = ()) -> RepositoryView:
    """The repository view of the event in ``event_dir``, from its snapshot and its clean slice."""
    clean = event_dir / "clean"
    slice_files = {path.relative_to(clean).as_posix(): path.read_text(encoding="utf-8")
                   for path in sorted(clean.rglob("*.py"))}
    return RepositoryView(read_snapshot(snapshots, event_dir.name), slice_files,
                          exclude_files=exclude_files, exclude_symbols=exclude_symbols)
