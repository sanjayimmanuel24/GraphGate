"""Rules R1 to R4 over the difference of two code graphs (BUILD_PLAN 4.5).

Each rule is a pure function of the graph before a change and the graph after
it, and returns the flags it raises. The rules read node roles and edge kinds
only (see ``model``), so each is tested on graphs built by hand.

How the wording in CLAUDE.md is read here. These readings were fixed before
the rules were run on any event; do not change them after seeing results.

- **R1, sanitizer removal.** A sanitizer node of the graph before is *absent*
  when the graph after no longer has it, and *bypassed* for a caller when
  something that caller used to hand the sanitized value to now also receives
  a value that did not pass a sanitizer. Either counts only for callers that
  still exist.
- **R2, new source-to-sink path.** A source and a sink are joined by a taint
  path that passes no sanitizer, and were not before.
- **R3, guard elimination.** A sanitize edge (a call to a validation function,
  or an inline guard) is gone, and the symbol that had it is on a
  source-to-sink path, or guards one, both before and after.
- **R4, path shortening.** A source and a sink are joined by a sanitizer-free
  path in both graphs and the shortest one has fewer edges than before.

R2 and R4 never fire on the same pair. R1 and R3 may fire together with R2;
a flag is evidence for triage, not a verdict.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

import networkx as nx

from graphgate.graph.model import (
    CALL,
    SANITIZE,
    SYMBOL_KINDS,
    TAINT,
    edges,
    owner,
    restrict,
    taint_graph,
    with_role,
)

DEFAULT_HOPS = 2


@dataclass(frozen=True)
class Flag:
    rule: str                      # "R1" .. "R4"
    summary: str
    nodes: tuple[str, ...]         # what the flag is about: (sanitizer, caller) or (source, sink)
    path: tuple[str, ...] = ()     # a taint path that supports it, where there is one
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "summary": self.summary, "nodes": list(self.nodes),
                "path": list(self.path), "detail": self.detail}


# --- shared graph questions ----------------------------------------------------------

def _reachable(graph: nx.DiGraph, starts: Iterable[str]) -> set[str]:
    seen = {s for s in starts if s in graph}
    queue = deque(seen)
    while queue:
        for nxt in graph.successors(queue.popleft()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def free_paths(graph: nx.MultiDiGraph) -> dict[tuple[str, str], tuple[str, ...]]:
    """Shortest sanitizer-free taint path for every joined (source, sink) pair."""
    flows = taint_graph(graph, sanitizer_free=True)
    ordered = nx.DiGraph()
    ordered.add_nodes_from(sorted(flows.nodes))
    ordered.add_edges_from(sorted(flows.edges))     # sorted, so the path chosen among equals is stable
    sinks = [k for k in with_role(graph, "sink") if k in ordered]
    found: dict[tuple[str, str], tuple[str, ...]] = {}
    for source in with_role(graph, "source"):
        if source not in ordered:
            continue
        paths = nx.single_source_shortest_path(ordered, source)
        for sink in sinks:
            if sink != source and sink in paths:
                found[source, sink] = tuple(paths[sink])
    return found


def symbols_on_paths(graph: nx.MultiDiGraph) -> set[str]:
    """Symbols that a source-to-sink taint path runs through, sanitized or not."""
    flows = taint_graph(graph)
    on_path = (_reachable(flows, with_role(graph, "source"))
               & _reachable(flows.reverse(copy=False), with_role(graph, "sink")))
    symbols = {owner(graph, n) for n in on_path}
    for u, v, data in edges(graph, TAINT):
        if u in on_path and v in on_path:
            symbols.update(data.get("via", ()))
    return symbols


def guarded_symbols(graph: nx.MultiDiGraph) -> set[str]:
    """Symbols on a source-to-sink path, plus the guards those symbols rely on.

    A validation function is called for its verdict, so no path runs through
    it, yet weakening it weakens the path it guards. It is therefore counted,
    together with what it calls and applies in turn.
    """
    live = symbols_on_paths(graph)
    guards: set[str] = set()
    todo = [n for s in live if s in graph for _, n, key in graph.out_edges(s, keys=True) if key == SANITIZE]
    while todo:
        node = todo.pop()
        if node in live or node in guards:
            continue
        guards.add(node)
        todo.extend(n for _, n, key in graph.out_edges(node, keys=True) if key in (SANITIZE, CALL))
    return live | guards


# --- the rules -----------------------------------------------------------------------

def sanitizer_removal(before: nx.MultiDiGraph, after: nx.MultiDiGraph) -> list[Flag]:
    """R1: a sanitizer is absent or bypassed while its callers remain."""
    flags = []
    for sanitizer in with_role(before, "sanitizer"):
        callers = sorted(u for u, _, key in before.in_edges(sanitizer, keys=True) if key == SANITIZE)
        remaining = [u for u in callers if u in after]
        if not remaining:
            continue
        if sanitizer not in after or not after.nodes[sanitizer].get("sanitizer"):
            flags.append(Flag("R1", f"sanitizer {sanitizer} is gone while {len(remaining)} caller(s) remain",
                              nodes=(sanitizer, *remaining), detail={"how": "absent"}))
            continue
        for caller in remaining:
            exposed = _bypassed(before, after, sanitizer, caller)
            if exposed:
                flags.append(Flag("R1", f"{caller} now passes a value around sanitizer {sanitizer}",
                                  nodes=(sanitizer, caller),
                                  detail={"how": "bypassed", "receives_unsanitized": exposed}))
    return flags


def _bypassed(before: nx.MultiDiGraph, after: nx.MultiDiGraph, sanitizer: str, caller: str) -> list[str]:
    """What ``caller`` gave the sanitized value to and now also gives an unsanitized one."""
    def unsanitized_into(graph: nx.MultiDiGraph, target: str) -> bool:
        return target in graph and any(
            key == TAINT and caller in data.get("via", ()) and not graph.nodes[u].get("sanitizer")
            for u, _, key, data in graph.in_edges(target, keys=True, data=True))

    protected = sorted(v for _, v, key, data in before.out_edges(sanitizer, keys=True, data=True)
                       if key == TAINT and caller in data.get("via", ()))
    return [t for t in protected if unsanitized_into(after, t) and not unsanitized_into(before, t)]


def new_paths(before: nx.MultiDiGraph, after: nx.MultiDiGraph) -> list[Flag]:
    """R2: a sanitizer-free source-to-sink path exists that did not exist before."""
    old, new = free_paths(before), free_paths(after)
    return [Flag("R2", f"new path from {source} to {sink}", nodes=(source, sink), path=new[source, sink],
                 detail={"sink": after.nodes[sink].get("sink"), "source": after.nodes[source].get("source")})
            for source, sink in sorted(new.keys() - old.keys())]


def guard_elimination(before: nx.MultiDiGraph, after: nx.MultiDiGraph) -> list[Flag]:
    """R3: a guard edge on an existing source-to-sink path disappears."""
    guarded = guarded_symbols(before) & guarded_symbols(after)
    flags = []
    for symbol, guard, data in sorted(edges(before, SANITIZE), key=lambda e: e[:2]):
        if symbol not in guarded or after.has_edge(symbol, guard, SANITIZE):
            continue
        added = sorted(n for _, n, key in after.out_edges(symbol, keys=True)
                       if key == SANITIZE and not before.has_edge(symbol, n, SANITIZE))
        flags.append(Flag("R3", f"{symbol} no longer applies {guard}", nodes=(symbol, guard),
                          detail={"uses": list(data.get("uses", ())), "added_instead": added}))
    return flags


def path_shortening(before: nx.MultiDiGraph, after: nx.MultiDiGraph) -> list[Flag]:
    """R4: the shortest sanitizer-free path from a source to a sink gets shorter."""
    old, new = free_paths(before), free_paths(after)
    return [Flag("R4", f"path from {source} to {sink} shortened from {len(old[source, sink]) - 1} "
                       f"to {len(new[source, sink]) - 1} hop(s)",
                 nodes=(source, sink), path=new[source, sink],
                 detail={"hops_before": len(old[source, sink]) - 1, "hops_after": len(new[source, sink]) - 1,
                         "path_before": list(old[source, sink])})
            for source, sink in sorted(new.keys() & old.keys())
            if len(new[source, sink]) < len(old[source, sink])]


RULES: dict[str, Callable[[nx.MultiDiGraph, nx.MultiDiGraph], list[Flag]]] = {
    "R1": sanitizer_removal,
    "R2": new_paths,
    "R3": guard_elimination,
    "R4": path_shortening,
}


# --- the delta: which part of the graphs the rules look at ----------------------------

def changed_symbols(before: nx.MultiDiGraph, after: nx.MultiDiGraph) -> set[str]:
    """Symbols added, removed, or whose code differs (by ``digest``)."""
    changed = set()
    for node in set(before.nodes) | set(after.nodes):
        old, new = before.nodes.get(node), after.nodes.get(node)
        if (old or new).get("kind") not in SYMBOL_KINDS:
            continue
        if old is None or new is None or old.get("digest") != new.get("digest"):
            changed.add(node)
    return changed


def neighbourhood(before: nx.MultiDiGraph, after: nx.MultiDiGraph, changed: Iterable[str], hops: int) -> set[str]:
    """Symbols within ``hops`` edges of a changed symbol, in either graph.

    Distance is counted between symbols, not between their ports: a taint edge
    made by a symbol's code ties that symbol to both of its ends.
    """
    near = nx.Graph()
    for graph in (before, after):
        near.add_nodes_from(owner(graph, n) for n in graph.nodes)
        for u, v, key, data in graph.edges(keys=True, data=True):
            ends = (owner(graph, u), owner(graph, v))
            makers = data.get("via", ()) if key == TAINT else ()
            if makers:
                near.add_edges_from((maker, end) for maker in makers for end in ends)
            else:
                near.add_edge(*ends)
    seen = {s for s in changed if s in near}
    frontier = set(seen)
    for _ in range(hops):
        frontier = {n for s in frontier for n in near.neighbors(s)} - seen
        seen |= frontier
    return seen


def apply_rules(before: nx.MultiDiGraph, after: nx.MultiDiGraph, *, hops: int | None = DEFAULT_HOPS,
                rules: Iterable[str] = ("R1", "R2", "R3", "R4")) -> list[Flag]:
    """Flags for the change from ``before`` to ``after``.

    The rules see the graphs only within ``hops`` of the changed symbols
    (CLAUDE.md, bounded retrieval; the depth is an ablation variable).
    ``hops=None`` lifts the bound.
    """
    if hops is not None:
        changed = changed_symbols(before, after)
        if not changed:
            return []
        near = neighbourhood(before, after, changed, hops)
        before, after = restrict(before, near), restrict(after, near)
    return [flag for name in rules for flag in RULES[name](before, after)]
