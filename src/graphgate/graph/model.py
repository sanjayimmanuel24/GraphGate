"""The code graph G(t) = (V, E_call, E_taint, E_sanitize) (BUILD_PLAN 4.1-4.3).

One ``networkx.MultiDiGraph`` per revision. Everything the difference rules
need is written here as plain node and edge attributes, so a rule can be
tested on a graph built by hand in a few lines.

**Nodes.** A *symbol* is a module, class, function or method, named
``path::qualname`` (``path::<module>`` for a module). Taint does not flow
between whole functions but between their parameters and return values, so
each symbol owns *ports*: ``sym#param``, ``sym#return``, ``cls#attr:name`` for
an attribute set through ``self``, and ``mod#var:name`` for a module-level
name. A port, a source site, a sink site and an inline guard all carry
``symbol``, the symbol that owns them; ``owner`` gives that symbol, or the node
itself for a symbol or a library function.

Three attributes mark the roles the rules look for, on any kind of node:
``source`` (a kind such as "request"), ``sink`` (a class: "sql", "command" or
"path") and ``sanitizer`` (how it was recognised: "library" or "validator").

**Edges**, told apart by ``kind``, which is also the edge key, so there is at
most one edge of a kind between two nodes:

- ``call``: symbol to the symbol it calls, with ``resolution``. A call that
  cannot be resolved goes to an ``unknown::`` node and is never dropped.
- ``taint``: data flows from one node to the next. ``via`` lists the symbols
  whose code makes it flow.
- ``sanitize``: a symbol applies a sanitizer, a validation function or an
  inline guard. ``uses`` holds "transform" (the result is used in place of the
  value) and/or "check" (it is called for its verdict).
"""

from __future__ import annotations

from typing import Any, Iterable, Iterator

import networkx as nx

CALL, TAINT, SANITIZE = "call", "taint", "sanitize"

MODULE, CLASS, FUNCTION, METHOD = "module", "class", "function", "method"
SYMBOL_KINDS = frozenset({MODULE, CLASS, FUNCTION, METHOD})
PORT, SOURCE, SINK, GUARD, EXTERNAL, UNKNOWN = "port", "source", "sink", "guard", "external", "unknown"

MODULE_QUALNAME = "<module>"

# How a call was resolved (CLAUDE.md, E_call). "unknown" is the explicit edge
# for everything the three rules cannot resolve.
SAME_MODULE, IMPORT, ATTRIBUTE, BUILTIN, UNRESOLVED = "same-module", "import", "attribute", "builtin", "unknown"

TRANSFORM, CHECK = "transform", "check"


def new_graph() -> nx.MultiDiGraph:
    return nx.MultiDiGraph()


def symbol_id(path: str, qualname: str = MODULE_QUALNAME) -> str:
    return f"{path}::{qualname}"


def owner(graph: nx.MultiDiGraph, node: str) -> str:
    """The symbol a node belongs to; a symbol or library node owns itself."""
    return graph.nodes[node].get("symbol", node)


def is_symbol(graph: nx.MultiDiGraph, node: str) -> bool:
    return graph.nodes[node].get("kind") in SYMBOL_KINDS


def edges(graph: nx.MultiDiGraph, kind: str) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for u, v, key, data in graph.edges(keys=True, data=True):
        if key == kind:
            yield u, v, data


def add_edge(graph: nx.MultiDiGraph, u: str, v: str, kind: str, **attrs: Any) -> None:
    """Add an edge, or merge into the one of this kind already there.

    List-valued attributes (``via``, ``uses``, ``lines``) are merged and kept
    sorted, so the graph does not depend on the order code was visited in.
    """
    for node in (u, v):
        if node not in graph:
            graph.add_node(node)
    if graph.has_edge(u, v, kind):
        data = graph.edges[u, v, kind]
        for name, value in attrs.items():
            if isinstance(value, (list, tuple, set, frozenset)):
                data[name] = sorted(set(data.get(name, ())) | set(value))
            else:
                data.setdefault(name, value)
    else:
        graph.add_edge(u, v, key=kind, kind=kind, **{
            name: sorted(set(value)) if isinstance(value, (list, tuple, set, frozenset)) else value
            for name, value in attrs.items()})


def taint_graph(graph: nx.MultiDiGraph, *, sanitizer_free: bool = False) -> nx.DiGraph:
    """The taint edges alone; without the sanitizer nodes if asked."""
    view = nx.DiGraph()
    blocked = {n for n, data in graph.nodes(data=True) if data.get("sanitizer")} if sanitizer_free else set()
    view.add_nodes_from(n for n in graph.nodes if n not in blocked)
    view.add_edges_from((u, v) for u, v, _ in edges(graph, TAINT) if u not in blocked and v not in blocked)
    return view


def with_role(graph: nx.MultiDiGraph, role: str) -> list[str]:
    return sorted(n for n, data in graph.nodes(data=True) if data.get(role))


def to_json(graph: nx.MultiDiGraph) -> dict[str, Any]:
    """A canonical, order-independent form: equal graphs give equal output."""
    return {
        "attrs": dict(sorted(graph.graph.items())),
        "nodes": [[n, dict(sorted(graph.nodes[n].items()))] for n in sorted(graph.nodes)],
        "edges": [[u, v, k, dict(sorted(d.items()))]
                  for u, v, k, d in sorted(graph.edges(keys=True, data=True), key=lambda e: e[:3])],
    }


def from_json(data: dict[str, Any]) -> nx.MultiDiGraph:
    graph = new_graph()
    graph.graph.update(data["attrs"])
    for node, attrs in data["nodes"]:
        graph.add_node(node, **attrs)
    for u, v, key, attrs in data["edges"]:
        graph.add_edge(u, v, key=key, **attrs)
    return graph


def restrict(graph: nx.MultiDiGraph, owners: Iterable[str]) -> nx.MultiDiGraph:
    """The part of the graph whose nodes belong to ``owners``."""
    keep = set(owners)
    return graph.subgraph([n for n in graph.nodes if owner(graph, n) in keep]).copy()
