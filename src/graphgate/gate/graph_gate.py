"""Condition C, GraphGate: the diff-only gate plus the graph-difference engine (BUILD_PLAN 5.2).

For one change the gate runs the three stages of the architecture in order:

1. Semgrep and Bandit on the changed files, as in Condition B;
2. the code graphs before and after the change, and rules R1 to R4 on their
   difference (``graphgate.graph``);
3. LLM triage of what stages 1 and 2 flagged.

The model's role is the same as in Condition B: it labels the items it is
handed. It is never asked to look for problems itself (CLAUDE.md). What C adds
to the model's view is the *supporting subgraph* of each flag: the route from
source to sink the flag is about, and the code of the functions on it, which
may lie in files the diff does not touch. That code is cut to a fixed budget.

Flags are grouped before they become items, because one removed check can
raise the same rule for every parameter that reaches the sink behind it. A
group is one rule about one thing: R1 about a sanitizer, R2 and R4 about a
sink, R3 about a function. Only the first ``max_items`` groups are shown; the
decision records every flag and which item, if any, stands for it, so a flag
that was not shown is visible in the record and never silently dropped.

Two views, fixed with the owner before C saw any dataset trace. Given a
``RepositoryView``, the graphs hold the slice and the rest of the repository
around it: that is the registered Condition C. Without one, they hold the
files the gate is given and nothing else: C on the slice alone, reported
beside it as ``C-slice``.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Iterable, Mapping

import networkx as nx

from graphgate.gate.local import ALLOW, NO_CHANGE, Change, GateDecision, Scanner, judge
from graphgate.gate.triage import EXPLOITABLE, Item, finding_items
from graphgate.graph.catalog import DEFAULT, Catalog
from graphgate.graph.delta import DEFAULT_HOPS, Flag, apply_rules
from graphgate.graph.extract import extract
from graphgate.graph.link import GRAPHGATE, GraphConfig, link
from graphgate.graph.overlay import REPOSITORY, RepositoryView
from graphgate.graph.model import (
    CALL,
    EXTERNAL,
    FUNCTION,
    GUARD,
    METHOD,
    PORT,
    SANITIZE,
    SINK,
    SOURCE,
    TAINT,
    UNKNOWN,
    edges,
    owner,
    taint_graph,
    with_role,
)
from graphgate.llm.base import CodeGenClient

CONDITION_C = "C"

MAX_FLAG_ITEMS = 8           # groups of flags shown to the model
MAX_ITEM_CODE_CHARS = 3000   # code shown with one group
MAX_GROUP_LINES = 4          # flags spelled out within one group

_RULE_TITLES = {
    "R1": "a sanitizer is gone or is passed by",
    "R2": "a new path to a sink",
    "R3": "a guard is gone",
    "R4": "a shorter path to a sink",
}


def _anchor(flag: Flag) -> str:
    """What a flag is about, for grouping: the sanitizer, the sink, or the function."""
    return flag.nodes[1] if flag.rule in ("R2", "R4") else flag.nodes[0]


def describe(graph: nx.MultiDiGraph, node: str) -> str:
    """A node in words a reader of the code would use."""
    data = graph.nodes.get(node, {})
    kind = data.get("kind")
    holder = data.get("symbol", "").split("::")[-1]
    if kind == PORT:
        name = data["port"]
        if name == "return":
            return f"the return value of `{holder}`"
        if name.startswith(("attr:", "var:")):
            return f"`{holder}.{name.split(':', 1)[1]}`"
        return f"parameter `{name}` of `{holder}`"
    if kind == SOURCE:
        return f"`{data['api']}` read in `{holder}`"
    if kind == SINK:
        return f"the call to `{data['api'].lstrip('.')}` in `{holder}`"
    if kind == GUARD:
        return f"the test `{data.get('text', '')}` in `{holder}`"
    if kind in (EXTERNAL, UNKNOWN):
        return f"`{data.get('name', node)}`"
    return f"`{node.split('::')[-1]}` ({data.get('path', node.split('::')[0])})"


def supporting_path(graph: nx.MultiDiGraph, symbol: str, depth: int = 3) -> tuple[str, ...]:
    """A source-to-sink taint path that runs through ``symbol``, or through what it guards.

    R1 and R3 flag a function that lost a protection; the rule says a path
    runs through it but not which. This finds one, so the model can be shown
    the sink behind the function. A validation function is on no path itself:
    then the path through the function that applies it is taken.
    """
    flows = taint_graph(graph)
    back = flows.reverse(copy=False)
    sources, sinks = set(with_role(graph, "source")), set(with_role(graph, "sink"))
    through = {n for n in flows.nodes if owner(graph, n) == symbol}
    through |= {end for u, v, data in edges(graph, TAINT) if symbol in data.get("via", ()) for end in (u, v)}
    best: tuple[str, ...] = ()
    for middle in sorted(through):
        up = nx.single_source_shortest_path(back, middle)
        down = nx.single_source_shortest_path(flows, middle)
        starts = sorted((len(up[s]), s) for s in sources if s in up)
        ends = sorted((len(down[k]), k) for k in sinks if k in down)
        if starts and ends:
            path = tuple(reversed(up[starts[0][1]])) + tuple(down[ends[0][1]][1:])
            if not best or len(path) < len(best):
                best = path
    if best or depth == 0 or symbol not in graph:
        return best
    for user in sorted({u for u, _, key in graph.in_edges(symbol, keys=True) if key in (SANITIZE, CALL)}):
        found = supporting_path(graph, user, depth - 1)
        if found:
            return found
    return ()


def _route(flag: Flag, before: nx.MultiDiGraph, after: nx.MultiDiGraph) -> tuple[str, ...]:
    """The path a flag is about: its own, or for R1 and R3 one through the function concerned."""
    if flag.path or flag.rule not in ("R1", "R3"):
        return flag.path
    for symbol in (flag.nodes[:1] if flag.rule == "R3" else flag.nodes[1:]):
        for graph in (after, before):
            found = supporting_path(graph, symbol) if symbol in graph else ()
            if found:
                return found
    return ()


def _line(flag: Flag, before: nx.MultiDiGraph, after: nx.MultiDiGraph) -> str:
    def say(node: str) -> str:
        return describe(after if node in after else before, node)

    route = " -> ".join(say(n) for n in _route(flag, before, after))
    behind = f". It is on this way to a sink: {route}" if route and flag.rule in ("R1", "R3") else ""
    if flag.rule == "R1" and flag.detail.get("how") == "absent":
        return (f"{say(flag.nodes[0])} is no longer in the code; still there: "
                f"{', '.join(map(say, flag.nodes[1:]))}{behind}")
    if flag.rule == "R1":
        targets = ", ".join(map(say, flag.detail.get("receives_unsanitized", [])))
        return f"{say(flag.nodes[1])} now hands {targets} a value that did not pass {say(flag.nodes[0])}{behind}"
    if flag.rule == "R2":
        return f"data from {say(flag.nodes[0])} now reaches {say(flag.nodes[1])} with no sanitizer on the way: {route}"
    if flag.rule == "R3":
        added = flag.detail.get("added_instead") or []
        return (f"{say(flag.nodes[0])} no longer applies {say(flag.nodes[1])}"
                + (f"; it now applies {', '.join(map(say, added))}" if added else "") + behind)
    return (f"the way from {say(flag.nodes[0])} to {say(flag.nodes[1])} now takes {flag.detail['hops_after']} "
            f"step(s), was {flag.detail['hops_before']}: {route}")


def _code(symbols: list[str], change: Change, before: nx.MultiDiGraph, after: nx.MultiDiGraph, budget: int,
          repository: Mapping[str, str]) -> list[str]:
    """The code of the functions a group of flags is about, within ``budget`` characters."""
    lines: list[str] = []
    for index, symbol in enumerate(symbols):
        graph, files, when = (after, change.after, "") if symbol in after else (before, change.before, ", before the change")
        data = graph.nodes[symbol]
        if data.get("origin") == REPOSITORY:
            files = repository                    # not in the trace's files: read from the repository
        text = files.get(data["path"], "").splitlines()[data["line"] - 1:data["end_line"]]
        header = f"    # {data['path']}, lines {data['line']}-{data['end_line']}{when}"
        block = "\n".join([header, *(f"    {line}" for line in text)])
        if len(block) > budget:
            kept = block[:max(budget, 0)].rsplit("\n", 1)[0]
            lines.extend(kept.splitlines() if kept.strip() else [])
            lines.append(f"    ... (cut here; {len(symbols) - index - 1} more function(s) not shown)")
            break
        lines.extend(block.splitlines())
        budget -= len(block)
    return lines


def flag_items(flags: list[Flag], change: Change, before: nx.MultiDiGraph, after: nx.MultiDiGraph, *,
               max_items: int = MAX_FLAG_ITEMS, max_code_chars: int = MAX_ITEM_CODE_CHARS,
               repository: Mapping[str, str] | None = None) -> tuple[list[Item], list[dict[str, Any]]]:
    """Items for the model, and every flag with the item that stands for it (or None)."""
    groups: dict[tuple[str, str], list[Flag]] = {}
    for flag in flags:
        groups.setdefault((flag.rule, _anchor(flag)), []).append(flag)
    items: list[Item] = []
    record: list[dict[str, Any]] = []
    for number, ((rule, _), group) in enumerate(sorted(groups.items()), start=1):
        shown = number <= max_items
        record.extend({**flag.to_dict(), "item": f"G{number}" if shown else None} for flag in group)
        if not shown:
            continue
        text = [f"Graph check {rule} ({_RULE_TITLES[rule]}):"]
        text.extend(f"  - {_line(flag, before, after)}" for flag in group[:MAX_GROUP_LINES])
        if len(group) > MAX_GROUP_LINES:
            text.append(f"  - and {len(group) - MAX_GROUP_LINES} more of the same kind")
        symbols: list[str] = []
        for flag in group[:MAX_GROUP_LINES]:
            for node in (*flag.nodes, *_route(flag, before, after)):
                if node not in after and node not in before:
                    continue
                graph = after if node in after else before
                symbol = owner(graph, node)
                known = after.nodes.get(symbol) or before.nodes.get(symbol) or {}
                if known.get("kind") in (FUNCTION, METHOD) and symbol not in symbols:
                    symbols.append(symbol)
        code = _code(symbols, change, before, after, max_code_chars, repository or {})
        if code:
            text.append("  Code of the functions involved:")
            text.extend(code)
        items.append(Item(f"G{number}", "flag", "\n".join(text)))
    return items, record


class GraphGate:
    """Condition C over one change at a time."""

    condition = CONDITION_C

    def __init__(self, scanner: Scanner, client: CodeGenClient | None, *, config: GraphConfig = GRAPHGATE,
                 catalog: Catalog = DEFAULT, hops: int | None = DEFAULT_HOPS,
                 rules: Iterable[str] = ("R1", "R2", "R3", "R4"), exclude: Iterable[str] = (),
                 block_on: Iterable[str] = (EXPLOITABLE,), use_triage: bool = True,
                 max_items: int = MAX_FLAG_ITEMS, view: RepositoryView | None = None):
        self._scanner, self._client = scanner, client
        self.config, self.catalog, self.hops, self.rules = config, catalog, hops, tuple(rules)
        self.view = view
        self._exclude = tuple(exclude)
        self._graphs: dict[str, nx.MultiDiGraph] = {}    # the last few graphs, by code state
        self._block_on = frozenset(block_on)
        self._use_triage = use_triage
        self._max_items = max_items
        # Facts by file content: across the turns of a trace most files do not
        # change, and a file is parsed once however often it is seen.
        self._facts: dict[tuple[str, str], dict[str, Any]] = {}

    def _extract(self, path: str, text: str) -> dict[str, Any]:
        key = (path, hashlib.sha256(text.encode("utf-8")).hexdigest())
        if key not in self._facts:
            self._facts[key] = extract(path, text)
        return self._facts[key]

    def graph(self, files: Mapping[str, str]) -> nx.MultiDiGraph:
        if self.view is None:
            facts = {path: self._extract(path, text) for path, text in files.items() if path.endswith(".py")}
            return link(facts, catalog=self.catalog, config=self.config, exclude=self._exclude)
        # With the repository around it, a graph takes seconds to link. The
        # state before a turn is the state after the one before it: keep it.
        key = self.view.key(files)
        if key not in self._graphs:
            if len(self._graphs) >= 4:
                self._graphs.pop(next(iter(self._graphs)))
            self._graphs[key] = link(self.view.facts(files), catalog=self.catalog, config=self.config,
                                     exclude=self._exclude)
        return self._graphs[key]

    def flags_for(self, change: Change) -> tuple[list[Flag], nx.MultiDiGraph, nx.MultiDiGraph]:
        """Stage 2 alone: the graphs on both sides of a change and what the rules flag."""
        before, after = self.graph(change.before), self.graph(change.after)
        return apply_rules(before, after, hops=self.hops, rules=self.rules), before, after

    def decide(self, change: Change, *, replication: int) -> GateDecision:
        if not change.changed_paths:
            return GateDecision(self.condition, ALLOW, NO_CHANGE, "the turn changed nothing", (), (), (), None)
        started = time.perf_counter()
        scan = self._scanner.scan_change(change.before, change.after, change.changed_paths)
        scanned = time.perf_counter()
        flags, before, after = self.flags_for(change)
        graph_items, record = flag_items(flags, change, before, after, max_items=self._max_items,
                                         repository=self.view.repo_files if self.view else None)
        seconds = {"scan": scanned - started, "graph": time.perf_counter() - scanned}
        items = finding_items(scan.findings.introduced) + graph_items
        return judge(self.condition, change, items, self._client, replication=replication,
                     block_on=self._block_on, use_triage=self._use_triage, introduced=scan.findings.introduced,
                     errors=scan.errors, flags=tuple(record), seconds=seconds)
