"""The facts of all files to one graph (BUILD_PLAN 4.2 and 4.3).

**Calls (E_call)** are resolved by the three rules of CLAUDE.md and nothing
else: (i) a name defined in the same module, (ii) a name reached through
static imports, (iii) an attribute call whose receiver's class can be read off
the code: ``self``, a class name, a variable assigned from one constructor, an
attribute assigned from one constructor, or an annotated parameter. Every
other call gets an explicit edge to an ``unknown::`` node and is counted;
``graph.graph["stats"]`` holds the counts the paper reports.

**Taint (E_taint)** follows the atoms recorded by ``extract``: inside a symbol
the origins of each name are solved to a fixed point, ignoring order and
branches, and edges are drawn from each origin to where the value goes: a
callee's parameter, the symbol's return value, an attribute, a sink. A call to
code the graph cannot see passes on whatever went into it.

**Sanitizers (E_sanitize).** A call to an allowlisted function gets a
``sanitize`` edge. Its arguments flow into the sanitizer node and its result
flows out of it, so a path that uses the result passes the node. A validation
function of the project, recognised by name, is treated the same way: callers'
values go to its node, not into its parameters.

Two settings widen what the graph marks beyond the proposal's wording. Both
are recorded in the graph, because they change what the rules can see; which
combination stands for GraphGate is fixed in ``SETTINGS`` below:

- ``public_api_sources``: the parameters of a library's public functions are
  sources, as untrusted as a request.
- ``structural_guards``: an ``if`` that raises or exits, or an ``assert``,
  whose test looks at a value, is a guard edge, like a call to a validator.
"""

from __future__ import annotations

import builtins
import logging
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable, Mapping

import networkx as nx

from graphgate.graph.catalog import DEFAULT, PUBLIC_API, REQUEST, Catalog, Sink, is_validator_name
from graphgate.graph.extract import extract
from graphgate.graph.model import (
    ATTRIBUTE,
    BUILTIN,
    CALL,
    CHECK,
    CLASS,
    EXTERNAL,
    FUNCTION,
    GUARD,
    IMPORT,
    METHOD,
    MODULE,
    PORT,
    SAME_MODULE,
    SANITIZE,
    SINK,
    SOURCE,
    TAINT,
    TRANSFORM,
    UNKNOWN,
    UNRESOLVED,
    add_edge,
    new_graph,
    symbol_id,
)

log = logging.getLogger(__name__)

_BUILTINS = frozenset(dir(builtins))
_TEST_DIRS = frozenset({"tests", "test", "testing"})
_MAX_ROUNDS = 100

Ref = tuple[str, Any]      # ("symbol", id) | ("external", dotted) | ("module", name) | ("var", (module id, name)) | ("unknown", text)


@dataclass(frozen=True)
class GraphConfig:
    public_api_sources: bool = False
    structural_guards: bool = False
    source_kinds: tuple[str, ...] | None = None      # None: every kind the catalog declares

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Fixed with the owner on 2026-10-08, before the rules were run on any event:
# GRAPHGATE is the graph of Condition C, the one the registered comparison with
# Condition B uses. The other three are reported beside it as an ablation and
# never in its place. AS_PROPOSED is the proposal's wording taken literally.
AS_PROPOSED = GraphConfig()
GRAPHGATE = GraphConfig(public_api_sources=True, structural_guards=True)
SETTINGS: dict[str, GraphConfig] = {
    "graphgate": GRAPHGATE,
    "public-api-sources-only": GraphConfig(public_api_sources=True),
    "structural-guards-only": GraphConfig(structural_guards=True),
    "as-proposed": AS_PROPOSED,
}


@dataclass(frozen=True)
class Target:
    """What a call resolves to."""
    node: str                       # the graph node the call edge goes to
    resolution: str
    name: str                       # dotted name of a library callee, else the callee as written
    symbol: str | None = None       # the function or method, when it is in the repository
    cls: str | None = None          # the class, when the call constructs one of the repository's
    bound: bool = False             # the first parameter is supplied by the call itself
    method: str | None = None       # the attribute name, when the receiver is not a repository class


@dataclass(frozen=True)
class Role:
    sink: tuple[str, Sink] | None = None
    source: tuple[str, str] | None = None
    sanitizer: str | None = None


def is_test_path(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    return bool(_TEST_DIRS & set(parts[:-1])) or name.startswith("test_") or name.endswith("_test.py") \
        or name == "conftest.py"


def build_graph(files: Mapping[str, str], *, catalog: Catalog = DEFAULT, config: GraphConfig = GraphConfig(),
                exclude: Iterable[str] = ()) -> nx.MultiDiGraph:
    """Graph of a set of files, given as repository path to text."""
    return link({path: extract(path, text) for path, text in files.items()},
                catalog=catalog, config=config, exclude=exclude)


def link(facts: Mapping[str, dict[str, Any]], *, catalog: Catalog = DEFAULT, config: GraphConfig = GraphConfig(),
         exclude: Iterable[str] = ()) -> nx.MultiDiGraph:
    """Graph of the files whose facts are given.

    ``exclude`` lists paths to leave out as if they were not in the repository:
    the leakage exclusions of an event (CLAUDE.md, leakage control).
    """
    excluded = sorted(set(exclude) & set(facts))
    kept = {path: facts[path] for path in sorted(facts) if path not in excluded}
    linker = _Linker(kept, catalog, config)
    graph = linker.run()
    graph.graph["excluded"] = excluded
    return graph


class _Linker:
    def __init__(self, facts: Mapping[str, dict[str, Any]], catalog: Catalog, config: GraphConfig):
        self.facts, self.catalog, self.config = facts, catalog, config
        self.graph = new_graph()
        self.modules = {f["module"]: f for f in facts.values()}
        self.top_packages = {name.split(".")[0] for name in self.modules}
        self.symbols = {s["id"]: s for f in facts.values() for s in f["symbols"]}
        self.file_of = {s["id"]: f for f in facts.values() for s in f["symbols"]}
        self.calls: Counter[str] = Counter()
        self.unknown_by_file: Counter[str] = Counter()
        self._locals: dict[str, frozenset[str]] = {}
        self._names: dict[tuple[str, str], tuple[str | None, Any]] = {}
        self._targets: dict[tuple[str, int], Target] = {}
        self._typing: set[tuple[str, str]] = set()        # type lookups in progress, against cycles
        self._homes: dict[str, str] = {}

    # --- driver ---

    def run(self) -> nx.MultiDiGraph:
        for sid, sym in self.symbols.items():
            attrs = {"kind": sym["kind"], "path": self.file_of[sid]["path"], "qualname": sym["qualname"],
                     "line": sym["line"], "end_line": sym["end_line"], "digest": sym["digest"]}
            if sym["kind"] in (FUNCTION, METHOD) and is_validator_name(sym["qualname"].split(".")[-1]):
                attrs["sanitizer"] = "validator"
            if sym.get("origin"):
                attrs["origin"] = sym["origin"]      # code laid around a slice (graph.overlay)
            self.graph.add_node(sid, **attrs)
        for sym in self.symbols.values():
            self._flows(sym)
        for sym in self.symbols.values():
            if sym["kind"] in (FUNCTION, METHOD):
                self._parameter_sources(sym)
        errors = sorted(f["path"] for f in self.facts.values() if f["parse_error"])
        for path in errors:
            log.warning("graph: %s has a syntax error; only what parses is in the graph", path)
        total = sum(self.calls.values())
        unknown = self.calls[UNRESOLVED]
        log.info("graph: %d file(s), %d symbol(s), %d call(s), %d unknown (%.0f%%)", len(self.facts),
                 len(self.symbols), total, unknown, 100 * unknown / total if total else 0)
        self.graph.graph["config"] = self.config.to_dict()
        self.graph.graph["stats"] = {
            "files": len(self.facts), "symbols": len(self.symbols), "parse_errors": errors,
            "calls": dict(sorted(self.calls.items())), "calls_total": total, "unknown_calls": unknown,
            "unknown_by_file": dict(sorted(self.unknown_by_file.items())),
        }
        return self.graph

    # --- scopes and names ---

    def _sibling(self, sym: dict[str, Any], qualname: str | None) -> dict[str, Any] | None:
        return self.symbols.get(symbol_id(self.file_of[sym["id"]]["path"], qualname)) if qualname else None

    def _module(self, sym: dict[str, Any]) -> dict[str, Any]:
        return self.file_of[sym["id"]]["symbols"][0]

    def _assigned(self, sym: dict[str, Any]) -> frozenset[str]:
        if sym["id"] not in self._locals:
            self._locals[sym["id"]] = frozenset(t[2:] for t, _ in sym["assigns"] if t.startswith("v:"))
        return self._locals[sym["id"]]

    def _is_self(self, sym: dict[str, Any], name: str) -> bool:
        return (sym["kind"] == METHOD and "staticmethod" not in sym["decorators"]
                and bool(sym["params"]) and sym["params"][0] == name)

    def _name(self, sym: dict[str, Any], name: str) -> tuple[str | None, Any]:
        """What a bare name means inside a symbol, by Python's scoping."""
        key = (sym["id"], name)
        if key not in self._names:
            self._names[key] = self._name_uncached(sym, name)
        return self._names[key]

    def _name_uncached(self, sym: dict[str, Any], name: str) -> tuple[str | None, Any]:
        if name in sym["params"]:
            return "param", name
        if name in self._assigned(sym):
            return "local", name
        scope: dict[str, Any] | None = sym
        while scope is not None:
            # A class body's names are not visible from its methods.
            if name in scope["defs"] and (scope is sym or scope["kind"] != CLASS):
                return "def", symbol_id(self.file_of[sym["id"]]["path"], scope["defs"][name])
            if scope is not sym and scope["kind"] in (FUNCTION, METHOD) \
                    and (name in scope["params"] or name in self._assigned(scope)):
                return "closure", name
            scope = self._sibling(scope, scope["parent"])
        module = self._module(sym)
        if name in self._assigned(module):
            return "global", name
        file = self.file_of[sym["id"]]
        if name in file["imports"]:
            return "import", file["imports"][name]
        for star in file["star_imports"]:
            found = self._lookup(star.split(".") + [name])
            if found[0] == "symbol":
                return "def", found[1]
        if name in _BUILTINS:
            return "builtin", name
        return None, name

    def _lookup(self, parts: list[str], depth: int = 0) -> Ref:
        """A dotted name to a symbol of the repository, a library name, or unknown."""
        for size in range(len(parts), 0, -1):
            module = ".".join(parts[:size])
            if module in self.modules:
                rest = parts[size:]
                return self._in_module(self.modules[module], rest, depth) if rest else ("module", module)
        dotted = ".".join(parts)
        # A module of this repository that is not among the files in view.
        return ("unknown", dotted) if parts[0] in self.top_packages else ("external", dotted)

    def _in_module(self, file: dict[str, Any], rest: list[str], depth: int) -> Ref:
        module = file["symbols"][0]
        name = rest[0]
        if name in module["defs"]:
            found = self._descend(symbol_id(file["path"], module["defs"][name]), rest[1:])
            return found or ("unknown", ".".join([file["module"], *rest]))
        if depth < 5:
            if name in file["imports"]:
                return self._lookup(file["imports"][name].split(".") + rest[1:], depth + 1)
            for star in file["star_imports"]:
                found = self._lookup(star.split(".") + rest, depth + 1)
                if found[0] == "symbol":
                    return found
        if name in self._assigned(module):
            return "var", (module["id"], name)
        return "unknown", ".".join([file["module"], *rest])

    def _descend(self, sid: str, rest: list[str]) -> Ref | None:
        """``Class.method`` or ``Outer.Inner.method`` below a module-level definition."""
        for index, part in enumerate(rest):
            if self.symbols[sid]["kind"] != CLASS:
                return None
            found = self._member(sid, part)
            if found is None or found[0] != "symbol":
                return found if index == len(rest) - 1 else None
            sid = found[1]
        return "symbol", sid

    def _class_ref(self, sym: dict[str, Any], parts: list[str]) -> Ref | None:
        """The class a dotted name written in ``sym`` refers to, if it is one."""
        kind, value = self._name(sym, parts[0])
        if kind == "def":
            found = self._descend(value, parts[1:])
        elif kind == "import":
            found = self._lookup(value.split(".") + parts[1:])
        else:
            return None
        if found and found[0] == "symbol":
            return found if self.symbols[found[1]]["kind"] == CLASS else None
        return found if found and found[0] == "external" else None

    def _member(self, class_id: str, name: str, seen: frozenset[str] = frozenset()) -> Ref | None:
        """A method of a class or of the bases that can be resolved."""
        cls = self.symbols[class_id]
        if name in cls["defs"]:
            return "symbol", symbol_id(self.file_of[class_id]["path"], cls["defs"][name])
        if name in self._assigned(cls):
            return None                          # an attribute holding something, not a method in view
        external = None
        for base in cls["bases"]:
            ref = self._class_ref(cls, base.split("."))
            if ref and ref[0] == "symbol" and ref[1] not in seen and ref[1] != class_id:
                found = self._member(ref[1], name, seen | {class_id})
                if found and found[0] == "symbol":
                    return found
                external = external or found
            elif ref and ref[0] == "external":
                external = external or ("external", f"{ref[1]}.{name}")
        return external

    # --- the class of a receiver ---

    def _constructed(self, sym: dict[str, Any], assignments: list[list[str]]) -> Ref | None:
        """The one class all assignments construct, else None."""
        classes = set()
        for atoms in assignments:
            if len(atoms) != 1 or not atoms[0].startswith("c:"):
                return None
            target = self._resolve(sym, int(atoms[0][2:]))
            if target.cls:
                classes.add(("symbol", target.cls))
            elif target.node.startswith("ext::") and target.name.split(".")[-1][:1].isupper():
                classes.add(("external", target.name))      # a capitalised library callable: a class
            else:
                return None
        return classes.pop() if len(classes) == 1 else None

    def _variable_class(self, sym: dict[str, Any], name: str) -> Ref | None:
        key = (sym["id"], name)
        if key in self._typing:
            return None
        self._typing.add(key)
        try:
            return self._constructed(sym, [atoms for target, atoms in sym["assigns"] if target == f"v:{name}"])
        finally:
            self._typing.discard(key)

    def _attribute_class(self, class_id: str, attr: str) -> Ref | None:
        key = (class_id, f".{attr}")
        if key in self._typing:
            return None
        self._typing.add(key)
        try:
            cls = self.symbols[class_id]
            found = set()
            if attr in self._assigned(cls):
                found.add(self._variable_class(cls, attr))
            for qualname in cls["defs"].values():
                method = self._sibling(cls, qualname)
                if method is None or method["kind"] != METHOD or not method["params"]:
                    continue
                written = [atoms for target, atoms in method["assigns"]
                           if target == f"a:{method['params'][0]}.{attr}"]
                if written:
                    found.add(self._constructed(method, written))
            return found.pop() if len(found) == 1 else None
        finally:
            self._typing.discard(key)

    def _receiver_class(self, sym: dict[str, Any], chain: list[str]) -> Ref | None:
        """The class of ``chain[:-1]``, the object a method is called on."""
        root = chain[0]
        kind, _ = self._name(sym, root)
        ref: Ref | None = None
        if kind == "param":
            if self._is_self(sym, root):
                ref = ("symbol", symbol_id(self.file_of[sym["id"]]["path"], sym["cls"]))
            elif root in sym["annotations"]:
                ref = self._class_ref(sym, sym["annotations"][root].split("."))
        elif kind == "local":
            ref = self._variable_class(sym, root)
        elif kind == "global":
            ref = self._variable_class(self._module(sym), root)
        for attr in chain[1:-1]:
            if ref is None or ref[0] != "symbol":
                return None
            ref = self._attribute_class(ref[1], attr)
        return ref

    # --- calls ---

    def _resolve(self, sym: dict[str, Any], index: int) -> Target:
        key = (sym["id"], index)
        if key not in self._targets:
            self._targets[key] = self._resolve_uncached(sym, sym["calls"][index])
        return self._targets[key]

    def _unknown(self, call: dict[str, Any]) -> Target:
        return Target(f"unknown::{call['text']}", UNRESOLVED, call["text"], method=call["attr"])

    def _target(self, ref: Ref | None, resolution: str, call: dict[str, Any], on_instance: bool) -> Target:
        if ref is None or ref[0] not in ("symbol", "external"):
            return self._unknown(call)
        if ref[0] == "external":
            return Target(f"ext::{ref[1]}", resolution, ref[1], method=call["attr"] if on_instance else None)
        callee = self.symbols[ref[1]]
        if callee["kind"] == MODULE:
            return self._unknown(call)
        if callee["kind"] == CLASS:
            init = self._member(ref[1], "__init__")
            init_id = init[1] if init and init[0] == "symbol" else None
            return Target(init_id or ref[1], resolution, callee["qualname"], symbol=init_id, cls=ref[1], bound=True)
        bound = (callee["kind"] == METHOD and "staticmethod" not in callee["decorators"]
                 and (on_instance or "classmethod" in callee["decorators"]))
        return Target(ref[1], resolution, callee["qualname"], symbol=ref[1], bound=bound)

    def _resolve_uncached(self, sym: dict[str, Any], call: dict[str, Any]) -> Target:
        chain = call["chain"]
        if not chain:
            return self._unknown(call)
        root, rest = chain[0], chain[1:]
        path = self.file_of[sym["id"]]["path"]
        if root == "super()":
            if not sym["cls"] or len(rest) != 1:
                return self._unknown(call)
            own = symbol_id(path, sym["cls"])
            found = None
            for base in self.symbols[own]["bases"]:
                ref = self._class_ref(self.symbols[own], base.split("."))
                if ref and ref[0] == "symbol":
                    found = found or self._member(ref[1], rest[0], frozenset({own}))
                elif ref and ref[0] == "external":
                    found = found or ("external", f"{ref[1]}.{rest[0]}")
            return self._target(found, ATTRIBUTE, call, on_instance=True)
        kind, value = self._name(sym, root)
        if kind == "import":
            return self._target(self._lookup(value.split(".") + rest), IMPORT, call, on_instance=False)
        if kind == "builtin":
            dotted = ".".join(["builtins", *chain])
            return Target(f"ext::{dotted}", BUILTIN, dotted)
        if kind == "def":
            found = self._descend(value, rest)
            same_file = self.file_of[value]["path"] == path
            how = ATTRIBUTE if rest else SAME_MODULE if same_file else IMPORT
            return self._target(found, how, call, on_instance=False)
        if not rest:
            if kind == "param" and self._is_self(sym, root) and "classmethod" in sym["decorators"]:
                return self._target(("symbol", symbol_id(path, sym["cls"])), ATTRIBUTE, call, on_instance=False)
            return self._unknown(call)           # a callable held in a variable
        owner_class = self._receiver_class(sym, chain)
        if owner_class is None:
            return self._unknown(call)
        if owner_class[0] == "external":
            return self._target(("external", f"{owner_class[1]}.{rest[-1]}"), ATTRIBUTE, call, on_instance=True)
        return self._target(self._member(owner_class[1], rest[-1]), ATTRIBUTE, call, on_instance=True)

    def _source(self, dotted: str) -> tuple[str, str] | None:
        found = self.catalog.source_kind(dotted)
        allowed = self.config.source_kinds
        return found if found and (allowed is None or found[1] in allowed) else None

    def _role(self, target: Target, call: dict[str, Any]) -> Role:
        """Whether a callee is a sink, a source or a sanitizer."""
        catalog = self.catalog
        if target.cls:
            return Role()
        if target.symbol:
            name = self.symbols[target.symbol]["qualname"].split(".")[-1]
            return Role(sanitizer="validator" if is_validator_name(name) else None)
        method = target.method
        if target.node.startswith("ext::"):
            sink = catalog.sinks.get(target.name)
            source = self._source(target.name)
            if sink or source or target.name in catalog.sanitizers:
                return Role(sink=(target.name, sink) if sink else None, source=source,
                            sanitizer=None if sink else "library" if target.name in catalog.sanitizers else None)
            if method is None:
                return Role()
        # From here on only the method name is known.
        last = method or target.name.split(".")[-1]
        sink = catalog.sink_methods.get(method) if method else None
        kind = catalog.source_methods.get(method) if method else None
        allowed = self.config.source_kinds
        source = (f".{method}", kind) if kind and (allowed is None or kind in allowed) else None
        unresolved = target.resolution == UNRESOLVED
        return Role(sink=(f".{method}", sink) if sink else None, source=source,
                    sanitizer="validator" if not sink and unresolved and is_validator_name(last) else None)

    # --- nodes ---

    def _node(self, node: str, **attrs: Any) -> str:
        if node not in self.graph:
            self.graph.add_node(node, **attrs)
        return node

    def _port(self, sid: str, name: str) -> str:
        return self._node(f"{sid}#{name}", kind=PORT, symbol=sid, port=name)

    def _attr_home(self, class_id: str) -> str:
        """The class an attribute is filed under: the top of the first-base chain.

        A base class reads ``self.x`` and a subclass sets it, or the other way
        round; filing both under one class keeps that flow in the graph.
        """
        if class_id not in self._homes:
            seen, home = {class_id}, class_id
            while True:
                cls = self.symbols[home]
                refs = (self._class_ref(cls, base.split(".")) for base in cls["bases"])
                above = next((ref[1] for ref in refs if ref and ref[0] == "symbol"), None)
                if above is None or above in seen:
                    break
                seen.add(above)
                home = above
            self._homes[class_id] = home
        return self._homes[class_id]

    def _attr_port(self, class_id: str, name: str) -> str:
        home = self._attr_home(class_id)
        return self._node(f"{home}#attr:{name}", kind=PORT, symbol=home, port=f"attr:{name}")

    def _var_port(self, module_id: str, name: str) -> str:
        return self._node(f"{module_id}#var:{name}", kind=PORT, symbol=module_id, port=f"var:{name}")

    def _source_site(self, sid: str, name: str, kind: str) -> str:
        return self._node(f"src@{sid}::{name}", kind=SOURCE, symbol=sid, api=name, source=kind)

    # --- flows inside one symbol ---

    def _origin(self, sym: dict[str, Any], atom: str, local: dict[str, set[str]],
                results: list[set[str]]) -> set[str]:
        """The nodes an atom's value may come from."""
        if atom[0] == "c":
            return results[int(atom[2:])]
        parts = atom[2:].split(".")
        root = parts[0]
        sid = sym["id"]
        kind, value = self._name(sym, root)
        if kind == "param":
            if len(parts) > 1 and self._is_self(sym, root):
                return {self._attr_port(symbol_id(self.file_of[sid]["path"], sym["cls"]), parts[1])}
            return {self._port(sid, root)} | local.get(root, set())
        if kind == "local":
            return set(local.get(root, ()))
        if kind == "global":
            return {self._var_port(self._module(sym)["id"], root)}
        if kind == "def":
            if len(parts) > 1 and self.symbols[value]["kind"] == CLASS:
                return {self._attr_port(value, parts[1])}
            return set()
        if kind == "import":
            dotted = ".".join([value, *parts[1:]])
            source = self._source(dotted)
            if source:
                return {self._source_site(sid, *source)}
            found = self._lookup(dotted.split("."))
            if found[0] == "var":
                return {self._var_port(*found[1])}
        return set()

    def _flows(self, sym: dict[str, Any]) -> None:
        sid, calls = sym["id"], sym["calls"]
        targets = [self._resolve(sym, k) for k in range(len(calls))]
        roles = [self._role(targets[k], calls[k]) for k in range(len(calls))]
        local: dict[str, set[str]] = {}
        results: list[set[str]] = [set() for _ in calls]

        def origins(atoms: Iterable[str]) -> set[str]:
            found: set[str] = set()
            for atom in atoms:
                found |= self._origin(sym, atom, local, results)
            return found

        for _ in range(_MAX_ROUNDS):
            size = sum(map(len, local.values())) + sum(map(len, results))
            for target, atoms in sym["assigns"]:
                root = target[2:].split(".")[0]
                if target[0] == "a" and self._is_self(sym, root):
                    continue                      # an attribute of the object: a port, drawn below
                if target[0] == "v" or self._name(sym, root)[0] in ("param", "local"):
                    local.setdefault(root, set()).update(origins(atoms))
            for k, call in enumerate(calls):
                results[k] = self._result(sym, call, targets[k], roles[k], origins)
            if size == sum(map(len, local.values())) + sum(map(len, results)):
                break
        else:
            log.warning("graph: flows in %s did not settle in %d rounds", sid, _MAX_ROUNDS)

        def taint(sources: Iterable[str], node: str) -> None:
            for source in sorted(sources):
                if source != node:
                    add_edge(self.graph, source, node, TAINT, via=[sid])

        path = self.file_of[sid]["path"]
        for k, call in enumerate(calls):
            self._draw_call(sym, call, targets[k], roles[k], origins, taint)
        if sym["kind"] in (FUNCTION, METHOD) and sym["returns"]:
            taint(origins(sym["returns"]), self._port(sid, "return"))
        for target, atoms in sym["assigns"]:
            parts = target[2:].split(".")
            if target[0] == "a" and len(parts) > 1 and self._is_self(sym, parts[0]):
                taint(origins(atoms), self._attr_port(symbol_id(path, sym["cls"]), parts[1]))
            elif target[0] == "v" and sym["kind"] == CLASS:
                taint(origins(atoms), self._attr_port(sid, parts[0]))
            elif target[0] == "v" and sym["kind"] == MODULE:
                taint(origins(atoms), self._var_port(sid, parts[0]))
        if self.config.structural_guards:
            for guard in sym["guards"]:
                if origins(guard["atoms"]):
                    node = self._node(f"guard@{sid}::{guard['fingerprint']}", kind=GUARD, symbol=sid,
                                      text=guard["text"])
                    add_edge(self.graph, sid, node, SANITIZE, uses=[CHECK], lines=[guard["line"]])

    def _result(self, sym: dict[str, Any], call: dict[str, Any], target: Target, role: Role,
                origins: Callable[[Iterable[str]], set[str]]) -> set[str]:
        """Where the value of a call may come from."""
        if role.sanitizer:
            return {target.node}
        found = {self._source_site(sym["id"], *role.source)} if role.source else set()
        if target.symbol and not target.cls:
            return found | {self._port(target.symbol, "return")}
        # A library function, an unresolved callee, a sink or a constructor:
        # what comes out may carry whatever went in.
        passed = [a for group in call["args"] for a in group] + [a for group in call["kwargs"].values() for a in group]
        return found | origins(passed + call["star"] + call["receiver"])

    def _draw_call(self, sym: dict[str, Any], call: dict[str, Any], target: Target, role: Role,
                   origins: Callable[[Iterable[str]], set[str]], taint: Callable[[Iterable[str], str], None]) -> None:
        sid, line = sym["id"], call["line"]
        if target.node.startswith("ext::"):
            self._node(target.node, kind=EXTERNAL, name=target.name)
        elif target.resolution == UNRESOLVED:
            self._node(target.node, kind=UNKNOWN, name=target.name)
            self.unknown_by_file[self.file_of[sid]["path"]] += 1
        add_edge(self.graph, sid, target.node, CALL, resolution=target.resolution, lines=[line])
        self.calls[target.resolution] += 1

        positional = [origins(group) for group in call["args"]]
        keywords = {name: origins(group) for name, group in call["kwargs"].items()}
        star, receiver = origins(call["star"]), origins(call["receiver"])
        if role.sink:
            name, sink = role.sink
            reach = set(star)
            for index, got in enumerate(positional):
                if sink.args is None or index in sink.args:
                    reach |= got
            for keyword, got in keywords.items():
                if sink.args is None or keyword in sink.kwargs:
                    reach |= got
            if sink.receiver:
                reach |= receiver
            taint(reach, self._node(f"sink@{sid}::{name}", kind=SINK, symbol=sid, api=name, sink=sink.family))
        if role.sanitizer:
            self.graph.nodes[target.node]["sanitizer"] = role.sanitizer
            add_edge(self.graph, sid, target.node, SANITIZE,
                     uses=[TRANSFORM if call["use"] == "value" else CHECK], lines=[line])
            taint(set().union(star, receiver, *positional, *keywords.values()), target.node)
        elif target.symbol:
            callee = self.symbols[target.symbol]
            params = list(callee["params"])
            if target.bound and params:
                first = params.pop(0)
                if not target.cls:
                    taint(receiver, self._port(target.symbol, first))
            named = [p for p in params if p not in (callee["vararg"], callee["kwarg"])]
            by_position = [p for p in named if p not in callee["keyword_only"]]
            for index, got in enumerate(positional):
                param = by_position[index] if index < len(by_position) else callee["vararg"]
                if param:
                    taint(got, self._port(target.symbol, param))
            for keyword, got in keywords.items():
                param = keyword if keyword in named else callee["kwarg"]
                if param:
                    taint(got, self._port(target.symbol, param))
            for param in params if star else ():
                taint(star, self._port(target.symbol, param))     # an unpacked argument may land anywhere

    # --- parameters that are sources ---

    def _parameter_sources(self, sym: dict[str, Any]) -> None:
        sid = sym["id"]
        allowed = self.config.source_kinds
        own = sym["params"][1:] if self._is_self(sym, sym["params"][0] if sym["params"] else "") else sym["params"]
        if allowed is None or REQUEST in allowed:
            if any(self._is_route(sym, decorator) for decorator in sym["decorators"]):
                for param in own:
                    self.graph.nodes[self._port(sid, param)]["source"] = REQUEST
            for param, annotation in sym["annotations"].items():
                ref = self._class_ref(sym, annotation.split("."))
                if ref and ref[0] == "external" and ref[1] in self.catalog.request_classes:
                    self.graph.nodes[self._port(sid, param)]["source"] = REQUEST
        if self.config.public_api_sources and self._is_public(sym):
            for param in own:
                self.graph.nodes[self._port(sid, param)].setdefault("source", PUBLIC_API)

    def _is_route(self, sym: dict[str, Any], decorator: str) -> bool:
        called = decorator.endswith("()")
        parts = decorator.removesuffix("()").split(".")
        kind, value = self._name(self._module(sym), parts[0])
        dotted = ".".join([value, *parts[1:]]) if kind == "import" else None
        return dotted in self.catalog.route_decorators or (
            called and len(parts) > 1 and parts[-1] in self.catalog.route_decorator_methods)

    def _is_public(self, sym: dict[str, Any]) -> bool:
        """A function a user of the library can call: no private name on the way to it."""
        if is_test_path(self.file_of[sym["id"]]["path"]):
            return False
        scope: dict[str, Any] | None = self._sibling(sym, sym["parent"])
        while scope is not None:
            if scope["kind"] in (FUNCTION, METHOD):
                return False                     # defined inside a function
            scope = self._sibling(scope, scope["parent"])
        return all(not part.startswith("_") or (part.startswith("__") and part.endswith("__"))
                   for part in sym["qualname"].split("."))
