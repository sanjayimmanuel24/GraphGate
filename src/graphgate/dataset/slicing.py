"""Trim a Python file down to named symbols (BUILD_PLAN 2.3).

An event's scenario is a *trimmed slice*: the files on the vulnerable flow, at
their real repository paths, cut down to the functions that matter. The
refinement model sees and rewrites whole files, so the files have to be small;
the gates analyse the same files, so the flow has to survive the cut.

Kept text is the original source, verbatim. What is kept:

- at module level: imports (including ``if``/``try`` blocks that only import,
  with fallback assignments), the module docstring, and the requested
  functions, classes and assignments;
- inside a partly kept class: the header, the docstring, every class-level
  assignment (attributes such as option lists are usually part of the flow),
  and the requested members.

Symbols are named ``name`` or ``Class.member`` (nesting allowed:
``Outer.Inner.method``). Naming a class keeps all of it.

Some flows run through module-level statements that are neither definitions
nor plain assignments: a parser grammar wired up with ``clause << ...``, or a
``with`` block that registers a handler as a callback. Adding the marker
``<wiring>`` to a file's symbols also keeps every such statement that refers to
a name the slice keeps. It is opt-in, so slices built without it never change.

Anything the kept code references but the cut removed is reported in
``dropped_references`` rather than silently lost (CLAUDE.md: no silent
fallbacks); whoever builds the slice decides whether to add it.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

import tree_sitter_python as tsp
from tree_sitter import Language, Node, Parser

_PARSER = Parser(Language(tsp.language()))

_IMPORTS = frozenset({"import_statement", "import_from_statement", "future_import_statement"})
_DEFINITIONS = frozenset({"function_definition", "class_definition"})
_CONDITIONAL = frozenset({"if_statement", "try_statement"})

# (first row, last row, blank lines to put before it when not adjacent)
Range = tuple[int, int, int]

# Opt-in marker: also keep module-level statements that refer to kept names.
WIRING = "<wiring>"


def parse(text: str) -> Node:
    return _PARSER.parse(text.encode("utf-8")).root_node


@dataclass
class TrimResult:
    text: str
    kept: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    dropped_references: list[str] = field(default_factory=list)
    syntax_error: str | None = None


def request_tree(symbols: list[str]) -> dict:
    """``["A.m", "A.n", "f"]`` → ``{"A": {"m": {}, "n": {}}, "f": {}}``.

    An empty dict means "keep all of it"; naming a whole class wins over
    naming some of its members.
    """
    tree: dict = {}
    for symbol in symbols:
        node = tree
        parts = symbol.split(".")
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                node[part] = {}
            elif part in node and node[part] == {}:
                break  # the whole of this scope is already requested
            else:
                node = node.setdefault(part, {})
    return tree


def trim(text: str, symbols: list[str]) -> TrimResult:
    """Keep ``symbols`` (and the module scaffolding) from ``text``."""
    root = parse(text)
    lines = text.splitlines(keepends=True)
    found: set[str] = set()
    wiring = WIRING in symbols
    symbols = [s for s in symbols if s != WIRING]
    ranges = _trim_scope(root, request_tree(symbols), "", found, module=True)
    if wiring:
        ranges = _add_wiring(root, ranges, {name.split(".")[0] for name in found})

    out: list[str] = []
    prev_end: int | None = None
    for start, end, gap in ranges:
        if prev_end is not None and start > prev_end + 1:
            out.append("\n" * gap)
        out.extend(lines[start:end + 1])
        prev_end = end
    trimmed = "".join(out)
    if trimmed and not trimmed.endswith("\n"):
        trimmed += "\n"

    result = TrimResult(text=trimmed, kept=sorted(found))
    result.missing = sorted(s for s in symbols if not _is_found(s, found))
    result.dropped_references = _dropped_references(root, trimmed)
    try:
        ast.parse(trimmed)
    except SyntaxError as exc:
        result.syntax_error = f"line {exc.lineno}: {exc.msg}"
    if result.syntax_error is None and parse(trimmed).has_error:
        result.syntax_error = "tree-sitter reports a parse error"
    return result


def _add_wiring(root: Node, ranges: list[Range], kept_names: set[str]) -> list[Range]:
    """Add module-level statements that refer to a kept name (see ``WIRING``).

    Definitions and imports are never added here: definitions are kept by
    name, imports always. What is left is the glue between kept symbols:
    expression statements, attribute assignments and ``with``/``if``/``for``
    blocks at module level.
    """
    covered = {row for start, end, _ in ranges for row in range(start, end + 1)}
    extra: list[Range] = []
    pending_comments: list[Node] = []
    last_statement_row = -1
    for child in root.named_children:
        if child.type == "comment":
            if child.start_point.row != last_statement_row:
                pending_comments.append(child)
            continue
        last_statement_row = child.end_point.row
        is_glue = (child.start_point.row not in covered and _definition(child) is None
                   and child.type not in _IMPORTS)
        if is_glue and kept_names & {n.text.decode() for n in _walk(child) if n.type == "identifier"}:
            start = child.start_point.row
            for comment in reversed(pending_comments):
                if comment.end_point.row != start - 1:
                    break
                start = comment.start_point.row
            extra.append((start, child.end_point.row, 1))
        pending_comments = []
    return sorted(ranges + extra)


def _is_found(symbol: str, found: set[str]) -> bool:
    parts = symbol.split(".")
    return any(".".join(parts[:i]) in found for i in range(len(parts), 0, -1))


def _definition(node: Node) -> Node | None:
    """The function/class a statement defines, looking through decorators."""
    if node.type in _DEFINITIONS:
        return node
    if node.type == "decorated_definition":
        return node.child_by_field_name("definition")
    return None


def _name(definition: Node) -> str:
    return definition.child_by_field_name("name").text.decode()


def _assigned_names(node: Node) -> list[str]:
    if node.type != "expression_statement" or not node.named_children:
        return []
    inner = node.named_children[0]
    if inner.type not in ("assignment", "augmented_assignment"):
        return []
    left = inner.child_by_field_name("left")
    if left is None:
        return []
    if left.type == "identifier":
        return [left.text.decode()]
    return [c.text.decode() for c in left.named_children if c.type == "identifier"]


def _is_docstring(node: Node, index: int) -> bool:
    return (index == 0 and node.type == "expression_statement"
            and len(node.named_children) == 1 and node.named_children[0].type == "string")


def _block_statements(node: Node) -> list[Node]:
    """Simple statements inside an ``if``/``try`` block, through its clauses."""
    found: list[Node] = []
    for child in node.named_children:
        if child.type == "block":
            for stmt in child.named_children:
                if stmt.type == "comment":
                    continue
                found.extend(_block_statements(stmt) if stmt.type in _CONDITIONAL else [stmt])
        elif child.type.endswith("_clause"):
            found.extend(_block_statements(child))
    return found


def _is_import_block(node: Node) -> bool:
    """``if TYPE_CHECKING: import …`` or ``try: import … except ImportError: x = None``."""
    stmts = _block_statements(node)
    return (any(s.type in _IMPORTS for s in stmts)
            and all(s.type in _IMPORTS or s.type == "pass_statement" or _assigned_names(s)
                    for s in stmts))


def _trim_scope(scope: Node, requests: dict, prefix: str, found: set[str], *, module: bool
                ) -> list[Range]:
    """Row ranges to keep from a module or class body."""
    ranges: list[Range] = []
    statements = [c for c in scope.named_children if c.type != "comment"]
    def_gap = 2 if module else 1
    pending_comments: list[Node] = []
    last_statement_row = -1
    for child in scope.named_children:
        if child.type == "comment":
            # A comment on the same row as a statement trails it: it is kept
            # or dropped with that statement, never pulled in on its own.
            if child.start_point.row != last_statement_row:
                pending_comments.append(child)
            continue
        last_statement_row = child.end_point.row
        keep: list[Range] = []
        definition = _definition(child)
        if definition is not None:
            name = _name(definition)
            if name in requests:
                qual = prefix + name
                sub = requests[name]
                if sub and definition.type == "class_definition":
                    keep = _partial_class(child, definition, sub, qual + ".", found, def_gap)
                else:
                    found.add(qual)
                    keep = [(child.start_point.row, child.end_point.row, def_gap)]
        elif child.type in _IMPORTS or _is_docstring(child, statements.index(child)):
            keep = [(child.start_point.row, child.end_point.row, 1)]
        elif module and child.type in _CONDITIONAL and _is_import_block(child):
            keep = [(child.start_point.row, child.end_point.row, 1)]
        else:
            names = _assigned_names(child)
            if names and (not module or any(n in requests for n in names)):
                found.update(prefix + n for n in names if n in requests)
                keep = [(child.start_point.row, child.end_point.row, 1)]
        if keep:
            # Comments directly above a kept statement (no blank line) go with it.
            start, end, gap = keep[0]
            for comment in reversed(pending_comments):
                if comment.end_point.row != start - 1:
                    break
                start = comment.start_point.row
            keep[0] = (start, end, gap)
            ranges.extend(keep)
        pending_comments = []
    return ranges


def _partial_class(stmt: Node, cls: Node, requests: dict, prefix: str, found: set[str],
                   gap: int) -> list[Range]:
    colon = next(c for c in cls.children if c.type == ":")
    header: Range = (stmt.start_point.row, colon.end_point.row, gap)
    inner = _trim_scope(cls.child_by_field_name("body"), requests, prefix, found, module=False)
    return [header] + [r for r in inner if r[0] > header[1]]


def _module_names(root: Node) -> set[str]:
    """Names bound at module level, including inside ``if``/``try`` blocks."""
    names: set[str] = set()
    for child in root.named_children:
        stmts = _block_statements(child) if child.type in _CONDITIONAL else [child]
        for stmt in stmts:
            definition = _definition(stmt)
            if definition is not None:
                names.add(_name(definition))
            names.update(_assigned_names(stmt))
    return names


def _class_members(root: Node) -> dict[str, set[str]]:
    """Top-level class name → names defined directly in its body."""
    members: dict[str, set[str]] = {}
    for child in root.named_children:
        definition = _definition(child)
        if definition is None or definition.type != "class_definition":
            continue
        names: set[str] = set()
        for stmt in definition.child_by_field_name("body").named_children:
            inner = _definition(stmt)
            if inner is not None:
                names.add(_name(inner))
            names.update(_assigned_names(stmt))
        members[_name(definition)] = names
    return members


def _walk(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _member_accesses(node: Node, own_class: str | None) -> set[tuple[str, str]]:
    """``(Class, member)`` for ``self.m`` / ``cls.m`` (own class) and ``Class.m``."""
    found: set[tuple[str, str]] = set()
    for n in _walk(node):
        if n.type != "attribute":
            continue
        obj, attr = n.child_by_field_name("object"), n.child_by_field_name("attribute")
        if obj is None or obj.type != "identifier":
            continue
        owner = own_class if obj.text in (b"self", b"cls") else obj.text.decode()
        if owner is not None:
            found.add((owner, attr.text.decode()))
    return found


def _dropped_references(original_root: Node, trimmed: str) -> list[str]:
    """Names the kept code uses that the original file defined but the cut removed."""
    if not trimmed:
        return []
    kept_root = parse(trimmed)
    identifiers = {n.text.decode() for n in _walk(kept_root) if n.type == "identifier"}
    dropped = set((_module_names(original_root) - _module_names(kept_root)) & identifiers)

    before, after = _class_members(original_root), _class_members(kept_root)
    accesses: set[tuple[str, str]] = set()
    for child in kept_root.named_children:
        definition = _definition(child)
        own = _name(definition) if definition is not None and definition.type == "class_definition" else None
        accesses |= _member_accesses(child, own)
    for owner, member in accesses:
        if owner in after and member in before.get(owner, set()) - after[owner]:
            dropped.add(f"{owner}.{member}")
    return sorted(dropped)
