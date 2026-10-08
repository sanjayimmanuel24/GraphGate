"""One Python file to plain facts, with tree-sitter (BUILD_PLAN 4.1).

``extract`` reads a file's text and returns everything the graph needs from it
as JSON-ready dicts: its symbols, its imports and, per symbol, what the code
calls, assigns and returns. Nothing here looks at another file, so the facts of
a file can be stored and reused until the file changes (4.4); resolving names
across files is the linker's job.

Data flow inside a symbol is recorded without evaluating it. An expression is
reduced to the *atoms* its value may come from:

- ``v:name``      a name (a parameter, a local, a global, an import);
- ``a:x.y.z``     an attribute chain that starts at a name;
- ``c:3``         the result of the symbol's fourth call.

An assignment is a target atom with the atoms of its right-hand side. Order
and branches are ignored: propagation is flow-insensitive (CLAUDE.md, E_taint).

What is not followed, by design (proposal 5.3): values captured from an
enclosing function, properties, ``getattr`` with a computed name, decorators
that replace a function. A call the linker cannot resolve stays in the facts
and becomes an explicit unknown edge.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

import tree_sitter_python as tsp
from tree_sitter import Language, Node, Parser

from graphgate.graph.model import CLASS, FUNCTION, METHOD, MODULE, MODULE_QUALNAME, symbol_id

FACTS_VERSION = 2

_PARSER = Parser(Language(tsp.language()))

_DEFS = frozenset({"function_definition", "class_definition", "decorated_definition"})
_LITERALS = frozenset({"integer", "float", "true", "false", "none", "ellipsis", "comment", "type"})
_COMPREHENSIONS = frozenset({"list_comprehension", "set_comprehension", "dictionary_comprehension",
                             "generator_expression"})
_SKIPPED = frozenset({"import_statement", "import_from_statement", "future_import_statement", "pass_statement",
                      "break_statement", "continue_statement", "global_statement", "nonlocal_statement",
                      "comment"})
# Calls that put their arguments into the object they are called on.
MUTATORS = frozenset({"append", "extend", "add", "update", "insert", "setdefault", "appendleft", "extendleft"})
# A branch that ends in one of these calls rejects the value it tested.
_EXIT_CALLS = frozenset({"exit", "_exit", "abort", "quit"})


def module_name(path: str) -> tuple[str, bool]:
    """Dotted module name of a repository path, and whether it is a package."""
    parts = path[:-3].split("/") if path.endswith(".py") else path.split("/")
    if parts and parts[0] == "src" and len(parts) > 1:
        parts = parts[1:]
    is_package = parts[-1] == "__init__"
    return ".".join(parts[:-1] if is_package else parts), is_package


def extract(path: str, text: str) -> dict[str, Any]:
    """Facts of the file at repository path ``path`` (POSIX, relative)."""
    root = _PARSER.parse(text.encode("utf-8")).root_node
    module, is_package = module_name(path)
    imports, stars = _imports(root, module, is_package)
    symbols = []
    todo: list[tuple[Node, str, str, str | None, str | None]] = [(root, MODULE, MODULE_QUALNAME, None, None)]
    while todo:
        node, kind, qualname, parent, cls = todo.pop(0)
        scope = _Scope(path, node, kind, qualname, parent, cls)
        symbols.append(scope.build())
        todo.extend(scope.nested)
    return {
        "version": FACTS_VERSION,
        "path": path,
        "module": module,
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "parse_error": root.has_error,
        "imports": imports,
        "star_imports": stars,
        "symbols": symbols,
    }


def _text(node: Node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _definition(node: Node) -> Node:
    return node.child_by_field_name("definition") if node.type == "decorated_definition" else node


def _imports(root: Node, module: str, is_package: bool) -> tuple[dict[str, str], list[str]]:
    """Local name to the dotted name it stands for, from every import in the file."""
    package = module.split(".") if is_package else module.split(".")[:-1]
    names: dict[str, str] = {}
    stars: list[str] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "import_statement":
            for item in node.named_children:
                if item.type == "aliased_import":
                    names[_text(item.child_by_field_name("alias"))] = _text(item.child_by_field_name("name"))
                elif item.type == "dotted_name":
                    top = _text(item).split(".")[0]
                    names[top] = top                 # "import a.b" binds "a"
        elif node.type == "import_from_statement":
            source = node.child_by_field_name("module_name")
            base = _from_base(source, package)
            for item in node.named_children:
                if item == source:
                    continue
                if item.type == "wildcard_import":
                    stars.append(base)
                elif item.type == "aliased_import":
                    name = _text(item.child_by_field_name("name"))
                    names[_text(item.child_by_field_name("alias"))] = f"{base}.{name}" if base else name
                elif item.type == "dotted_name":
                    name = _text(item)
                    names[name] = f"{base}.{name}" if base else name
        else:
            stack.extend(node.children)
    return dict(sorted(names.items())), sorted(stars)


def _from_base(source: Node, package: list[str]) -> str:
    if source.type != "relative_import":
        return _text(source)
    dots = sum(_text(c).count(".") for c in source.children if c.type == "import_prefix")
    tail = [_text(c) for c in source.named_children if c.type == "dotted_name"]
    base = package[:len(package) - (dots - 1)] if dots > 1 else list(package)
    return ".".join(base + tail)


def _chain(node: Node) -> list[str] | None:
    """``a.b.c`` as ``["a", "b", "c"]``; None unless the chain starts at a name."""
    if node.type == "identifier":
        return [_text(node)]
    if node.type == "attribute":
        head = _chain(node.child_by_field_name("object"))
        return None if head is None else head + [_text(node.child_by_field_name("attribute"))]
    if node.type == "call" and _text(node).replace(" ", "") == "super()":
        return ["super()"]
    return None


def _is_bare_string(node: Node) -> bool:
    return (node.type == "expression_statement" and len(node.named_children) == 1
            and node.named_children[0].type in ("string", "concatenated_string"))


def _own_tokens(node: Node, own: tuple[Node, ...]) -> list[str]:
    """Leaf tokens of a symbol's own code: no comments, docstrings or nested definitions.

    ``own`` holds the symbol's own definition node (and its decorated wrapper),
    which are definitions too but must not be skipped.
    """
    if node.type == "comment" or _is_bare_string(node) or (node.type in _DEFS and node not in own):
        return []
    if node.child_count == 0:
        return [_text(node)]
    return [token for child in node.children for token in _own_tokens(child, own)]


def _annotation(node: Node | None) -> str | None:
    """The class an annotation names, when it is a plain or Optional dotted name."""
    if node is None:
        return None
    text = _text(node).strip().strip("\"'").replace(" ", "")
    text = re.sub(r"^(?:typing\.)?Optional\[(.*)\]$", r"\1", text)
    text = re.sub(r"\|None$|^None\|", "", text)
    return text if re.fullmatch(r"[A-Za-z_][\w.]*", text) else None


class _Scope:
    """Collects the facts of one symbol: a module, a class or a function."""

    def __init__(self, path: str, node: Node, kind: str, qualname: str, parent: str | None, cls: str | None):
        self.path, self.kind, self.qualname, self.parent, self.cls = path, kind, qualname, parent, cls
        self.outer = node                       # with decorators, for the digest and the line span
        self.node = _definition(node) if kind != MODULE else node
        self.nested: list[tuple[Node, str, str, str | None, str | None]] = []
        self.defs: dict[str, str] = {}
        self.assigns: list[list[Any]] = []
        self.returns: set[str] = set()
        self.calls: list[dict[str, Any] | None] = []
        self.guards: list[dict[str, Any]] = []
        self._mentioned: set[str] | None = None  # while a guard's test is read: every atom in it

    def build(self) -> dict[str, Any]:
        params, annotations, vararg, kwarg, keyword_only = self._parameters()
        body = self.node if self.kind == MODULE else self.node.child_by_field_name("body")
        for statement in body.named_children:
            self._statement(statement)
        local = set(params) | {t[2:] for t, _ in self.assigns if t.startswith("v:")}
        tokens = _own_tokens(self.outer, (self.outer, self.node))
        return {
            "id": symbol_id(self.path, self.qualname),
            "qualname": self.qualname,
            "kind": self.kind,
            "parent": self.parent,
            "cls": self.cls,
            "line": self.outer.start_point.row + 1,
            "end_line": self.outer.end_point.row + 1,
            "digest": hashlib.sha256("\x00".join(tokens).encode("utf-8")).hexdigest()[:16],
            "params": params,
            "annotations": annotations,
            "vararg": vararg,
            "kwarg": kwarg,
            "keyword_only": keyword_only,
            "decorators": self._decorators(),
            "bases": self._bases(),
            "defs": dict(sorted(self.defs.items())),
            "assigns": self.assigns,
            "returns": sorted(self.returns),
            "calls": self.calls,
            "guards": [self._finish_guard(g, local) for g in self.guards],
        }

    # --- the definition's header ---

    def _parameters(self) -> tuple[list[str], dict[str, str], str | None, str | None, list[str]]:
        params: list[str] = []
        annotations: dict[str, str] = {}
        keyword_only: list[str] = []         # after "*" or "*args": never filled by position
        vararg = kwarg = None
        after_star = False
        holder = self.node.child_by_field_name("parameters") if self.node.type == "function_definition" else None
        for child in holder.named_children if holder is not None else ():
            inner = child
            if child.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
                inner = child.child_by_field_name("name") or child.named_children[0]
                annotated = _annotation(child.child_by_field_name("type"))
                if annotated:
                    annotations[_text(inner).lstrip("*")] = annotated
            if inner.type == "keyword_separator":
                after_star = True
            elif inner.type == "list_splat_pattern":
                vararg = _text(inner).lstrip("*")
                params.append(vararg)
                after_star = True
            elif inner.type == "dictionary_splat_pattern":
                kwarg = _text(inner).lstrip("*")
                params.append(kwarg)
            elif inner.type == "identifier":
                params.append(_text(inner))
                if after_star:
                    keyword_only.append(_text(inner))
        return params, annotations, vararg, kwarg, keyword_only

    def _decorators(self) -> list[str]:
        names = []
        for child in self.outer.children if self.outer.type == "decorated_definition" else ():
            if child.type == "decorator" and child.named_children:
                target = child.named_children[0]
                called = target.type == "call"
                chain = _chain(target.child_by_field_name("function") if called else target)
                if chain:
                    names.append(".".join(chain) + ("()" if called else ""))
        return names

    def _bases(self) -> list[str]:
        holder = self.node.child_by_field_name("superclasses") if self.node.type == "class_definition" else None
        chains = (_chain(c) for c in holder.named_children) if holder is not None else ()
        return [".".join(chain) for chain in chains if chain]

    # --- statements ---

    def _statement(self, node: Node) -> None:
        kind = node.type
        if kind in _SKIPPED:
            return
        if kind in _DEFS:
            self._nested_definition(node)
        elif kind == "expression_statement":
            for child in node.named_children:
                self._expression_statement(child)
        elif kind == "return_statement":
            for child in node.named_children:
                self.returns |= self._atoms(child)
        elif kind in ("if_statement", "elif_clause"):
            self._if(node)
        elif kind == "while_statement":
            self._atoms(node.child_by_field_name("condition"), cond=True)
            self._children(node, skip=node.child_by_field_name("condition"))
        elif kind == "assert_statement":
            tested = node.named_children[0]
            self._guard(tested, self._mentions(tested), "assert")
            for extra in node.named_children[1:]:
                self._atoms(extra)
        elif kind == "for_statement":
            self._assign(self._targets(node.child_by_field_name("left")),
                         self._atoms(node.child_by_field_name("right")))
            self._children(node, skip=node.child_by_field_name("left"), also=node.child_by_field_name("right"))
        elif kind == "with_item":
            value = node.child_by_field_name("value")
            if value.type == "as_pattern":
                alias = value.child_by_field_name("alias")
                self._assign(self._targets(alias) if alias is not None else [],
                             self._atoms(value.named_children[0]))
            else:
                self._atoms(value)
        else:
            self._children(node)

    def _children(self, node: Node, skip: Node | None = None, also: Node | None = None) -> None:
        """Visit the parts of a compound statement: statements as such, the rest as values."""
        for child in node.named_children:
            if child in (skip, also):
                continue
            if (child.type.endswith(("_statement", "_clause")) or child.type in _DEFS
                    or child.type in ("block", "with_item")):
                self._statement(child)
            else:
                self._atoms(child)

    def _nested_definition(self, node: Node) -> None:
        definition = _definition(node)
        name = _text(definition.child_by_field_name("name"))
        qualname = name if self.kind == MODULE else f"{self.qualname}.{name}"
        self.defs[name] = qualname
        if definition.type == "class_definition":
            self.nested.append((node, CLASS, qualname, self.qualname, None))
        else:
            kind = METHOD if self.kind == CLASS else FUNCTION
            self.nested.append((node, kind, qualname, self.qualname, self.qualname if kind == METHOD else None))

    def _expression_statement(self, node: Node) -> None:
        if node.type == "assignment":
            right = node.child_by_field_name("right")
            if right is None:
                return                          # a bare annotation: "x: int"
            values = self._assignment_value(right)
            self._assign(self._targets(node.child_by_field_name("left")), values)
        elif node.type == "augmented_assignment":
            left = node.child_by_field_name("left")
            self._assign(self._targets(left), self._atoms(left) | self._atoms(node.child_by_field_name("right")))
        elif node.type == "call":
            self._call(node, "stmt")
        elif node.type == "await" and node.named_children and node.named_children[0].type == "call":
            self._call(node.named_children[0], "stmt")
        else:
            self._atoms(node)

    def _assignment_value(self, right: Node) -> set[str]:
        if right.type != "assignment":
            return self._atoms(right)
        values = self._assignment_value(right.child_by_field_name("right"))     # a = b = value
        self._assign(self._targets(right.child_by_field_name("left")), values)
        return values

    def _if(self, node: Node) -> None:
        tested = node.child_by_field_name("condition")
        atoms = self._mentions(tested)
        consequence = node.child_by_field_name("consequence")
        alternatives = [c for c in node.children_by_field_name("alternative")]
        if _rejects(consequence):
            self._guard(tested, atoms, "if")
        elif any(a.type == "else_clause" and _rejects(a.child_by_field_name("body")) for a in alternatives):
            self._guard(tested, atoms, "unless")
        self._children(node, skip=tested)

    def _mentions(self, tested: Node) -> set[str]:
        """Every value a test looks at. Its own value is a truth value and carries none."""
        outer, self._mentioned = self._mentioned, set()
        self._atoms(tested, cond=True)
        mentioned, self._mentioned = self._mentioned, outer
        if outer is not None:
            outer |= mentioned
        return mentioned

    def _guard(self, tested: Node, atoms: set[str], how: str) -> None:
        self.guards.append({"how": how, "line": tested.start_point.row + 1, "atoms": sorted(atoms),
                            "tokens": _own_tokens(tested, (tested,))})

    def _finish_guard(self, guard: dict[str, Any], local: set[str]) -> dict[str, Any]:
        # Local names are blanked out, so renaming a variable does not make a
        # new guard; what the guard compares against stays.
        shape = " ".join("_" if token in local else token for token in guard.pop("tokens"))
        shape = f"{guard['how']} {shape}"
        return {**guard, "text": shape[:120], "fingerprint": hashlib.sha256(shape.encode("utf-8")).hexdigest()[:12]}

    # --- assignments ---

    def _targets(self, node: Node | None) -> list[str]:
        if node is None:
            return []
        if node.type == "identifier":
            return [f"v:{_text(node)}"]
        if node.type == "attribute":
            chain = _chain(node)
            return [f"a:{'.'.join(chain)}"] if chain else []
        if node.type == "subscript":
            for child in node.named_children[1:]:
                self._atoms(child)
            return self._targets(node.child_by_field_name("value"))
        return [target for child in node.named_children for target in self._targets(child)]

    def _assign(self, targets: list[str], atoms: set[str]) -> None:
        for target in targets:
            self.assigns.append([target, sorted(atoms)])

    # --- expressions ---

    def _atoms(self, node: Node | None, cond: bool = False) -> set[str]:
        """Where the value of an expression may come from; records the calls in it."""
        found = self._value(node, cond)
        if self._mentioned is not None:
            self._mentioned |= found
        return found

    def _value(self, node: Node | None, cond: bool) -> set[str]:
        if node is None or node.type in _LITERALS:
            return set()
        kind = node.type
        if kind == "identifier":
            return {f"v:{_text(node)}"}
        if kind == "attribute":
            chain = _chain(node)
            return {f"a:{'.'.join(chain)}"} if chain else self._atoms(node.child_by_field_name("object"))
        if kind == "call":
            return {f"c:{self._call(node, 'cond' if cond else 'value')}"}
        if kind == "subscript":
            for child in node.named_children[1:]:
                self._atoms(child)
            return self._atoms(node.child_by_field_name("value"))
        if kind in ("comparison_operator", "not_operator"):
            for child in node.named_children:
                self._atoms(child, cond)
            return set()                         # a truth value carries no data
        if kind in ("boolean_operator", "parenthesized_expression"):
            return self._union(node.named_children, cond)
        if kind == "conditional_expression":
            chosen, tested, otherwise = node.named_children[:3]
            self._atoms(tested, cond=True)
            return self._atoms(chosen) | self._atoms(otherwise)
        if kind == "named_expression":
            value = self._atoms(node.child_by_field_name("value"))
            self._assign(self._targets(node.child_by_field_name("name")), value)
            return value
        if kind == "lambda":
            self._atoms(node.child_by_field_name("body"))
            return set()
        if kind in _COMPREHENSIONS:
            for clause in node.named_children:
                if clause.type == "for_in_clause":
                    self._assign(self._targets(clause.child_by_field_name("left")),
                                 self._atoms(clause.child_by_field_name("right")))
                elif clause.type == "if_clause":
                    self._union(clause.named_children, cond=True)
            return self._atoms(node.child_by_field_name("body"))
        if kind == "yield":
            self.returns |= self._union(node.named_children)
            return set()
        if kind == "keyword_argument":
            return self._atoms(node.child_by_field_name("value"))
        return self._union(node.named_children)

    def _union(self, nodes: list[Node], cond: bool = False) -> set[str]:
        found: set[str] = set()
        for node in nodes:
            found |= self._atoms(node, cond)
        return found

    def _call(self, node: Node, use: str) -> int:
        index = len(self.calls)
        self.calls.append(None)                  # holds the place: calls inside the arguments come after
        function = node.child_by_field_name("function")
        chain = _chain(function)
        receiver: set[str] = set()
        if function.type == "attribute":
            receiver = self._atoms(function.child_by_field_name("object"))
        elif function.type != "identifier":
            self._atoms(function)
        positional: list[list[str]] = []
        keywords: dict[str, list[str]] = {}
        star: set[str] = set()
        arguments = node.child_by_field_name("arguments")
        if arguments is not None and arguments.type == "generator_expression":
            positional.append(sorted(self._atoms(arguments)))
        for argument in arguments.named_children if arguments is not None and arguments.type == "argument_list" else ():
            if argument.type == "keyword_argument":
                keywords[_text(argument.child_by_field_name("name"))] = sorted(self._atoms(argument))
            elif argument.type in ("list_splat", "dictionary_splat"):
                star |= self._union(argument.named_children)
            elif argument.type != "comment":
                positional.append(sorted(self._atoms(argument)))
        self.calls[index] = {
            "chain": chain,
            "attr": _text(function.child_by_field_name("attribute")) if function.type == "attribute" else None,
            "text": " ".join(_text(function).split())[:80],
            "line": node.start_point.row + 1,
            "args": positional,
            "kwargs": dict(sorted(keywords.items())),
            "star": sorted(star),
            "receiver": sorted(receiver),
            "use": use,
        }
        if chain and len(chain) >= 2 and chain[-1] in MUTATORS and chain[0] != "super()":
            holder = f"v:{chain[0]}" if len(chain) == 2 else f"a:{'.'.join(chain[:-1])}"
            self._assign([holder], {a for group in positional for a in group}
                         | {a for group in keywords.values() for a in group} | star)
        return index


def _rejects(block: Node | None) -> bool:
    """Whether a branch turns the value away: it raises, or calls an exit function."""
    for statement in block.named_children if block is not None else ():
        if statement.type == "raise_statement":
            return True
        calls = [c for c in statement.named_children if c.type == "call"] \
            if statement.type in ("expression_statement", "return_statement") else []
        for call in calls:
            name = _text(call.child_by_field_name("function")).split(".")[-1]
            if name in _EXIT_CALLS:
                return True
    return False
