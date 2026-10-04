"""Strip security-revealing comments from extracted code (BUILD_PLAN 2.3).

The refinement model sees every snapshot file verbatim, so a fix commit's
``# fix CVE-2023-…: sanitize input`` would tell it exactly what the injected
regression undoes (CLAUDE.md: no research framing in model-visible code).

Only comments and docstring paragraphs are removed, and every removal is
recorded so it can be reported. Code is never touched: identifiers, string
literals and log messages are the program's real behaviour. String literals
that match are listed in ``flagged_strings`` for the human reviewer instead.

The same function runs on the clean and the regressed slice, so identical
text is scrubbed identically and the regression diff stays minimal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tree_sitter import Node

from graphgate.dataset.slicing import parse

# Words that describe a vulnerability or its fix rather than what code does.
# Deliberately broad: removing a neutral comment costs nothing, leaving a
# revealing one in front of the model biases the trace.
REVEALING = re.compile(
    r"\bCVE-\d|\bGHSA-|\bCWE-?\d|\bhuntr\b|bug.?bounty|vulnerab|exploit|\battack|"
    r"malicious|\bsecurity\b|\binject|travers|\bRCE\b|arbitrary (?:file|code|command|path)|"
    r"\badvisor(?:y|ies)\b|\bPoC\b|\bpentest|\bCVSS\b|\bsecurely\b|\binsecure",
    re.IGNORECASE,
)

_STRING = re.compile(r'(?s)^([rRbBuUfF]*)("""|\'\'\'|"|\')(.*)\2$')


@dataclass
class ScrubResult:
    text: str
    removed: list[dict] = field(default_factory=list)
    flagged_strings: list[dict] = field(default_factory=list)


def scrub(text: str) -> ScrubResult:
    root = parse(text)
    data = text.encode("utf-8")
    edits: list[tuple[int, int, bytes]] = []  # (start byte, end byte, replacement)
    result = ScrubResult(text=text)
    docstrings = {id_(n) for n in _docstrings(root)}

    for node in _walk(root):
        if node.type == "comment" and REVEALING.search(node.text.decode("utf-8", "replace")):
            result.removed.append(_record(node, "comment"))
            edits.append(_comment_edit(data, node))
        elif node.type == "string" and id_(node) in docstrings:
            edit = _docstring_edit(data, node, result)
            if edit:
                edits.append(edit)
        elif node.type == "string" and node.parent is not None and node.parent.type != "string":
            if REVEALING.search(node.text.decode("utf-8", "replace")):
                result.flagged_strings.append(_record(node, "string"))

    for start, end, replacement in sorted(edits, reverse=True):
        data = data[:start] + replacement + data[end:]
    result.text = data.decode("utf-8")
    result.removed.sort(key=lambda r: r["line"])
    result.flagged_strings.sort(key=lambda r: r["line"])
    return result


def id_(node: Node) -> tuple[int, int]:
    return (node.start_byte, node.end_byte)


def _walk(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _record(node: Node, kind: str) -> dict:
    return {"line": node.start_point.row + 1, "kind": kind,
            "text": node.text.decode("utf-8", "replace")}


def _docstrings(root: Node) -> list[Node]:
    """String nodes that are the first statement of a module, class or function."""
    found = []
    bodies = [root] + [n.child_by_field_name("body") for n in _walk(root)
                       if n.type in ("function_definition", "class_definition")]
    for body in bodies:
        if body is None:
            continue
        stmts = [c for c in body.named_children if c.type != "comment"]
        if (stmts and stmts[0].type == "expression_statement"
                and len(stmts[0].named_children) == 1 and stmts[0].named_children[0].type == "string"):
            found.append(stmts[0].named_children[0])
    return found


def _line_bounds(data: bytes, start: int, end: int) -> tuple[int, int]:
    line_start = data.rfind(b"\n", 0, start) + 1
    line_end = data.find(b"\n", end)
    return line_start, (len(data) if line_end == -1 else line_end + 1)


def _comment_edit(data: bytes, node: Node) -> tuple[int, int, bytes]:
    line_start, line_end = _line_bounds(data, node.start_byte, node.end_byte)
    if not data[line_start:node.start_byte].strip():
        return line_start, line_end, b""  # the comment is the whole line
    # A trailing comment: drop it and the whitespace before it.
    start = node.start_byte
    while start > line_start and data[start - 1:start] in (b" ", b"\t"):
        start -= 1
    return start, node.end_byte, b""


def _docstring_edit(data: bytes, node: Node, result: ScrubResult) -> tuple[int, int, bytes] | None:
    raw = node.text.decode("utf-8")
    m = _STRING.match(raw)
    if not m or not REVEALING.search(m[3]):
        return None
    prefix, quote, inner = m[1], m[2], m[3]
    lead = inner[:len(inner) - len(inner.lstrip())]
    trail = inner[len(inner.rstrip()):]
    paragraphs = re.split(r"\n[ \t]*\n", inner.strip())
    kept = [p for p in paragraphs if not REVEALING.search(p)]
    for p in paragraphs:
        if REVEALING.search(p):
            result.removed.append({"line": node.start_point.row + 1, "kind": "docstring",
                                   "text": p.strip()})
    statement = node.parent
    if kept:
        kept[0] = kept[0].lstrip()
        new = prefix + quote + lead + "\n\n".join(kept) + trail + quote
        return node.start_byte, node.end_byte, new.encode("utf-8")
    body = statement.parent
    others = [c for c in body.named_children if c.type != "comment" and id_(c) != id_(statement)]
    if others:
        line_start, line_end = _line_bounds(data, statement.start_byte, statement.end_byte)
        return line_start, line_end, b""
    return node.start_byte, node.end_byte, b"pass"  # the docstring was the whole body
