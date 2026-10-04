"""Inject a known regression into code the model has already refined (BUILD_PLAN 2.4).

A regression event gives two versions of a few files: *clean* (the real fix)
and *regressed* (the real vulnerable code). A refinement trace starts from the
clean files, and at one chosen turn the regression has to appear in whatever
the code looks like by then, as if that turn had introduced it.

The regression is therefore expressed as changes to *units* (a function, a
class attribute, an import, a module-level statement) rather than as a text
patch, which would stop applying as soon as an earlier turn reformatted
anything:

- a unit that differs between clean and regressed is replaced by its regressed
  text, wherever the refined file now has it;
- a unit only the clean version has (a helper the fix added) is removed;
- a unit only the regressed version has is added back after its neighbour.

If a file is still exactly its clean text, the regressed file is swapped in
whole, so the common case is byte-exact. If a changed function or attribute
can no longer be found by name, the injection fails loudly
(:class:`InjectionError`); it is never applied in part.
"""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from typing import Any

from tree_sitter import Node

from graphgate.dataset.slicing import _IMPORTS, _assigned_names, _definition, _name, parse

Key = tuple


class InjectionError(RuntimeError):
    """The regression cannot be placed in the current code."""


@dataclass(frozen=True)
class Unit:
    key: Key      # e.g. ("def", "Git.execute", 0), ("import", "", "import os", 0)
    start: int    # first row, including comments attached directly above
    end: int      # last row, inclusive
    indent: str
    text: str     # the unit's lines, attached comments included


def units(text: str) -> list[Unit]:
    """Every unit of a file, module level first, class members flattened."""
    lines = text.splitlines(keepends=True)
    out: list[Unit] = []
    _scope_units(parse(text), "", lines, out)
    return out


def _scope_units(scope: Node, prefix: str, lines: list[str], out: list[Unit]) -> None:
    seen: Counter = Counter()
    pending: list[Node] = []
    last_statement_row = -1

    def emit(kind: str, *ident: str, start: int, end: int) -> None:
        base = (kind, *ident)
        key = (*base, seen[base])
        seen[base] += 1
        first = lines[start] if start < len(lines) else ""
        out.append(Unit(key, start, end, first[:len(first) - len(first.lstrip())],
                        "".join(lines[start:end + 1])))

    def flush(comments: list[Node]) -> None:
        for c in comments:
            emit("comment", prefix, c.text.decode(), start=c.start_point.row, end=c.end_point.row)

    for child in scope.named_children:
        if child.type == "comment":
            if child.start_point.row != last_statement_row:  # not a trailing comment
                pending.append(child)
            continue
        start, attached = child.start_point.row, 0
        for comment in reversed(pending):
            if comment.end_point.row != start - 1:
                break
            start, attached = comment.start_point.row, attached + 1
        flush(pending[:len(pending) - attached])
        pending = []
        last_statement_row = child.end_point.row

        definition = _definition(child)
        if definition is not None and definition.type == "class_definition":
            name = prefix + _name(definition)
            colon = next(c for c in definition.children if c.type == ":")
            emit("class", name, start=start, end=colon.end_point.row)
            _scope_units(definition.child_by_field_name("body"), name + ".", lines, out)
        elif definition is not None:
            emit("def", prefix + _name(definition), start=start, end=child.end_point.row)
        elif child.type in _IMPORTS:
            emit("import", prefix, child.text.decode(), start=start, end=child.end_point.row)
        else:
            names = _assigned_names(child)
            if names:
                emit("assign", prefix + names[0], start=start, end=child.end_point.row)
            else:
                emit("stmt", prefix, child.text.decode(), start=start, end=child.end_point.row)
    flush(pending)


# --------------------------------------------------------------------------
# Deriving and applying the change
# --------------------------------------------------------------------------

# Units that carry the regression itself: if one cannot be found, stop.
_NAMED = ("def", "class", "assign")


def _scope_of(key: Key) -> str:
    """The class a unit lives in ("" for module level)."""
    if key[0] in _NAMED:
        return key[1].rpartition(".")[0]
    return key[1].rstrip(".")


def _reindent(text: str, old: str, new: str) -> list[str]:
    lines = text.splitlines(keepends=True)
    if old == new:
        return lines
    return [new + line[len(old):] if line.startswith(old) else line for line in lines]


def merge(current: str, clean: str, regressed: str) -> tuple[str, list[str]]:
    """Apply the clean→regressed change to ``current``. Returns (text, notes)."""
    clean_units = {u.key: u for u in units(clean)}
    regressed_list = units(regressed)
    regressed_units = {u.key: u for u in regressed_list}
    current_list = units(current)
    current_units: dict[Key, Unit] = {}
    for u in current_list:
        current_units.setdefault(u.key, u)
    lines = current.splitlines(keepends=True)
    notes: list[str] = []
    # (first row, row after the last, replacement lines); an insert has first == after.
    edits: list[tuple[int, int, list[str]]] = []

    for key, unit in clean_units.items():
        target = current_units.get(key)
        if key not in regressed_units:
            if target is None:
                notes.append(f"{_describe(key)} was to be removed but is no longer there")
                continue
            end = target.end + 1
            if target.start == 0 or not lines[target.start - 1].strip():
                while end < len(lines) and not lines[end].strip():
                    end += 1  # do not leave a doubled gap behind
            edits.append((target.start, end, []))
        elif regressed_units[key].text != unit.text:
            if target is None:
                raise InjectionError(f"{_describe(key)} changed in the regression but is not in the current file")
            new = regressed_units[key]
            edits.append((target.start, target.end + 1, _reindent(new.text, new.indent, target.indent)))

    inserts: dict[int, list[str]] = {}
    position: dict[Key, int] = {}
    previous: dict[str, Key | None] = {}
    for unit in regressed_list:
        scope = _scope_of(unit.key)
        anchor = previous.get(scope)
        previous[scope] = unit.key
        if unit.key in clean_units:
            continue
        if anchor is not None and anchor in position:
            row = position[anchor]                      # after another added unit
        elif anchor is not None and anchor in current_units:
            row = current_units[anchor].end + 1
        elif ("class", scope, 0) in position:
            row = position[("class", scope, 0)]         # first member of an added class
        else:
            row = _scope_end(current_list, scope, len(lines))
            if anchor is not None:
                notes.append(f"{_describe(unit.key)} added at the end of its scope; its neighbour moved")
        position[unit.key] = row
        indent = _scope_indent(current_list, scope, unit.indent)
        gap = ["\n"] if unit.key[0] in ("def", "class") or scope else []
        if unit.key[0] in ("def", "class") and not scope:
            gap = ["\n", "\n"]
        if unit.key[0] == "import":
            gap = []
        inserts.setdefault(row, []).extend(gap + _reindent(unit.text, unit.indent, indent))
    edits.extend((row, row, new) for row, new in inserts.items())

    # Bottom-up so earlier rows keep their numbers; at one row, a replacement
    # goes in before an insert so the inserted unit lands above it.
    for start, end, new in sorted(edits, key=lambda e: (e[0], e[1] > e[0]), reverse=True):
        if new and start == len(lines) and lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines[start:end] = new
    merged = "".join(lines)
    if merged.strip() and not current.endswith("\n\n"):
        merged = merged.rstrip("\n") + "\n"  # removing the last unit must not leave blank lines
    try:
        ast.parse(merged)
    except SyntaxError as exc:
        raise InjectionError(f"the merged file does not parse (line {exc.lineno}: {exc.msg})") from exc
    return merged, notes


def _describe(key: Key) -> str:
    return f"{key[0]} {key[1] or key[2]!r}" if key[0] in _NAMED else f"{key[0]} {key[2][:60]!r}"


def _scope_end(current: list[Unit], scope: str, default: int) -> int:
    members = [u for u in current if _scope_of(u.key) == scope]
    if members:
        return max(u.end for u in members) + 1
    if scope:
        raise InjectionError(f"class {scope!r} is not in the current file")
    return default


def _scope_indent(current: list[Unit], scope: str, default: str) -> str:
    for u in current:
        if _scope_of(u.key) == scope:
            return u.indent
    return default


# --------------------------------------------------------------------------
# The plan carried by a trace
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class InjectionPlan:
    """Which regression to inject, and at which turn.

    Holds both versions of every file the regression changes (``None`` where a
    version does not have the file), so a trace that records the plan can be
    replayed from the trace file alone.
    """

    event_id: str
    turn: int
    clean: dict[str, str | None]
    regressed: dict[str, str | None]

    def to_dict(self) -> dict[str, Any]:
        return {"event_id": self.event_id, "turn": self.turn,
                "clean": dict(self.clean), "regressed": dict(self.regressed)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InjectionPlan:
        return cls(event_id=data["event_id"], turn=data["turn"],
                   clean=dict(data["clean"]), regressed=dict(data["regressed"]))

    @classmethod
    def from_files(cls, event_id: str, turn: int, clean: dict[str, str],
                   regressed: dict[str, str]) -> InjectionPlan:
        """Keep only the files the regression changes."""
        paths = sorted(p for p in set(clean) | set(regressed) if clean.get(p) != regressed.get(p))
        if not paths:
            raise InjectionError(f"event {event_id}: clean and regressed files are identical")
        return cls(event_id, turn, {p: clean.get(p) for p in paths}, {p: regressed.get(p) for p in paths})

    def apply(self, files: dict[str, str]) -> tuple[dict[str, str], dict[str, Any]]:
        """Return the files with the regression in place, and how it was done."""
        out = dict(files)
        how: dict[str, str] = {}
        notes: list[str] = []
        for path in sorted(self.regressed):
            clean, regressed, current = self.clean[path], self.regressed[path], files.get(path)
            if regressed is None:
                if current is None:
                    notes.append(f"{path} was to be removed but is no longer there")
                else:
                    del out[path]
                    how[path] = "removed"
            elif clean is None:
                out[path] = regressed
                how[path] = "added"
            elif current is None:
                raise InjectionError(f"{path} is not in the current snapshot")
            elif current == clean:
                out[path] = regressed
                how[path] = "swapped"
            else:
                out[path], file_notes = merge(current, clean, regressed)
                notes.extend(f"{path}: {n}" for n in file_notes)
                how[path] = "merged"
        return out, {"files": how, "notes": notes}
