"""Facts read from one file (BUILD_PLAN 4.1): symbols, imports, calls, assignments, guards."""

import textwrap

from graphgate.graph.extract import extract, module_name


def facts(code, path="pkg/mod.py"):
    return extract(path, textwrap.dedent(code))


def symbol(file, qualname):
    return next(s for s in file["symbols"] if s["qualname"] == qualname)


def test_module_names_follow_repository_paths():
    assert module_name("git/repo/base.py") == ("git.repo.base", False)
    assert module_name("git/__init__.py") == ("git", True)
    assert module_name("src/pkg/mod.py") == ("pkg.mod", False)


def test_symbols_are_modules_classes_functions_and_methods_with_their_nesting():
    file = facts('''
        import os

        class Store:
            limit = 5

            def find(self, name, *rest, key=None, **options):
                def inner(x):
                    return x
                return inner(name)

            @staticmethod
            def clean(name: str = ""):
                return name

        async def load(path: "Path", flag: Optional[Flag] = None):
            return path
    ''')

    kinds = {s["qualname"]: (s["kind"], s["parent"], s["cls"]) for s in file["symbols"]}
    assert kinds == {
        "<module>": ("module", None, None),
        "Store": ("class", "<module>", None),
        "Store.find": ("method", "Store", "Store"),
        "Store.find.inner": ("function", "Store.find", None),
        "Store.clean": ("method", "Store", "Store"),
        "load": ("function", "<module>", None),
    }
    find = symbol(file, "Store.find")
    assert find["params"] == ["self", "name", "rest", "key", "options"]
    assert (find["vararg"], find["kwarg"]) == ("rest", "options") and find["defs"] == {"inner": "Store.find.inner"}
    assert find["keyword_only"] == ["key"]
    assert symbol(file, "Store.clean")["decorators"] == ["staticmethod"]
    assert symbol(file, "load")["annotations"] == {"path": "Path", "flag": "Flag"}
    assert symbol(file, "<module>")["defs"] == {"Store": "Store", "load": "load"}
    assert not file["parse_error"]


def test_imports_resolve_aliases_and_relative_forms():
    code = '''
        import os.path
        import subprocess as sp
        from flask import request, abort as stop
        from . import util
        from .db import run
        from ..core.auth import check
        from helpers import *
    '''
    file = facts(code, path="app/web/views.py")

    assert file["imports"] == {
        "os": "os", "sp": "subprocess", "request": "flask.request", "stop": "flask.abort",
        "util": "app.web.util", "run": "app.web.db.run", "check": "app.core.auth.check",
    }
    assert file["star_imports"] == ["helpers"]
    assert facts("from . import util", path="app/web/__init__.py")["imports"] == {"util": "app.web.util"}


def test_calls_record_callee_arguments_receiver_and_use():
    f = symbol(facts('''
        def f(name, parts):
            value = clean(name)
            if not check(value):
                return None
            log(value)
            cur.execute("q" + value, params=parts, *extra)
            return get_db().run(value)
    '''), "f")

    by_text = {c["text"]: c for c in f["calls"]}
    assert by_text["clean"]["use"] == "value" and by_text["clean"]["args"] == [["v:name"]]
    assert by_text["check"]["use"] == "cond"
    assert by_text["log"]["use"] == "stmt"
    execute = by_text["cur.execute"]
    assert execute["chain"] == ["cur", "execute"] and execute["attr"] == "execute"
    assert execute["args"] == [["v:value"]] and execute["kwargs"] == {"params": ["v:parts"]}
    assert execute["star"] == ["v:extra"] and execute["receiver"] == ["v:cur"]
    run = by_text["get_db().run"]
    assert run["chain"] is None and run["attr"] == "run"
    assert run["receiver"] == [f"c:{f['calls'].index(by_text['get_db'])}"]
    assert f["returns"] == [f"c:{f['calls'].index(run)}"]


def test_assignments_cover_the_forms_values_travel_through():
    f = symbol(facts('''
        def f(self, a, b):
            x = y = a
            x += b
            first, second = pair()
            self.name = a
            box.items[0] = b
            for item in a:
                pass
            with open(a) as handle:
                pass
            names = [n for n in b if n]
            if (m := match(a)):
                pass
            parts = []
            parts.append(a)
            self.rows.extend(b)
    '''), "f")

    assigns = {(target, tuple(atoms)) for target, atoms in f["assigns"]}
    calls = [c["text"] for c in f["calls"]]
    for expected in [("v:x", ("v:a",)), ("v:y", ("v:a",)), ("v:x", ("v:b", "v:x")), ("a:self.name", ("v:a",)),
                     ("a:box.items", ("v:b",)), ("v:item", ("v:a",)), ("v:n", ("v:b",)), ("v:names", ("v:n",)),
                     ("v:parts", ("v:a",)), ("a:self.rows", ("v:b",)),
                     ("v:first", (f"c:{calls.index('pair')}",)), ("v:second", (f"c:{calls.index('pair')}",)),
                     ("v:handle", (f"c:{calls.index('open')}",)), ("v:m", (f"c:{calls.index('match')}",))]:
        assert expected in assigns, expected


def test_a_value_is_reduced_to_where_it_may_come_from():
    f = symbol(facts('''
        def f(a, b, c):
            return [a.name, f"{b}!", c[0] if a == b else "x", not c, lambda q: q, 3]
    '''), "f")

    assert f["returns"] == ["a:a.name", "v:b", "v:c"]      # the comparison and "not c" are truth values


def test_guards_are_tests_that_reject_and_keep_what_they_test():
    f = symbol(facts('''
        def f(path, user):
            if ".." in path:
                raise ValueError(path)
            if user.ok:
                pass
            else:
                abort(403)
            assert is_safe(path), "no"
            if not path:
                return None
    '''), "f")

    assert [(g["how"], g["text"]) for g in f["guards"]] == [
        ("if", 'if " .. " in _'), ("unless", "unless _ . ok"), ("assert", "assert is_safe ( _ )")]
    assert f["guards"][0]["atoms"] == ["v:path"] and f["guards"][1]["atoms"] == ["a:user.ok"]


def test_renaming_a_variable_keeps_a_guard_and_changing_the_test_does_not():
    def fingerprint(code):
        return symbol(facts(code), "f")["guards"][0]["fingerprint"]

    original = fingerprint('def f(p):\n    if p.startswith(".."):\n        raise E\n')

    assert fingerprint('def f(q):\n    if q.startswith(".."):\n        raise E\n') == original
    assert fingerprint('def f(p):\n    if p.startswith("."):\n        raise E\n') != original


def test_digest_ignores_comments_docstrings_layout_and_nested_definitions():
    def digest(code, qualname="f"):
        return symbol(facts(code), qualname)["digest"]

    plain = "def f(a):\n    return run(a)\n"

    assert digest('def f(a):\n    """Doc."""\n    # note\n    return run( a )\n') == digest(plain)
    assert digest("@cached\ndef f(a):\n    return run(a)\n") != digest(plain)
    assert digest("def f(a):\n    return run(a, 1)\n") != digest(plain)
    outer = "def f(a):\n    def g():\n        return {}\n    return run(a)\n"
    assert digest(outer.format(1)) == digest(outer.format(2))
    assert digest(outer.format(1), "f.g") != digest(outer.format(2), "f.g")


def test_a_file_that_does_not_parse_is_marked_and_still_read():
    file = facts("def ok():\n    return 1\n\ndef broken(:\n")

    assert file["parse_error"] and "ok" in [s["qualname"] for s in file["symbols"]]
