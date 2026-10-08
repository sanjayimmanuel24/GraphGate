"""Facts to a graph (BUILD_PLAN 4.2, 4.3): call resolution, taint and sanitize edges."""

import textwrap

from graphgate.graph.catalog import DEFAULT, Sink, is_validator_name
from graphgate.graph.delta import apply_rules, free_paths
from graphgate.graph.link import GraphConfig, build_graph, is_test_path
from graphgate.graph.model import CALL, SANITIZE, TAINT, edges, to_json, with_role


def build(files, exclude=(), **config):
    return build_graph({path: textwrap.dedent(code) for path, code in files.items()},
                       config=GraphConfig(**config), exclude=exclude)


def calls(graph):
    return {(u.split("::")[-1], v): data["resolution"] for u, v, data in edges(graph, CALL)}


def taint(graph):
    return {(u, v) for u, v, _ in edges(graph, TAINT)}


def sanitize(graph):
    return {(u, v): data["uses"] for u, v, data in edges(graph, SANITIZE)}


def path_ends(graph):
    return set(free_paths(graph))


# --- E_call: the three resolution rules, and the explicit unknown edge ----------------

def test_same_module_calls_resolve_to_functions_classes_and_nested_functions():
    graph = build({"m.py": '''
        class Job:
            def __init__(self, name):
                self.name = name

        def helper(x):
            return x

        def main(x):
            def local(y):
                return y
            Job(helper(local(x)))
    '''})

    assert calls(graph) == {
        ("main", "m.py::helper"): "same-module",
        ("main", "m.py::main.local"): "same-module",
        ("main", "m.py::Job.__init__"): "same-module",
    }


def test_imports_resolve_across_modules_through_aliases_and_re_exports():
    graph = build({
        "pkg/__init__.py": "from .core import run\n",
        "pkg/core.py": "def run(cmd):\n    return cmd\n\nclass Tool:\n    @classmethod\n    def make(cls):\n        return cls()\n",
        "app.py": '''
            import os
            import pkg.core as core
            from pkg import run as go
            from pkg.core import Tool

            def main(x):
                go(x)
                core.run(x)
                Tool.make()
                os.getcwd()
        ''',
    })

    found = calls(graph)
    assert found["main", "pkg/core.py::run"] == "import"
    assert found["main", "pkg/core.py::Tool.make"] == "import"
    assert calls(graph)["Tool.make", "pkg/core.py::Tool"] == "attribute"      # cls() in a classmethod
    assert found["main", "ext::os.getcwd"] == "import"
    assert graph.graph["stats"]["unknown_calls"] == 0


def test_attribute_calls_resolve_when_the_receivers_class_can_be_read_off_the_code():
    graph = build({"m.py": '''
        import threading

        class Base:
            def save(self):
                pass

        class Repo(Base):
            def __init__(self):
                self.cache = Cache()

            def open(self):
                self.save()
                self.cache.get()
                super().save()

        class Cache:
            def get(self):
                pass

        class Worker(threading.Thread):
            def go(self):
                self.start()

        def use(repo: Repo):
            local = Cache()
            local.get()
            repo.open()
            Repo.open(repo)
    '''})

    found = calls(graph)
    assert found["Repo.open", "m.py::Base.save"] == "attribute"          # self, through a base class
    assert found["Repo.open", "m.py::Cache.get"] == "attribute"          # self.cache = Cache()
    assert found["use", "m.py::Cache.get"] == "attribute"                # local = Cache()
    assert found["use", "m.py::Repo.open"] == "attribute"                # annotated parameter; Class.method
    assert found["Worker.go", "ext::threading.Thread.start"] == "attribute"
    assert graph.graph["stats"]["unknown_calls"] == 0


def test_calls_that_cannot_be_resolved_get_an_unknown_edge_and_are_counted():
    graph = build({
        "pkg/a.py": '''
            from pkg.missing import gone

            def f(obj, handlers, fn):
                obj.method()
                handlers["x"]()
                fn()
                make()().run()
                gone()
        ''',
    })

    found = calls(graph)
    unknown = {target for (_, target), how in found.items() if how == "unknown"}
    # "gone" lives in a module of this repository that is not among the files.
    assert unknown == {"unknown::obj.method", 'unknown::handlers["x"]', "unknown::fn", "unknown::make",
                       "unknown::make()", "unknown::make()().run", "unknown::gone"}
    assert graph.graph["stats"]["unknown_calls"] == 7 == graph.graph["stats"]["calls_total"]
    assert graph.graph["stats"]["unknown_by_file"] == {"pkg/a.py": 7}
    assert graph.nodes["unknown::obj.method"]["kind"] == "unknown"


# --- E_taint --------------------------------------------------------------------------

def test_taint_runs_from_a_request_through_parameters_to_a_sink():
    graph = build({
        "views.py": '''
            from flask import request
            from store import find

            def show():
                name = request.args.get("name")
                label = "n=" + name
                return find(label)
        ''',
        "store.py": '''
            def find(text):
                query = "select * from t where " + text
                return run(query)

            def run(sql):
                cur = connect().cursor()
                cur.execute(sql)
                return cur.fetchall()
        ''',
    })

    source, sink = "src@views.py::show::flask.request", "sink@store.py::run::.execute"
    assert graph.nodes[source]["source"] == "request" and graph.nodes[sink]["sink"] == "sql"
    assert free_paths(graph) == {
        (source, sink): (source, "store.py::find#text", "store.py::run#sql", sink)}
    assert graph.edges["store.py::find#text", "store.py::run#sql", TAINT]["via"] == ["store.py::find"]


def test_only_the_arguments_that_reach_a_sink_count():
    graph = build({"m.py": '''
        import os, subprocess

        def a(cur):
            name = os.environ.get("NAME")
            cur.execute("select 1 where n = %s", (name,))

        def b(cur):
            name = os.environ["NAME"]
            cur.execute("select 1 where n = " + name)

        def c():
            subprocess.run(args=os.getenv("CMD"), cwd="/")
    '''})

    assert path_ends(graph) == {
        ("src@m.py::b::os.environ", "sink@m.py::b::.execute"),
        ("src@m.py::c::os.getenv", "sink@m.py::c::subprocess.run"),
    }


def test_values_travel_through_attributes_globals_returns_and_library_calls():
    graph = build({"m.py": '''
        import os, sys

        ROOT = os.environ.get("ROOT")

        class Loader:
            def __init__(self, name):
                self.name = name

            def read(self):
                return open(os.path.join(ROOT, self.name.strip())).read()

        def pick():
            return sys.argv[1]

        def main():
            Loader(pick()).read()
    '''}, source_kinds=("env", "cli"))

    ends = path_ends(graph)
    assert ("src@m.py::<module>::os.environ", "sink@m.py::Loader.read::builtins.open") in ends
    assert ("src@m.py::pick::sys.argv", "sink@m.py::Loader.read::builtins.open") in ends
    assert ("m.py::pick#return", "m.py::Loader.__init__#name") in taint(graph)
    assert ("m.py::Loader.__init__#name", "m.py::Loader#attr:name") in taint(graph)


def test_an_attribute_set_in_a_subclass_and_read_in_its_base_is_one_port():
    graph = build({"m.py": '''
        import os

        class Base:
            def run(self):
                os.system(self.cmd)

        class Job(Base):
            def __init__(self):
                self.cmd = os.environ.get("CMD")
    '''})

    assert path_ends(graph) == {("src@m.py::Job.__init__::os.environ", "sink@m.py::Base.run::os.system")}
    assert ("m.py::Base#attr:cmd", "sink@m.py::Base.run::os.system") in taint(graph)


def test_bound_and_keyword_arguments_land_on_the_right_parameters():
    graph = build({"m.py": '''
        class Shell:
            def run(self, cmd, *rest, env=None, **options):
                pass

            @staticmethod
            def plain(cmd):
                pass

        def main(shell: Shell, a, b, c, d, e):
            shell.run(a, b, env=c, cwd=d)
            Shell.plain(e)
    '''})

    into = {(u.split("#")[-1], v.split("::")[-1]) for u, v in taint(graph)}
    assert into == {("shell", "Shell.run#self"), ("a", "Shell.run#cmd"), ("b", "Shell.run#rest"),
                    ("c", "Shell.run#env"), ("d", "Shell.run#options"), ("e", "Shell.plain#cmd")}


def test_request_parameters_are_sources_by_decorator_and_by_annotation():
    graph = build({"m.py": '''
        from django.http import HttpRequest
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/files/{name}")
        def download(name: str, limit: int = 1):
            return open(name)

        def view(request: HttpRequest, pk):
            return open(request.GET.get("f"))

        class Views:
            @app.route("/x")
            def page(self, slug):
                return slug
    '''})

    assert {n: graph.nodes[n]["source"] for n in with_role(graph, "source") if "#" in n} == {
        "m.py::download#name": "request", "m.py::download#limit": "request",
        "m.py::view#request": "request", "m.py::Views.page#slug": "request"}
    assert ("m.py::view#request", "sink@m.py::view::builtins.open") in path_ends(graph)


def test_source_kinds_can_be_limited():
    code = {"m.py": "import os\n\ndef f():\n    os.system(os.environ.get('X'))\n    os.system(input())\n"}

    assert len(path_ends(build(code))) == 2
    assert path_ends(build(code, source_kinds=("env",))) == {("src@m.py::f::os.environ", "sink@m.py::f::os.system")}


# --- E_sanitize -----------------------------------------------------------------------

def test_a_library_sanitizer_stands_on_the_path_when_its_result_is_used():
    graph = build({"m.py": '''
        import os, shlex

        def safe():
            os.system("ls " + shlex.quote(os.environ.get("D")))

        def unsafe():
            arg = os.environ.get("D")
            shlex.quote(arg)
            os.system("ls " + arg)
    '''})

    assert graph.nodes["ext::shlex.quote"]["sanitizer"] == "library"
    assert sanitize(graph) == {("m.py::safe", "ext::shlex.quote"): ["transform"],
                               ("m.py::unsafe", "ext::shlex.quote"): ["check"]}
    assert ("ext::shlex.quote", "sink@m.py::safe::os.system") in taint(graph)
    assert path_ends(graph) == {("src@m.py::unsafe::os.environ", "sink@m.py::unsafe::os.system")}


def test_validation_functions_are_recognised_by_a_word_of_their_name():
    for name in ("sanitize_path", "escapeLike", "check_unsafe_options", "is_valid", "quote_ident",
                 "validateName", "verify_token", "secure_filename", "safe_join", "is_safe_path"):
        assert is_validator_name(name), name
    for name in ("unsafe_load", "checkout", "process", "cleanup", "check_output", "requote", "misquote"):
        assert not is_validator_name(name), name


def test_a_projects_validator_is_a_sanitizer_node_whether_resolved_or_not():
    graph = build({"m.py": '''
        import os

        def check_name(name):
            return name

        def a(db):
            name = os.environ.get("N")
            check_name(name)
            os.system(db.escape(name))
    '''})

    assert sanitize(graph) == {("m.py::a", "m.py::check_name"): ["check"],
                               ("m.py::a", "unknown::db.escape"): ["transform"]}
    assert with_role(graph, "sanitizer") == ["m.py::check_name", "unknown::db.escape"]
    assert ("src@m.py::a::os.environ", "m.py::check_name") in taint(graph)     # into the node, not its parameter
    assert path_ends(graph) == set()


def test_structural_guards_are_edges_only_when_asked_for_and_only_on_values():
    code = {"m.py": '''
        def f(path):
            if ".." in path:
                raise ValueError(path)
            if 1 > 2:
                raise RuntimeError
            return open(path)
    '''}

    assert sanitize(build(code)) == {}
    guards = sanitize(build(code, structural_guards=True))
    assert len(guards) == 1
    (symbol, guard), uses = next(iter(guards.items()))
    assert symbol == "m.py::f" and guard.startswith("guard@m.py::f::") and uses == ["check"]


# --- settings, exclusions, determinism ------------------------------------------------

def test_public_api_parameters_are_sources_only_when_asked_for():
    code = {
        "lib/api.py": '''
            class Repo:
                def clone(self, url, _depth=1):
                    return _run(url)

                def _hidden(self, x):
                    return _run(x)

            def _run(arg):
                import os
                os.system(arg)

            def export(path):
                def inner(p):
                    return p
                return open(inner(path))
        ''',
        "tests/test_api.py": "def test_it(tmp):\n    open(tmp)\n",
    }

    def api_sources(graph):
        return [n for n in with_role(graph, "source") if graph.nodes[n]["source"] == "public-api"]

    assert api_sources(build(code)) == []
    graph = build(code, public_api_sources=True)
    assert api_sources(graph) == ["lib/api.py::Repo.clone#_depth", "lib/api.py::Repo.clone#url",
                                  "lib/api.py::export#path"]
    assert ("lib/api.py::Repo.clone#url", "sink@lib/api.py::_run::os.system") in path_ends(graph)
    assert graph.graph["config"]["public_api_sources"] is True


def test_test_files_are_told_apart_by_path():
    assert all(map(is_test_path, ["tests/test_a.py", "pkg/test/helpers.py", "pkg/test_x.py", "pkg/x_test.py",
                                  "conftest.py"]))
    assert not any(map(is_test_path, ["pkg/testing.py", "pkg/contest.py", "latest/x.py"]))


def test_excluded_files_are_left_out_as_if_they_were_not_there():
    code = {"a.py": "from b import twin\n\ndef f(x):\n    twin(x)\n", "b.py": "def twin(x):\n    pass\n"}

    graph = build(code, exclude=["b.py", "not-there.py"])

    assert graph.graph["excluded"] == ["b.py"]
    assert all(not node.startswith("b.py") for node in graph.nodes)
    # "b" is no longer a module of the repository in view, so the call is a library call.
    assert calls(graph) == {("f", "ext::b.twin"): "import"}


def test_the_graph_does_not_depend_on_the_order_files_are_given_in():
    code = {
        "a.py": "import os\nfrom b import g\n\ndef f(x):\n    g(os.environ.get(x))\n",
        "b.py": "import os\n\ndef g(y):\n    os.system(y)\n",
    }

    assert to_json(build(code)) == to_json(build(dict(reversed(code.items()))))


def test_a_catalog_can_be_extended_per_repository_without_touching_the_default():
    catalog = DEFAULT.extended(sanitizers={"proj.util.scrub": "command"})

    assert "proj.util.scrub" in catalog.sanitizers and "proj.util.scrub" not in DEFAULT.sanitizers
    assert DEFAULT.sinks["builtins.open"] == Sink("path", kwargs=("file", "path", "name"))
    assert DEFAULT.source_kind("flask.request.args.get") == ("flask.request", "request")
    assert DEFAULT.source_kind("flask.render_template") is None


# --- from code to flags: each rule once, end to end -----------------------------------

VIEW = '''
    import os, shlex
    from store import archive

    def export():
        name = os.environ.get("NAME")
        {body}
'''
STORE = '''
    import os

    def archive(name):
        return pack(name)

    def pack(name):
        os.system("tar cf out.tar " + name)

    def check_name(name):
        return name
'''


def flags(before_body, after_body, store_after=STORE, **config):
    before = build({"view.py": VIEW.format(body=before_body), "store.py": STORE}, **config)
    after = build({"view.py": VIEW.format(body=after_body), "store.py": store_after}, **config)
    return sorted({flag.rule for flag in apply_rules(before, after)})


def test_removing_a_sanitizer_call_raises_r1_r2_and_r3():
    assert flags("archive(shlex.quote(name))", "archive(name)") == ["R1", "R2", "R3"]


def test_a_new_call_that_hands_input_to_a_sink_raises_r2_alone():
    assert flags("print(name)", "archive(name)") == ["R2"]


def test_dropping_a_validation_call_raises_r3_alone():
    with_check = "from store import check_name\n        check_name(name)\n        archive(name)"

    assert flags(with_check, "archive(name)") == ["R3"]


def test_cutting_a_layer_out_of_the_way_to_the_sink_raises_r4_alone():
    direct = STORE.replace("return pack(name)", 'os.system("tar cf out.tar " + name)')

    assert flags("archive(name)", "archive(name)", store_after=direct) == ["R2"]     # the sink moved: a new pair
    assert flags("archive(name)", "from store import pack\n        pack(name)") == ["R4"]


def test_a_change_that_leaves_the_flow_alone_raises_nothing():
    assert flags("archive(name)", "label = name\n        archive(label)  # renamed") == []
