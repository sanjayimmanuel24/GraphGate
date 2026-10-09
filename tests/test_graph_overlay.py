"""The repository laid around a slice: Condition C's registered view (BUILD_PLAN 5.2)."""

import textwrap

import pytest

from graphgate.gate import graph_gate
from graphgate.gate.graph_gate import GraphGate
from graphgate.gate.local import BLOCK, Change
from graphgate.graph.delta import changed_symbols, free_paths
from graphgate.graph.link import GRAPHGATE, link
from graphgate.graph.overlay import (
    RepositoryView,
    SnapshotMissing,
    read_snapshot,
    view_for_event,
    without_symbols,
    write_snapshot,
)
from graphgate.graph.extract import extract

from conftest import StubScanner


def dedent(code):
    return textwrap.dedent(code).lstrip("\n")


# The repository: store.py is large, so the slice keeps save() and Store.put() and cuts the rest.
STORE = dedent('''
    import os

    ROOT = os.environ.get("ROOT")
    LIMIT = 10


    def save(name, data):
        check(name)
        return _write(name, data)


    def check(name):
        if ".." in name:
            raise ValueError(name)


    def _write(name, data):
        with open(os.path.join(ROOT, name), "w") as handle:
            handle.write(data)


    class Store:
        def put(self, name, data):
            return save(name, data)

        def flush(self, name):
            os.remove(name)
''')
SLICE = dedent('''
    import os

    LIMIT = 10


    def save(name, data):
        check(name)
        return _write(name, data)


    def check(name):
        if ".." in name:
            raise ValueError(name)


    class Store:
        def put(self, name, data):
            return save(name, data)
''')
API = "from lib.store import save\n\n\ndef upload(name, data):\n    return save(name, data)\n"
TWIN = "import os\n\n\ndef save_copy(name, data):\n    open(name, 'w').write(data)\n"
REPO = {"lib/store.py": STORE, "lib/api.py": API, "lib/twin.py": TWIN, "tests/test_store.py": "def test_it():\n    pass\n",
        "README.md": "not python"}


def view(**kwargs):
    return RepositoryView(REPO, {"lib/store.py": SLICE}, **kwargs)


def names(facts, path="lib/store.py"):
    return {s["qualname"]: s.get("origin") for s in facts[path]["symbols"]}


def graph(view_, slice_text=SLICE):
    return link(view_.facts({"lib/store.py": slice_text}), config=GRAPHGATE)


# --- what the view holds ---------------------------------------------------------------

def test_code_cut_from_a_slice_file_is_put_back_from_the_repository():
    found = names(view().facts({"lib/store.py": SLICE}))

    assert found == {"<module>": None, "save": None, "check": None, "Store": None, "Store.put": None,
                     "_write": "repository", "Store.flush": "repository"}


def test_the_rest_of_the_repository_is_there_as_it_is_and_only_python_files():
    facts = view().facts({"lib/store.py": SLICE})

    assert sorted(facts) == ["lib/api.py", "lib/store.py", "lib/twin.py", "tests/test_store.py"]
    assert names(facts, "lib/api.py") == {"<module>": "repository", "upload": "repository"}


def test_the_sink_behind_the_slice_is_reachable_again():
    """The slice alone has no sink at all; with the repository the flow runs from the API to open()."""
    alone = link({"lib/store.py": extract("lib/store.py", SLICE)}, config=GRAPHGATE)
    around = graph(view())

    assert free_paths(alone) == {}
    assert ("lib/api.py::upload#name", "sink@lib/store.py::_write::builtins.open") in free_paths(around)
    assert around.nodes["lib/store.py::_write"]["origin"] == "repository"
    assert "origin" not in around.nodes["lib/store.py::save"]


def test_a_cut_assignment_comes_back_with_the_calls_it_needs():
    """ROOT was cut from the slice; the environment still reaches open() through it."""
    around = graph(view())

    assert ("src@lib/store.py::<module>::os.environ", "sink@lib/store.py::_write::builtins.open") in free_paths(around)
    module = next(s for s in view().facts({"lib/store.py": SLICE})["lib/store.py"]["symbols"]
                  if s["qualname"] == "<module>")
    assert [target for target, _ in module["assigns"]] == ["v:LIMIT", "v:ROOT"]     # LIMIT is the slice's own


def test_imports_the_trace_dropped_still_serve_the_cut_code():
    tidied = SLICE.replace("import os\n\n", "")          # the model removes an import its file no longer uses

    around = graph(view(), tidied)

    assert around.has_node("ext::os.path.join") and "sink@lib/store.py::Store.flush::os.remove" in around


# --- what belongs to the trace ---------------------------------------------------------

def test_what_the_model_deletes_stays_deleted():
    without_check = SLICE.replace('def check(name):\n    if ".." in name:\n        raise ValueError(name)\n\n\n', "")

    found = names(view().facts({"lib/store.py": without_check}))

    assert "check" not in found and found["_write"] == "repository"


def test_a_name_the_model_defines_wins_over_the_cut_definition():
    own = SLICE + "\n\ndef _write(name, data):\n    return None\n"

    found = names(view().facts({"lib/store.py": own}))

    assert found["_write"] is None
    assert "sink@lib/store.py::_write::builtins.open" not in graph(view(), own)


def test_a_cut_method_goes_when_its_class_goes():
    no_class = SLICE.split("class Store:")[0]

    found = names(view().facts({"lib/store.py": no_class}))

    assert "Store" not in found and "Store.flush" not in found and found["_write"] == "repository"


def test_a_deleted_slice_file_is_gone_and_an_added_file_is_taken_as_it_is():
    facts = view().facts({"lib/new.py": "def fresh():\n    pass\n"})

    assert "lib/store.py" not in facts
    assert names(facts, "lib/new.py") == {"<module>": None, "fresh": None}


def test_nothing_in_the_repository_counts_as_changed():
    edited = SLICE.replace("check(name)\n    return", "return")
    before, after = graph(view()), graph(view(), edited)

    assert changed_symbols(before, after) == {"lib/store.py::save"}


# --- leakage exclusions ----------------------------------------------------------------

def test_excluded_files_and_functions_are_left_out():
    limited = view(exclude_files=["lib/twin.py", "tests/test_store.py"],
                   exclude_symbols=[("lib/store.py", "Store.flush"), ("lib/api.py", "upload")])

    facts = limited.facts({"lib/store.py": SLICE})

    assert sorted(facts) == ["lib/api.py", "lib/store.py"]
    assert "Store.flush" not in names(facts) and names(facts, "lib/api.py") == {"<module>": "repository"}
    assert facts["lib/api.py"]["symbols"][0]["defs"] == {}


def test_removing_a_definition_takes_what_is_inside_it_along():
    facts = extract("m.py", "class A:\n    def f(self):\n        def g():\n            pass\n\ndef h():\n    pass\n")

    left = without_symbols(facts, ["A.f"])

    assert [s["qualname"] for s in left["symbols"]] == ["<module>", "A", "h"]
    assert left["symbols"][1]["defs"] == {}
    assert "A.f.g" in [s["qualname"] for s in facts["symbols"]]        # the facts handed in are untouched


# --- the gate with a view --------------------------------------------------------------

def test_the_gate_shows_the_model_repository_code_behind_a_flag(fake_client):
    edited = SLICE.replace("    check(name)\n", "")
    change = Change.between({"lib/store.py": SLICE}, {"lib/store.py": edited})
    reply = '{"items": [{"id": "G1", "label": "exploitable-regression", "rationale": "the check is gone"}]}'
    client = fake_client([reply])

    decision = GraphGate(StubScanner(), client, view=view()).decide(change, replication=0)

    assert decision.decision == BLOCK and [f["rule"] for f in decision.flags] == ["R3"]
    shown = client.prompts_seen[0].split("Items to judge:")[1]
    assert "# lib/store.py, lines 17-19" in shown                       # _write, at its place in the repository
    assert 'with open(os.path.join(ROOT, name), "w") as handle:' in shown
    assert "def _write" not in change.diff                              # the diff never shows that function


def test_without_a_view_the_same_change_shows_no_sink():
    edited = SLICE.replace("    check(name)\n", "")
    change = Change.between({"lib/store.py": SLICE}, {"lib/store.py": edited})

    decision = GraphGate(StubScanner(), None, use_triage=False).decide(change, replication=0)

    assert decision.flags == ()                    # the slice has no sink, so the guard guards no path


def test_the_gate_links_each_code_state_once(monkeypatch):
    linked = []
    real = graph_gate.link
    monkeypatch.setattr(graph_gate, "link", lambda facts, **kw: linked.append(1) or real(facts, **kw))
    gate = GraphGate(StubScanner(), None, use_triage=False, view=view())
    second = SLICE.replace("LIMIT = 10", "LIMIT = 20")
    third = second.replace("LIMIT = 20", "LIMIT = 30")

    gate.decide(Change.between({"lib/store.py": SLICE}, {"lib/store.py": second}), replication=0)
    gate.decide(Change.between({"lib/store.py": second}, {"lib/store.py": third}), replication=0)

    assert len(linked) == 3                        # three states, not four graphs


# --- snapshots on disk -----------------------------------------------------------------

def test_a_snapshot_is_written_once_per_file_and_read_back(tmp_path):
    files = [("lib/store.py", "b1", STORE), ("lib/api.py", "b2", API)]
    assert write_snapshot(tmp_path, "demo-0001", "o/r", "abc", files) == 2
    assert write_snapshot(tmp_path, "demo-0002", "o/r", "def", files[:1]) == 1

    assert sorted(p.name for p in (tmp_path / "blobs").iterdir()) == ["b1.py", "b2.py"]
    assert read_snapshot(tmp_path, "demo-0001") == {"lib/store.py": STORE, "lib/api.py": API}
    assert read_snapshot(tmp_path, "demo-0002") == {"lib/store.py": STORE}


def test_a_missing_snapshot_is_an_error_not_a_fallback(tmp_path):
    with pytest.raises(SnapshotMissing, match="build_repo_snapshots"):
        read_snapshot(tmp_path, "demo-0001")


def test_a_view_is_built_from_an_events_clean_slice_and_its_snapshot(tmp_path):
    clean = tmp_path / "events" / "demo-0001" / "clean" / "lib"
    clean.mkdir(parents=True)
    (clean / "store.py").write_text(SLICE, encoding="utf-8")
    write_snapshot(tmp_path / "snapshots", "demo-0001", "o/r", "abc",
                   [(path, f"b{n}", text) for n, (path, text) in enumerate(REPO.items()) if path.endswith(".py")])

    built = view_for_event(tmp_path / "events" / "demo-0001", tmp_path / "snapshots", exclude_files=["lib/twin.py"])

    assert names(built.facts({"lib/store.py": SLICE}))["_write"] == "repository"
    assert "lib/twin.py" not in built.facts({"lib/store.py": SLICE}) and built.missing_from_repository == []
