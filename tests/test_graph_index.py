"""The stored graph and its incremental update (BUILD_PLAN 4.4)."""

import json

import pytest

from graphgate.graph import index as index_module
from graphgate.graph.index import GraphIndex, Update
from graphgate.graph.link import GraphConfig, build_graph
from graphgate.graph.model import to_json

FILES = {
    "app.py": "import os\nfrom lib import run\n\ndef main():\n    run(os.environ.get('CMD'))\n",
    "lib.py": "import os\n\ndef run(cmd):\n    os.system(cmd)\n",
    "other.py": "def idle():\n    return 1\n",
}
EDITED = "import os, shlex\n\ndef run(cmd):\n    os.system(shlex.quote(cmd))\n"


def canonical(graph):
    return json.dumps(to_json(graph), sort_keys=True)


@pytest.fixture
def parsed(monkeypatch):
    """Paths handed to the parser, in order."""
    seen = []
    real = index_module.extract

    def spy(path, text):
        seen.append(path)
        return real(path, text)

    monkeypatch.setattr(index_module, "extract", spy)
    return seen


def test_first_update_parses_every_file_and_matches_a_build_from_scratch(tmp_path, parsed):
    with GraphIndex(tmp_path / "graph.sqlite") as index:
        update = index.update(FILES)

        assert update == Update(parsed=("app.py", "lib.py", "other.py"), reused=0, removed=())
        assert canonical(index.graph()) == canonical(build_graph(FILES))


def test_only_a_changed_file_is_parsed_again_and_the_graph_is_still_exact(tmp_path, parsed):
    with GraphIndex(tmp_path / "graph.sqlite") as index:
        index.update(FILES)
        parsed.clear()

        update = index.update({**FILES, "lib.py": EDITED})

        assert parsed == ["lib.py"] and update == Update(parsed=("lib.py",), reused=2, removed=())
        assert canonical(index.graph()) == canonical(build_graph({**FILES, "lib.py": EDITED}))


def test_a_change_in_one_file_updates_how_calls_in_another_resolve(tmp_path):
    """app.py is not parsed again, yet its call to run() must stop resolving."""
    with GraphIndex(tmp_path / "graph.sqlite") as index:
        index.update(FILES)
        renamed = FILES["lib.py"].replace("def run(", "def execute(")

        index.apply({"lib.py": renamed})

        graph = index.graph()
        assert "lib.py::run" not in graph and graph.graph["stats"]["unknown_calls"] == 1
        assert canonical(graph) == canonical(build_graph({**FILES, "lib.py": renamed}))


def test_apply_takes_a_change_set_with_deletions(tmp_path, parsed):
    with GraphIndex(tmp_path / "graph.sqlite") as index:
        index.update(FILES)
        parsed.clear()

        update = index.apply({"lib.py": EDITED, "other.py": None, "app.py": FILES["app.py"], "gone.py": None})

        assert parsed == ["lib.py"]
        assert update == Update(parsed=("lib.py",), reused=1, removed=("other.py",))
        assert canonical(index.graph()) == canonical(
            build_graph({"app.py": FILES["app.py"], "lib.py": EDITED}))


def test_a_file_missing_from_a_full_revision_is_removed(tmp_path):
    with GraphIndex(tmp_path / "graph.sqlite") as index:
        index.update(FILES)

        update = index.update({k: v for k, v in FILES.items() if k != "other.py"})

        assert update.removed == ("other.py",) and "other.py::idle" not in index.graph()


def test_the_graph_is_read_back_from_disk_without_parsing(tmp_path, parsed):
    path = tmp_path / "graph.sqlite"
    with GraphIndex(path) as index:
        index.update(FILES)
        expected = canonical(index.graph())
    parsed.clear()

    with GraphIndex(path) as reopened:
        assert canonical(reopened.graph()) == expected
        assert reopened.update(FILES) == Update(parsed=(), reused=3, removed=())
    assert parsed == []


def test_a_stored_graph_is_linked_again_when_the_settings_differ(tmp_path, parsed):
    path = tmp_path / "graph.sqlite"
    with GraphIndex(path) as index:
        index.update(FILES)
    parsed.clear()
    config = GraphConfig(public_api_sources=True)

    with GraphIndex(path, config=config) as reopened:
        graph = reopened.graph()

    assert parsed == []                                   # facts do not depend on the settings
    assert canonical(graph) == canonical(build_graph(FILES, config=config))
    assert graph.nodes["lib.py::run#cmd"]["source"] == "public-api"


def test_exclusions_apply_to_the_stored_graph(tmp_path):
    with GraphIndex(tmp_path / "graph.sqlite") as index:
        index.update(FILES, exclude=["other.py"])

        assert index.graph().graph["excluded"] == ["other.py"]
        assert canonical(index.graph()) == canonical(build_graph(FILES, exclude=["other.py"]))


def test_an_empty_index_has_an_empty_graph(tmp_path):
    with GraphIndex(tmp_path / "graph.sqlite") as index:
        assert len(index.graph()) == 0
