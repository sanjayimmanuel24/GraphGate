"""Tests for building regression-event dossiers."""

import json

import pytest

from graphgate.dataset.events import (
    CROSS_FILE,
    LOCAL,
    SpecError,
    build_event,
    classify_scope,
    load_spec,
    slice_requests,
)
from gitrepo import Origin

VIEWS = '''\
from app.files import read_file


def download(request):
    name = request.args["name"]
    return read_file(name)


def index(request):
    return "ok"
'''

FILES_VULNERABLE = '''\
import os

ROOT = "/srv/data"


def read_file(name):
    path = os.path.join(ROOT, name)
    with open(path) as fh:
        return fh.read()


def list_files():
    return os.listdir(ROOT)
'''

FILES_FIXED = '''\
import os

ROOT = "/srv/data"


def _safe_path(name):
    # fix CVE-2024-0001: block path traversal
    path = os.path.realpath(os.path.join(ROOT, name))
    if not path.startswith(ROOT + os.sep):
        raise ValueError("bad name")
    return path


def read_file(name):
    path = _safe_path(name)
    with open(path) as fh:
        return fh.read()


def list_files():
    return os.listdir(ROOT)
'''


def loc(symbol, kind=None, note="n"):
    return {"symbol": symbol, "note": note, **({"kind": kind} if kind else {})}


def flow(entry, guards, sinks):
    return {"entry": [loc(s, "http-request") for s in entry],
            "guards": [loc(s) for s in guards],
            "sinks": [loc(s, "filesystem") for s in sinks]}


# --- The scope rule -------------------------------------------------------


def test_flow_in_one_file_is_local():
    f = flow(["a.py::view"], ["a.py::view"], ["a.py::view"])

    assert classify_scope(f, ["a.py"]) == LOCAL


def test_sink_outside_the_changed_file_is_cross_file():
    f = flow(["a.py::view"], ["a.py::view"], ["b.py::read"])

    assert classify_scope(f, ["a.py"]) == CROSS_FILE


def test_entry_outside_the_changed_file_is_cross_file():
    f = flow(["views.py::download"], ["files.py::read_file"], ["files.py::read_file"])

    assert classify_scope(f, ["files.py"]) == CROSS_FILE


def test_a_regression_changing_every_flow_file_is_still_cross_file():
    """Two changed files: a diff-only gate sees both diffs but not the call between them."""
    f = flow(["a.py::view"], ["a.py::view", "b.py::read"], ["b.py::read"])

    assert classify_scope(f, ["a.py", "b.py"]) == CROSS_FILE


def test_scope_follows_the_true_sink_not_its_stand_in():
    """The sink is recorded at a call site in a.py, but really runs in b.py."""
    f = flow(["a.py::view"], ["a.py::view"], ["a.py::view"])
    f["sinks"][0]["true_symbol"] = "b.py::execute"

    assert classify_scope(f, ["a.py"]) == CROSS_FILE


def test_a_stand_in_in_the_same_file_keeps_the_label():
    f = flow(["a.py::view"], ["a.py::view"], ["a.py::view"])
    f["sinks"][0]["true_symbol"] = "a.py::Big.execute"

    assert classify_scope(f, ["a.py"]) == LOCAL


def test_guards_cannot_have_a_true_symbol(tmp_path):
    bad = flow(["a.py::f"], ["a.py::f"], ["a.py::f"])
    bad["guards"][0]["true_symbol"] = "b.py::g"

    with pytest.raises(SpecError, match="no true_symbol"):
        load_spec(write_spec(tmp_path, flow=bad))


def test_guard_outside_the_regression_is_inconsistent():
    f = flow(["a.py::view"], ["b.py::check"], ["a.py::view"])

    with pytest.raises(SpecError, match="guard in a file the regression does not change"):
        classify_scope(f, ["a.py"])


def test_every_role_is_required():
    with pytest.raises(SpecError, match="at least one guards"):
        classify_scope({"entry": [loc("a.py::f")], "guards": [], "sinks": [loc("a.py::f")]},
                       ["a.py"])


# --- Specs ----------------------------------------------------------------


def write_spec(directory, **overrides):
    spec = {
        "event_id": "demo-0001",
        "advisories": ["GHSA-demo"],
        "repo": "demo/app",
        "clean_commit": overrides.pop("clean_commit", "c" * 40),
        "regressed_commit": overrides.pop("regressed_commit", "r" * 40),
        "vulnerability_class": "path-traversal",
        "flow": flow(["app/views.py::download"], ["app/files.py::read_file", "app/files.py::_safe_path"],
                     ["app/files.py::read_file"]),
        "slice": {"app/views.py": ["download"], "app/files.py": ["read_file", "ROOT"]},
    }
    spec.update(overrides)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def test_spec_rejects_an_unknown_source_kind(tmp_path):
    path = write_spec(tmp_path, flow={"entry": [loc("a.py::f", "keyboard")],
                                      "guards": [loc("a.py::f")], "sinks": [loc("a.py::f", "sql")]})

    with pytest.raises(SpecError, match="entry kind"):
        load_spec(path)


def test_spec_rejects_a_class_outside_the_injection_family(tmp_path):
    with pytest.raises(SpecError, match="vulnerability_class"):
        load_spec(write_spec(tmp_path, vulnerability_class="xss"))


def test_flow_symbols_are_added_to_the_slice(tmp_path):
    spec = load_spec(write_spec(tmp_path))

    assert slice_requests(spec) == {"app/files.py": ["read_file", "ROOT", "_safe_path"],
                                    "app/views.py": ["download"]}


# --- Building a dossier from real history ----------------------------------


@pytest.fixture
def repo(tmp_path):
    origin = Origin(tmp_path / "origin")
    vulnerable = origin.commit({"app/views.py": VIEWS, "app/files.py": FILES_VULNERABLE}, "start")
    fixed = origin.commit({"app/files.py": FILES_FIXED}, "resolve names under the root")
    return {"dir": origin.root, "vulnerable": vulnerable, "fixed": fixed}


@pytest.fixture
def built(repo, tmp_path):
    spec = write_spec(tmp_path / "events" / "demo-0001",
                      clean_commit=repo["fixed"], regressed_commit=repo["vulnerable"])
    return spec.parent, build_event(spec, repo["dir"])


def test_writes_trimmed_clean_and_regressed_slices(built):
    out, _ = built
    clean = (out / "clean" / "app" / "files.py").read_text(encoding="utf-8")
    regressed = (out / "regressed" / "app" / "files.py").read_text(encoding="utf-8")

    assert "def _safe_path(name):" in clean and "_safe_path" not in regressed
    assert "list_files" not in clean and "list_files" not in regressed
    assert (out / "clean" / "app" / "views.py").read_text(encoding="utf-8") == (
        out / "regressed" / "app" / "views.py").read_text(encoding="utf-8")


def test_strips_the_revealing_comment_and_records_it(built):
    out, event = built

    assert "CVE" not in (out / "clean" / "app" / "files.py").read_text(encoding="utf-8")
    assert event["scrubbed"]["clean"] == [{"path": "app/files.py", "line": 7, "kind": "comment",
                                           "text": "# fix CVE-2024-0001: block path traversal"}]
    assert event["scrubbed"]["regressed"] == []


def test_derives_scope_and_regression_files(built):
    _, event = built

    assert event["regression_files"] == ["app/files.py"]
    assert event["flow_files"] == ["app/files.py", "app/views.py"]
    assert event["scope"] == CROSS_FILE


def test_regression_diff_undoes_the_fix(built):
    out, _ = built
    diff = (out / "regression.diff").read_text(encoding="utf-8")

    assert diff.startswith("--- a/app/files.py\n+++ b/app/files.py\n")
    assert "-    path = _safe_path(name)\n+    path = os.path.join(ROOT, name)\n" in diff


def test_all_checks_pass_on_a_consistent_spec(built):
    _, event = built

    statuses = {c["name"]: c["status"] for c in event["checks"]}
    assert statuses == {"commits": "ok", "symbols-found": "ok", "flow-present": "ok",
                        "regression-nonempty": "ok", "parses": "ok", "size": "ok",
                        "dropped-references": "ok", "flagged-strings": "ok"}


def test_event_json_matches_the_return_value(built):
    out, event = built

    assert json.loads((out / "event.json").read_text(encoding="utf-8")) == event


def test_rebuilding_is_deterministic(built, repo):
    out, first = built
    before = {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}

    build_event(out / "spec.json", repo["dir"])

    after = {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}
    assert before == after


def test_cut_references_and_security_wording_are_warnings(repo, tmp_path):
    spec = write_spec(tmp_path / "e", clean_commit=repo["fixed"], regressed_commit=repo["vulnerable"],
                      slice={"app/views.py": ["download"], "app/files.py": ["read_file"]})

    checks = {c["name"]: c for c in build_event(spec, repo["dir"])["checks"]}

    assert checks["dropped-references"]["status"] == "warn"
    assert "app/files.py::ROOT" in checks["dropped-references"]["detail"]


def test_a_missing_symbol_fails(repo, tmp_path):
    spec = write_spec(tmp_path / "e", clean_commit=repo["fixed"], regressed_commit=repo["vulnerable"],
                      slice={"app/views.py": ["download", "nope"], "app/files.py": ["read_file"]})

    checks = {c["name"]: c for c in build_event(spec, repo["dir"])["checks"]}

    assert checks["symbols-found"] == {"name": "symbols-found", "status": "fail",
                                       "detail": "missing in both variants: app/views.py::nope"}


def test_swapped_commits_fail_the_ancestry_check(repo, tmp_path):
    spec = write_spec(tmp_path / "e", clean_commit=repo["vulnerable"], regressed_commit=repo["fixed"])

    checks = {c["name"]: c["status"] for c in build_event(spec, repo["dir"])["checks"]}

    assert checks["commits"] == "fail"
    assert checks["flow-present"] == "fail"  # the guard only exists in the fixed commit


def test_oversized_slice_fails(repo, tmp_path):
    spec = write_spec(tmp_path / "e", clean_commit=repo["fixed"], regressed_commit=repo["vulnerable"])

    event = build_event(spec, repo["dir"], soft_limit=50, hard_limit=100)

    assert {c["name"]: c["status"] for c in event["checks"]}["size"] == "fail"


def test_guard_not_changed_by_the_regression_fails_the_scope_check(repo, tmp_path):
    bad = flow(["app/views.py::download"], ["app/views.py::download"], ["app/files.py::read_file"])
    spec = write_spec(tmp_path / "e", clean_commit=repo["fixed"], regressed_commit=repo["vulnerable"],
                      flow=bad)

    event = build_event(spec, repo["dir"])

    assert event["scope"] is None
    assert {c["name"]: c["status"] for c in event["checks"]}["scope"] == "fail"


def test_local_event_end_to_end(tmp_path):
    origin = Origin(tmp_path / "origin")
    vulnerable = origin.commit({"svc.py": "import subprocess\n\n\ndef run(args):\n"
                                          "    return subprocess.run(args['cmd'], shell=True)\n"}, "a")
    fixed = origin.commit({"svc.py": "import shlex\nimport subprocess\n\n\ndef run(args):\n"
                                     "    return subprocess.run(shlex.split(args['cmd']))\n"}, "b")
    spec = write_spec(tmp_path / "e", clean_commit=fixed, regressed_commit=vulnerable,
                      vulnerability_class="os-command",
                      flow={"entry": [loc("svc.py::run", "library-api")], "guards": [loc("svc.py::run")],
                            "sinks": [loc("svc.py::run", "subprocess")]},
                      slice={"svc.py": ["run"]})

    event = build_event(spec, origin.root)

    assert event["scope"] == LOCAL
    assert all(c["status"] == "ok" for c in event["checks"])
