"""Tests for leakage control (BUILD_PLAN 2.6)."""

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

from graphgate.dataset.events import BlobMissing, dossier_version
from graphgate.dataset.leakage import (
    FIX_TEST,
    MIN_TOKENS,
    NEAR_DUPLICATE,
    THRESHOLD,
    build_report,
    code_tokens,
    fix_changed_files,
    load_exclusions,
    read_tree,
    regression_units,
    scan_event,
    similarity,
)
from gitrepo import Origin

REPO_ROOT = Path(__file__).resolve().parent.parent

GUARDED = '''\
import os

ROOT = "/srv/data"


def read_file(name, encoding="utf-8"):
    """Return the text of a stored file."""
    path = os.path.normpath(os.path.join(ROOT, name))
    if not path.startswith(ROOT + os.sep):
        raise ValueError("outside the data directory")
    with open(path, encoding=encoding) as handle:
        return handle.read()
'''

UNGUARDED = '''\
import os

ROOT = "/srv/data"


def read_file(name, encoding="utf-8"):
    """Return the text of a stored file."""
    path = os.path.join(ROOT, name)
    with open(path, encoding=encoding) as handle:
        return handle.read()
'''

VIEWS = '''\
from app.files import read_file


def download(request):
    return read_file(request.args["name"])
'''

UNRELATED = '''\
def total(orders, rate=0.2):
    amount = 0
    for order in orders:
        amount += order.quantity * order.unit_price
    return round(amount * (1 + rate), 2)
'''


# --- Tokens and similarity ----------------------------------------------------


def test_tokens_ignore_comments_docstrings_layout_and_quote_style():
    plain = "def f(a):\n    return open(a, 'r').read()\n"
    dressed = ('def f( a ):\n    """Read it."""\n    # all at once\n'
               '    return open(a,\n                "r").read()\n')

    assert code_tokens(plain) == code_tokens(dressed)
    assert "Read" not in " ".join(code_tokens(dressed))


def test_code_python_cannot_parse_is_still_tokenised():
    tokens = code_tokens("def f(a):\n    print a  # python 2\n")

    assert tokens == ("def", "f", "(", "a", ")", ":", "print", "a")


def test_similarity_is_one_for_copies_and_low_for_unrelated_code():
    guarded, unguarded, other = (code_tokens(t) for t in (GUARDED, UNGUARDED, UNRELATED))

    assert similarity(guarded, guarded) == 1.0
    assert 0.7 < similarity(guarded, unguarded) < 1.0   # the same function with its guard removed
    assert similarity(guarded, other) < 0.5


# --- What counts as part of the regression ------------------------------------


def test_regression_units_are_the_functions_and_assignments_that_changed():
    clean = {"a.py": GUARDED + "\n\nLIMIT = 10\n\n\ndef helper(x):\n    return x + 1\n", "b.py": VIEWS}
    regressed = {"a.py": UNGUARDED + "\n\nLIMIT = 99\n\n\ndef extra(x):\n    return x\n", "b.py": VIEWS}

    found = {(u.kind, u.symbol): sorted(u.versions) for u in regression_units(clean, regressed)}

    assert found == {
        ("def", "read_file"): ["clean", "regressed"],   # changed
        ("assign", "LIMIT"): ["clean", "regressed"],    # changed
        ("def", "helper"): ["clean"],                   # removed by the regression
        ("def", "extra"): ["regressed"],                # added by it
    }


def test_a_change_to_comments_or_docstrings_is_not_part_of_the_regression():
    commented = GUARDED.replace('"""Return the text of a stored file."""',
                                '"""Read a file."""\n    # check the path first')

    assert regression_units({"a.py": GUARDED}, {"a.py": commented}) == []


# --- Scanning a repository ----------------------------------------------------


@pytest.fixture
def project(tmp_path):
    """A repository with a fix commit, and the event cut from it.

    Besides the slice (app/files.py, app/views.py) the repository holds a twin
    of the fixed function, an old copy of the vulnerable one, unrelated code,
    and two test files, only one of which the fix touched.
    """
    (tmp_path / "repos").mkdir()
    origin = Origin(tmp_path / "repos" / "acme__store")
    common = {
        "app/views.py": VIEWS,
        "app/billing.py": UNRELATED,
        "legacy/files.py": UNGUARDED.replace("def read_file", "def read_old_file"),
        "tests/test_views.py": "def test_download():\n    assert True\n",
    }
    vulnerable = origin.commit({**common, "app/files.py": UNGUARDED,
                                "app/mirror.py": UNGUARDED.replace("def read_file", "def read_mirror")},
                               "initial")
    fixed = origin.commit({"app/files.py": GUARDED,
                           "app/mirror.py": GUARDED.replace("def read_file", "def read_mirror"),
                           "tests/test_files.py": "def test_rejects_parent_paths():\n    assert True\n"},
                          "check paths")

    event = tmp_path / "events" / "store-0001"
    for variant, text in (("clean", GUARDED), ("regressed", UNGUARDED)):
        (event / variant / "app").mkdir(parents=True)
        (event / variant / "app" / "files.py").write_text(text, encoding="utf-8")
        (event / variant / "app" / "views.py").write_text(VIEWS, encoding="utf-8")
    (event / "event.json").write_text(json.dumps(
        {"repo": "acme/store", "clean_commit": fixed, "regressed_commit": vulnerable}), encoding="utf-8")
    return tmp_path, origin, event


def test_scan_finds_twins_and_the_fixs_tests_outside_the_slice(project):
    _, origin, event = project

    result = scan_event(event, origin.root)

    assert result["scanned"]["files"] == 5   # everything but the slice's two files
    near = {(d["path"], d["symbol"]): (d["version"], d["similarity"]) for d in result["near_duplicates"]}
    assert near[("app/mirror.py", "read_mirror")][0] == "clean"        # the fixed twin
    assert near[("legacy/files.py", "read_old_file")][0] == "regressed"  # an old vulnerable copy
    assert all(score >= 0.9 for _, score in near.values())
    assert ("app/billing.py", "total") not in near
    assert not any(path == "app/files.py" for path, _ in near)          # the slice itself

    assert result["fix_files"] == [
        {"path": "app/mirror.py", "status": "M", "kind": "source", "excluded": False},
        {"path": "tests/test_files.py", "status": "A", "kind": "test", "excluded": True},
    ]
    assert result["exclusions"] == [
        {"path": "tests/test_files.py", "symbol": None, "reason": FIX_TEST},
        {"path": "app/mirror.py", "symbol": "read_mirror", "reason": NEAR_DUPLICATE},
        {"path": "legacy/files.py", "symbol": "read_old_file", "reason": NEAR_DUPLICATE},
    ]


def test_every_regression_unit_is_reported_with_its_closest_match(project):
    _, origin, event = project
    for variant, text in (("clean", GUARDED + "\n\nLIMIT = 10\n"), ("regressed", UNGUARDED + "\n\nLIMIT = 99\n")):
        (event / variant / "app" / "files.py").write_text(text, encoding="utf-8")

    units = {u["symbol"]: u for u in scan_event(event, origin.root)["regression_units"]}

    assert units["read_file"]["compared"] and units["read_file"]["nearest"]["similarity"] >= 0.9
    assert units["read_file"]["tokens"]["clean"] > units["read_file"]["tokens"]["regressed"] >= MIN_TOKENS
    # Too short to tell a copy from a coincidence: listed, not silently skipped.
    assert units["LIMIT"]["compared"] is False and "too short" in units["LIMIT"]["note"]


def test_a_stricter_threshold_finds_fewer_duplicates(project):
    _, origin, event = project

    exact_only = scan_event(event, origin.root, threshold=1.0)

    assert exact_only["near_duplicates"] == []
    assert [e["reason"] for e in exact_only["exclusions"]] == [FIX_TEST]


def test_only_files_the_fix_added_or_modified_are_listed(project):
    _, origin, event = project
    commits = json.loads((event / "event.json").read_text(encoding="utf-8"))

    files = fix_changed_files(origin.root, commits["regressed_commit"], commits["clean_commit"])

    assert [(f["path"], f["kind"]) for f in files] == [
        ("app/files.py", "source"), ("app/mirror.py", "source"), ("tests/test_files.py", "test")]


def test_a_blob_the_clone_lacks_is_an_error_not_a_download(project, tmp_path):
    _, origin, event = project
    commit = json.loads((event / "event.json").read_text(encoding="utf-8"))["clean_commit"]
    partial = tmp_path / "partial"
    subprocess.run(["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout",
                    origin.url, str(partial)], check=True, capture_output=True)

    with pytest.raises(BlobMissing, match="not in the local clone"):
        list(read_tree(partial, commit))


# --- The report and its reader ------------------------------------------------


def test_report_round_trips_into_what_retrieval_reads(project, tmp_path):
    _, origin, event = project
    report = build_report({"store-0001": scan_event(event, origin.root)},
                          threshold=THRESHOLD, min_tokens=MIN_TOKENS)
    path = tmp_path / "leakage.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    exclusions = load_exclusions(path)["store-0001"]

    assert report["summary"]["near_duplicates"] == 2 and report["summary"]["fix_tests_excluded"] == 1
    assert report["summary"]["fix_sources_left_in_scope"] == 1
    assert exclusions.covers("tests/test_files.py")                       # the whole file
    assert exclusions.covers("tests/test_files.py", "test_rejects_parent_paths")
    assert exclusions.covers("app/mirror.py", "read_mirror")              # one symbol
    assert not exclusions.covers("app/mirror.py")                         # not the rest of its file
    assert not exclusions.covers("app/billing.py", "total")
    assert not exclusions.covers("tests/test_views.py")                   # a test the fix did not touch


def load_script():
    spec = importlib.util.spec_from_file_location("check_leakage", REPO_ROOT / "scripts" / "check_leakage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_script(root, *extra):
    return load_script().main([*extra, "--events-dir", str(root / "events"), "--repos", str(root / "repos"),
                               "--signoff", str(root / "signoff.json"), "--ai-review", str(root / "ai.json"),
                               "--out", str(root / "leakage.json")])


def test_script_scans_validated_events_and_writes_the_list(project, capsys):
    root, _, event = project
    review = {"event_id": "store-0001", "status": "sound"}
    (root / "ai.json").write_text(json.dumps({"results": [review]}), encoding="utf-8")

    assert run_script(root) == 1                      # nothing signed off yet
    assert not (root / "leakage.json").exists()

    (root / "signoff.json").write_text(json.dumps({"decisions": {"store-0001": {
        "decision": "accept", "dossier": dossier_version(event, review)}}}), encoding="utf-8")
    assert run_script(root) == 0

    report = json.loads((root / "leakage.json").read_text(encoding="utf-8"))
    assert list(report["events"]) == ["store-0001"]
    assert report["method"]["threshold"] == THRESHOLD and report["method"]["min_tokens"] == MIN_TOKENS
    assert "2 near-duplicate(s)" in capsys.readouterr().out


def test_script_preview_of_named_events_writes_nothing(project, capsys):
    root, _, _ = project
    (root / "ai.json").write_text(json.dumps({"results": []}), encoding="utf-8")

    assert run_script(root, "store-0001") == 0

    assert not (root / "leakage.json").exists()
    assert "preview only" in capsys.readouterr().out


# --- The list that is checked in ----------------------------------------------


def test_the_checked_in_list_matches_the_rule_and_never_excludes_a_slice_file():
    report = json.loads((REPO_ROOT / "data" / "leakage_exclusions.json").read_text(encoding="utf-8"))

    assert report["method"]["threshold"] == THRESHOLD and report["method"]["min_tokens"] == MIN_TOKENS
    for event_id, event in report["events"].items():
        slice_dir = REPO_ROOT / "data" / "events" / event_id / "clean"
        slice_paths = {p.relative_to(slice_dir).as_posix() for p in slice_dir.rglob("*.py")}
        assert not {e["path"] for e in event["exclusions"]} & slice_paths, event_id
        assert all(d["similarity"] >= THRESHOLD for d in event["near_duplicates"]), event_id
