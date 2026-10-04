"""Tests for injecting a known regression into refined code."""

import re
import textwrap
from pathlib import Path

import pytest

from graphgate.harness.injection import InjectionError, InjectionPlan, merge, units

CLEAN = textwrap.dedent('''\
    import os
    from safe import check_name

    ROOT = "/srv/data"


    class Store:
        allowed = ["a", "b"]

        def read(self, name):
            check_name(name)
            return open(os.path.join(ROOT, name)).read()

        def size(self, name):
            return os.path.getsize(os.path.join(ROOT, name))


    def _resolve(name):
        return os.path.realpath(os.path.join(ROOT, name))
    ''')

REGRESSED = textwrap.dedent('''\
    import os

    ROOT = "/srv/data"


    class Store:
        allowed = ["a", "b", "c"]

        def read(self, name):
            return open(os.path.join(ROOT, name)).read()

        def size(self, name):
            return os.path.getsize(os.path.join(ROOT, name))
    ''')

# What an earlier "improve readability" turn might have left behind: new
# docstrings and a renamed local, but the same function names.
REFINED = textwrap.dedent('''\
    """File storage helpers."""
    import os
    from safe import check_name

    ROOT = "/srv/data"


    class Store:
        """Reads files under ROOT."""

        allowed = ["a", "b"]

        def read(self, name):
            check_name(name)
            return open(os.path.join(ROOT, name)).read()

        def size(self, filename):
            """Size of a stored file in bytes."""
            return os.path.getsize(os.path.join(ROOT, filename))


    def _resolve(name):
        return os.path.realpath(os.path.join(ROOT, name))
    ''')


def test_units_name_functions_members_and_scaffolding():
    keys = [u.key for u in units(CLEAN)]

    assert ("import", "", "import os", 0) in keys
    assert ("assign", "ROOT", 0) in keys
    assert ("class", "Store", 0) in keys
    assert ("assign", "Store.allowed", 0) in keys
    assert ("def", "Store.read", 0) in keys
    assert ("def", "_resolve", 0) in keys


def test_merging_into_the_clean_text_gives_the_regressed_text():
    merged, notes = merge(CLEAN, CLEAN, REGRESSED)

    assert merged == REGRESSED
    assert notes == []


def test_regression_lands_in_refined_code_and_keeps_the_refinements():
    merged, _ = merge(REFINED, CLEAN, REGRESSED)

    # The regression: guard call, its import, the helper and the attribute.
    assert "check_name" not in merged
    assert "_resolve" not in merged
    assert 'allowed = ["a", "b", "c"]' in merged
    # Refinements outside the changed units survive.
    assert '"""File storage helpers."""' in merged
    assert '"""Reads files under ROOT."""' in merged
    assert "def size(self, filename):" in merged


def test_a_unit_only_the_regressed_version_has_is_added_back():
    clean = "import os\n\n\ndef a():\n    return 1\n"
    regressed = "import os\n\n\ndef a():\n    return 1\n\n\ndef legacy():\n    return a()\n"
    refined = 'import os\n\n\ndef a():\n    """One."""\n    return 1\n'

    merged, _ = merge(refined, clean, regressed)

    assert merged.endswith("def legacy():\n    return a()\n")
    assert '"""One."""' in merged


def test_replaced_method_is_reindented_to_where_it_now_lives():
    clean = "class A:\n    def m(self):\n        return check(1)\n"
    regressed = "class A:\n    def m(self):\n        return 1\n"
    refined = "class A:\n        def m(self):\n                return check(1)\n"  # 8-space style

    merged, _ = merge(refined, clean, regressed)

    assert merged == "class A:\n        def m(self):\n            return 1\n"


def test_a_renamed_function_makes_the_injection_fail():
    renamed = REFINED.replace("def read(self, name):", "def read_file(self, name):")

    with pytest.raises(InjectionError, match="Store.read"):
        merge(renamed, CLEAN, REGRESSED)


def test_a_helper_that_is_already_gone_is_only_noted():
    without_helper = REFINED.split("\n\ndef _resolve")[0] + "\n"

    merged, notes = merge(without_helper, CLEAN, REGRESSED)

    assert "check_name" not in merged
    assert any("_resolve" in n and "no longer there" in n for n in notes)


# --- The plan -----------------------------------------------------------------


def plan(turn=3):
    return InjectionPlan.from_files(
        "demo", turn,
        clean={"store.py": CLEAN, "views.py": "x = 1\n", "new_guard.py": "def g():\n    pass\n"},
        regressed={"store.py": REGRESSED, "views.py": "x = 1\n"},
    )


def test_plan_keeps_only_the_files_the_regression_changes():
    p = plan()

    assert sorted(p.regressed) == ["new_guard.py", "store.py"]
    assert p.regressed["new_guard.py"] is None  # the fix added this file


def test_untouched_file_is_swapped_whole_and_added_file_is_removed():
    files, report = plan().apply({"store.py": CLEAN, "views.py": "x = 1\n",
                                  "new_guard.py": "def g():\n    pass\n"})

    assert files == {"store.py": REGRESSED, "views.py": "x = 1\n"}
    assert report["files"] == {"store.py": "swapped", "new_guard.py": "removed"}


def test_refined_file_is_merged():
    files, report = plan().apply({"store.py": REFINED, "views.py": "x = 2\n"})

    assert report["files"]["store.py"] == "merged"
    assert "check_name" not in files["store.py"]
    assert files["views.py"] == "x = 2\n"  # untouched by the regression


def test_plan_round_trips_through_a_dict():
    p = plan()

    assert InjectionPlan.from_dict(p.to_dict()) == p


def test_identical_versions_are_rejected():
    with pytest.raises(InjectionError, match="identical"):
        InjectionPlan.from_files("demo", 2, {"a.py": "x = 1\n"}, {"a.py": "x = 1\n"})


# --- Every real dossier ---------------------------------------------------------


def _changed_files():
    root = Path(__file__).resolve().parent.parent / "data" / "events"
    for clean in sorted(root.glob("*/clean/**/*.py")):
        event = clean.relative_to(root).parts[0]
        regressed = root / event / "regressed" / clean.relative_to(root / event / "clean")
        if regressed.exists() and regressed.read_bytes() != clean.read_bytes():
            yield pytest.param(clean, regressed, id=f"{event}:{clean.name}")


@pytest.mark.parametrize("clean, regressed", list(_changed_files()))
def test_merge_reproduces_every_real_regression(clean, regressed):
    """The unit merge, applied to the clean file, must give the regressed file."""
    clean_text, regressed_text = clean.read_text(encoding="utf-8"), regressed.read_text(encoding="utf-8")

    merged, _ = merge(clean_text, clean_text, regressed_text)

    squeeze = lambda s: re.sub(r"\n\s*\n+", "\n", s).strip()  # blank lines aside
    assert squeeze(merged) == squeeze(regressed_text)
