"""Tests for selecting and pinning the Semgrep rule set."""

import json
from pathlib import Path

import pytest

from graphgate.gate.rules import (
    COMMIT,
    RECLASSIFIED,
    RuleSetError,
    build,
    check_id,
    declared_cwes,
    load_ruleset,
    select,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def rule(rule_id: str, cwe_block: str, message: str = "Avoid this.") -> str:
    return (f"rules:\n- id: {rule_id}\n  pattern: os.system(...)\n  message: {message}\n"
            f"  metadata:\n{cwe_block}    category: security\n  severity: ERROR\n  languages: [python]\n")


LIST_78 = "    cwe:\n    - \"CWE-78: Improper Neutralization of Special Elements used in an OS Command\"\n"
INLINE_89 = "    cwe: 'CWE-89: SQL Injection'\n"
LIST_79 = "    cwe:\n    - 'CWE-79: Cross-site Scripting'\n"
LIST_704 = "    cwe:\n    - 'CWE-704: Incorrect Type Conversion or Cast'\n"


@pytest.fixture
def upstream(tmp_path):
    """A stand-in for a checkout of the community rules."""
    files = {
        "python/lang/security/system-call.yaml": rule("system-call", LIST_78),
        "python/flask/security/raw-query.yaml": rule("raw-query", INLINE_89),
        "python/flask/security/xss.yaml": rule("xss", LIST_79),
        # Mentions an injection CWE in its message only; its own CWE is another.
        "python/lang/security/mentions.yaml": rule("mentions", LIST_79, "See CWE-78 for the related risk."),
        "python/flask/security/injection/tainted-sql-string.yaml": rule("tainted-sql-string", LIST_704),
        "python/lang/security/system-call.test.yaml": rule("system-call", LIST_78),
        "python/lang/security/system-call.py": "import os\nos.system('ls')\n",
        "javascript/lang/security/exec.yaml": rule("exec", LIST_78),
    }
    for rel, text in files.items():
        path = tmp_path / "upstream" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="")
    return tmp_path / "upstream"


def test_declared_cwes_come_from_the_metadata_entry_only():
    assert declared_cwes(rule("a", LIST_78)) == (78,)
    assert declared_cwes(rule("a", INLINE_89)) == (89,)
    assert declared_cwes(rule("a", LIST_79, "See CWE-78 and CWE-89.")) == (79,)
    assert declared_cwes(rule("a", "")) == ()
    two = "    cwe:\n    - 'CWE-22: Path Traversal'\n    - 'CWE-73: External Control of File Name'\n"
    assert declared_cwes(rule("a", two)) == (22, 73)


def test_selection_keeps_python_rules_that_declare_a_family_cwe(upstream):
    selected = {r["path"]: r for r in select(upstream)}

    assert sorted(selected) == [
        "python/flask/security/injection/tainted-sql-string.yaml",   # counted as CWE-89, see below
        "python/flask/security/raw-query.yaml",
        "python/lang/security/system-call.yaml",
    ]
    assert selected["python/lang/security/system-call.yaml"]["family_cwes"] == [78]


def test_a_rule_filed_upstream_under_another_cwe_is_counted_and_marked(upstream):
    path = "python/flask/security/injection/tainted-sql-string.yaml"
    assert RECLASSIFIED[path] == 89

    entry = next(r for r in select(upstream) if r["path"] == path)

    assert entry["declared_cwes"] == [704] and entry["family_cwes"] == [89]


def test_another_family_selects_other_rules(upstream):
    assert [r["path"] for r in select(upstream, cwes={79})] == [
        "python/flask/security/xss.yaml", "python/lang/security/mentions.yaml"]


def test_build_copies_the_selection_and_describes_it(upstream, tmp_path):
    dest = tmp_path / "selected"
    (dest / "python/old").mkdir(parents=True)
    (dest / "python/old/dropped.yaml").write_text("rules: []\n", encoding="utf-8")   # from an earlier selection

    manifest = build(upstream, dest)

    copied = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*.yaml"))
    assert copied == [r["path"] for r in manifest["rules"]] and "python/old/dropped.yaml" not in copied
    assert manifest["commit"] == COMMIT and manifest["rule_files"] == 3
    assert manifest["rule_files_by_cwe"] == {"22": 0, "77": 0, "78": 1, "89": 2}
    assert set(manifest["reclassified"]) == set(RECLASSIFIED)


def test_the_selection_hashes_the_same_whatever_the_line_endings(upstream, tmp_path):
    first = build(upstream, tmp_path / "a")["ruleset_sha256"]
    for path in upstream.rglob("*.yaml"):
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))   # as git checks out on Windows

    assert build(upstream, tmp_path / "b")["ruleset_sha256"] == first


def test_load_ruleset_accepts_only_the_pinned_files(upstream, tmp_path):
    dest, manifest_path = tmp_path / "selected", tmp_path / "rules.json"
    manifest_path.write_text(json.dumps(build(upstream, dest)), encoding="utf-8")

    ruleset = load_ruleset(manifest_path, dest)
    assert ruleset.config == "python" and ruleset.root == dest
    assert ruleset.reclassified["python.flask.security.injection.tainted-sql-string"] == 89

    target = dest / "python/lang/security/system-call.yaml"
    target.write_text(target.read_text(encoding="utf-8") + "# edited\n", encoding="utf-8")
    with pytest.raises(RuleSetError, match="not the set pinned"):
        load_ruleset(manifest_path, dest)


def test_missing_rules_or_manifest_say_how_to_get_them(tmp_path):
    with pytest.raises(RuleSetError, match="fetch_semgrep_rules"):
        load_ruleset(tmp_path / "none.json", tmp_path / "none")

    manifest = tmp_path / "rules.json"
    manifest.write_text(json.dumps({"ruleset_sha256": "x", "rule_files": 3, "commit": COMMIT,
                                    "reclassified": {}}), encoding="utf-8")
    with pytest.raises(RuleSetError, match="fetch_semgrep_rules"):
        load_ruleset(manifest, tmp_path / "none")


def test_check_id_is_the_dotted_rule_path():
    assert check_id("python/lang/security/dangerous-system-call.yaml") == "python.lang.security.dangerous-system-call"


def test_the_checked_in_manifest_pins_the_commit_the_code_names():
    manifest = json.loads((REPO_ROOT / "data" / "semgrep_rules.json").read_text(encoding="utf-8"))

    assert manifest["commit"] == COMMIT
    assert manifest["rule_files"] == len(manifest["rules"]) > 0
    assert sorted(manifest["family_cwes"]) == [22, 77, 78, 89]
    assert all(set(r["family_cwes"]) <= {22, 77, 78, 89} for r in manifest["rules"])
