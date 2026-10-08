"""Tests for the Semgrep and Bandit wrapper.

Most run against stand-ins that answer in the tools' real output format (taken
from Semgrep 1.179.0 and Bandit 1.9.4), so they need neither tool. The tests
marked ``slow`` run the real tools and are skipped where they are not installed.
"""

import json
import os
from pathlib import Path

import pytest

from graphgate.gate.analysers import (
    AnalyserError,
    FindingCache,
    StaticScanner,
    Tools,
    default_scanner,
)
from graphgate.gate.rules import RuleSet, RuleSetError

REPO_ROOT = Path(__file__).resolve().parent.parent

SYSTEM = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
SAFE = "def add(a, b):\n    return a + b\n"
BROKEN = "import os\n\ndef run(cmd):\n    os.system(cmd\n"


class FakeTools:
    """Semgrep and Bandit, reduced to three patterns but faithful in output shape."""

    def __init__(self, *, semgrep_skips=(), exit_code=None):
        self.calls = []
        self.semgrep_skips = semgrep_skips    # path fragments Semgrep "forgets" to scan
        self.exit_code = exit_code
        self.ignore_file_seen = False

    def __call__(self, args, cwd, env):
        tool = Path(args[0]).stem
        self.calls.append({"tool": tool, "args": args, "cwd": cwd, "env": env})
        if "--version" in args:
            return 0, ("1.2.3\n" if tool == "semgrep" else "bandit 4.5.6\n  python version = 3.12\n"), ""
        if self.exit_code is not None:
            return self.exit_code, "", f"{tool}: fatal error"
        root = Path(args[-1]) if tool == "semgrep" else Path(args[args.index("-r") + 1])
        files = sorted(root.rglob("*.py"))
        if tool == "semgrep":
            self.ignore_file_seen = (root / ".semgrepignore").is_file()
            return 0, json.dumps(self._semgrep(files)), ""
        output = self._bandit(files)
        return (1 if output["results"] else 0), json.dumps(output), ""

    def _semgrep(self, files):
        results, errors, scanned = [], [], []
        for path in files:
            if any(fragment in path.as_posix() for fragment in self.semgrep_skips):
                continue
            scanned.append(str(path))
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            if "os.system(cmd\n" in text:   # the unclosed call in BROKEN
                errors.append({"code": 3, "level": "warn", "message": "Syntax error", "path": str(path),
                               "type": ["PartialParsing", [{"path": str(path)}]]})
                continue
            for number, line in enumerate(lines, start=1):
                for needle, check, cwe, severity in (
                        ("os.system(", "python.lang.security.dangerous-system-call",
                         ["CWE-78: Improper Neutralization of Special Elements used in an OS Command"], "ERROR"),
                        ("eval(", "python.lang.security.audit.eval-detected",
                         ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"], "WARNING"),
                        ("tainted_sql(", "python.flask.security.injection.tainted-sql-string",
                         ["CWE-704: Incorrect Type Conversion or Cast"], "ERROR")):
                    if needle in line:
                        results.append({
                            "check_id": check, "path": str(path),
                            "start": {"line": number, "col": 5, "offset": 0},
                            "end": {"line": number, "col": 20, "offset": 15},
                            "extra": {"message": "Found  dynamic content\nin a call.", "severity": severity,
                                      "metadata": {"cwe": cwe, "confidence": "MEDIUM", "category": "security"},
                                      "lines": "requires login", "fingerprint": "requires login",
                                      "engine_kind": "OSS", "validation_state": "NO_VALIDATOR"}})
        return {"version": "1.2.3", "results": results, "errors": errors, "paths": {"scanned": scanned},
                "skipped_rules": []}

    def _bandit(self, files):
        results, errors, metrics = [], [], {"_totals": {}}
        for path in files:
            metrics[str(path)] = {"loc": 1}
            text = path.read_text(encoding="utf-8")
            if "os.system(cmd\n" in text:
                errors.append({"filename": str(path), "reason": "syntax error while parsing AST from file"})
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                if "os.system(" in line:
                    results.append({
                        "code": f"{number} {line}\n", "col_offset": 4, "end_col_offset": 18, "filename": str(path),
                        "issue_confidence": "HIGH", "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/78"},
                        "issue_severity": "HIGH", "issue_text": "Starting a process with a shell.",
                        "line_number": number, "line_range": [number], "more_info": "https://bandit",
                        "test_id": "B605", "test_name": "start_process_with_a_shell"})
                if line.startswith("assert "):
                    results.append({
                        "code": line, "col_offset": 0, "end_col_offset": 6, "filename": str(path),
                        "issue_confidence": "HIGH", "issue_cwe": {"id": 703, "link": "x"},
                        "issue_severity": "LOW", "issue_text": "Use of assert detected.",
                        "line_number": number, "line_range": [number], "more_info": "x",
                        "test_id": "B101", "test_name": "assert_used"})
        return {"errors": errors, "generated_at": "now", "metrics": metrics, "results": results}


@pytest.fixture
def ruleset(tmp_path):
    (tmp_path / "rules").mkdir()
    return RuleSet(root=tmp_path / "rules", sha256="abc123", commit="deadbeef",
                   reclassified={"python.flask.security.injection.tainted-sql-string": 89})


def make_scanner(ruleset, fake=None, **kwargs):
    fake = fake or FakeTools()
    tools = Tools(semgrep=Path("semgrep"), bandit=Path("bandit"))
    return StaticScanner(tools, ruleset, run=fake, **kwargs), fake


# --- Findings -----------------------------------------------------------------


def test_findings_come_back_per_file_with_snapshot_paths_and_real_code(ruleset):
    scanner, _ = make_scanner(ruleset)

    scans = scanner.scan_files({"app/run.py": SYSTEM, "app/maths.py": SAFE})

    found = scans["app/run.py"].findings
    assert [(f.tool, f.rule_id, f.cwes) for f in found] == [
        ("bandit", "B605", (78,)), ("semgrep", "python.lang.security.dangerous-system-call", (78,))]
    semgrep = found[1]
    assert (semgrep.path, semgrep.start_line, semgrep.code) == ("app/run.py", 5, "    os.system(cmd)")
    assert (semgrep.severity, semgrep.confidence) == ("high", "medium")
    assert semgrep.message == "Found dynamic content in a call."      # one line, whatever the tool sent
    assert found[0].message.startswith("start_process_with_a_shell:")
    assert scans["app/maths.py"].findings == () and scans["app/maths.py"].errors == ()


def test_findings_outside_the_family_are_dropped(ruleset):
    scanner, _ = make_scanner(ruleset)

    scan = scanner.scan_files({"a.py": "assert x\nvalue = eval(text)\n"})["a.py"]

    assert scan.findings == ()   # CWE-703 from Bandit and CWE-95 from Semgrep are not injection-family


def test_the_family_is_a_setting(ruleset):
    scanner, _ = make_scanner(ruleset, cwes={95})

    found = scanner.scan_files({"a.py": "value = eval(text)\nos.system(cmd)\n"})["a.py"].findings

    assert [f.rule_id for f in found] == ["python.lang.security.audit.eval-detected"]


def test_a_reclassified_rule_counts_under_the_family_cwe(ruleset):
    scanner, _ = make_scanner(ruleset)

    found = scanner.scan_files({"a.py": "rows = tainted_sql(name)\n"})["a.py"].findings

    assert [(f.rule_id.rsplit(".", 1)[-1], f.cwes) for f in found] == [("tainted-sql-string", (89, 704))]


# --- Nothing is skipped quietly -------------------------------------------------


def test_a_file_that_does_not_parse_is_reported_by_both_tools(ruleset):
    scanner, _ = make_scanner(ruleset)

    scan = scanner.scan_files({"app/run.py": BROKEN})["app/run.py"]

    assert scan.findings == ()
    assert scan.errors == ("semgrep: PartialParsing", "bandit: syntax error while parsing AST from file")


def test_a_file_semgrep_left_out_is_an_error(ruleset):
    scanner, _ = make_scanner(ruleset, FakeTools(semgrep_skips=("/tests/",)))

    with pytest.raises(AnalyserError, match=r"semgrep did not scan 1 file\(s\).*pkg/tests/run.py"):
        scanner.scan_files({"pkg/tests/run.py": SYSTEM, "pkg/run.py": SYSTEM})


def test_semgreps_default_ignore_list_is_replaced(ruleset):
    scanner, fake = make_scanner(ruleset)

    scanner.scan_files({"pkg/tests/run.py": SYSTEM})

    assert fake.ignore_file_seen


def test_a_failing_tool_stops_the_scan_with_its_message(ruleset):
    scanner, _ = make_scanner(ruleset, FakeTools(exit_code=2))

    with pytest.raises(AnalyserError, match="semgrep failed.*fatal error"):
        scanner.scan_files({"a.py": SYSTEM})


def test_a_path_that_leaves_the_snapshot_is_never_written(ruleset):
    scanner, fake = make_scanner(ruleset)

    scan = scanner.scan_files({"../outside.py": SYSTEM})["../outside.py"]

    assert scan.findings == () and "leaves the snapshot" in scan.errors[0]
    assert fake.calls == []   # nothing was materialised or run


def test_an_empty_file_needs_no_tool(ruleset):
    scanner, fake = make_scanner(ruleset)

    assert scanner.scan_files({"pkg/__init__.py": ""})["pkg/__init__.py"].findings == ()
    assert fake.calls == []


# --- One run for many versions, and never twice ----------------------------------


def test_one_run_per_tool_covers_every_new_version(ruleset):
    scanner, fake = make_scanner(ruleset)

    scans = scanner.scan([("a.py", SYSTEM), ("a.py", SAFE), ("b.py", SYSTEM)])   # two versions of a.py

    assert [c["tool"] for c in fake.calls] == ["semgrep", "bandit"] and scanner.runs == 2
    assert len(scans[("a.py", SYSTEM)].findings) == 2 and scans[("a.py", SAFE)].findings == ()
    assert scans[("b.py", SYSTEM)].findings[0].path == "b.py"

    scanner.scan([("a.py", SYSTEM), ("b.py", SYSTEM)])
    assert scanner.runs == 2   # known versions are not scanned again


def test_semgrep_runs_offline_from_the_rule_directory(ruleset):
    scanner, fake = make_scanner(ruleset)

    scanner.scan_files({"a.py": SYSTEM})

    call = fake.calls[0]
    assert call["cwd"] == ruleset.root and call["args"][1:4] == ["scan", "--config", "python"]
    assert {"--metrics=off", "--disable-version-check", "--no-git-ignore", "--json"} <= set(call["args"])
    env = call["env"]
    assert env["SEMGREP_SEND_METRICS"] == "off" and env["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    home = os.path.expanduser("~")
    for name in ("SEMGREP_SETTINGS_FILE", "SEMGREP_LOG_FILE"):      # kept out of the user's home
        assert "graphgate-scan-" in env[name] and not env[name].startswith(os.path.join(home, ".semgrep"))


def test_the_cache_file_carries_results_to_a_later_run(ruleset, tmp_path):
    with FindingCache(tmp_path / "cache.sqlite") as cache:
        first, _ = make_scanner(ruleset, cache=cache)
        expected = first.scan_files({"a.py": SYSTEM, "b.py": BROKEN})
    with FindingCache(tmp_path / "cache.sqlite") as cache:
        second, fake = make_scanner(ruleset, cache=cache)
        again = second.scan_files({"a.py": SYSTEM, "b.py": BROKEN})

        assert again == expected
        assert [c["tool"] for c in fake.calls if "--version" not in c["args"]] == []   # only the version check ran


def test_results_are_not_shared_between_tool_versions_or_rule_sets(ruleset, tmp_path):
    other_rules = RuleSet(root=ruleset.root, sha256="different", commit="x", reclassified={})
    scanner, _ = make_scanner(ruleset)
    other, _ = make_scanner(other_rules)

    assert scanner.config != other.config
    assert scanner.config == "semgrep=1.2.3;bandit=4.5.6;rules=abc123;cwes=22,77,78,89"


# --- A change -------------------------------------------------------------------


def test_scan_change_compares_the_changed_files_only(ruleset):
    scanner, fake = make_scanner(ruleset)
    before = {"app/run.py": SAFE, "app/other.py": SYSTEM}
    after = {"app/run.py": SYSTEM, "app/other.py": SYSTEM, "app/new.py": SYSTEM}

    change = scanner.scan_change(before, after, ["app/run.py", "app/new.py"])

    assert change.findings.before == ()
    assert sorted({f.path for f in change.findings.introduced}) == ["app/new.py", "app/run.py"]
    assert change.errors == ()
    scanned = {Path(p).name for c in fake.calls for p in [c["args"][-1]]}
    assert len(fake.calls) == 2 and scanned   # app/other.py did not change and was never written out


def test_scan_change_reports_which_side_failed_to_parse(ruleset):
    scanner, _ = make_scanner(ruleset)

    change = scanner.scan_change({"a.py": SYSTEM}, {"a.py": BROKEN}, ["a.py"])

    assert [f.rule_id for f in change.findings.resolved] == ["B605", "python.lang.security.dangerous-system-call"]
    assert change.findings.introduced == ()
    assert change.errors == ("after a.py: semgrep: PartialParsing",
                             "after a.py: bandit: syntax error while parsing AST from file")


# --- Finding the tools ------------------------------------------------------------


def test_tools_are_found_in_the_projects_tools_environment(tmp_path, monkeypatch):
    monkeypatch.delenv("GRAPHGATE_TOOLS", raising=False)
    folder = tmp_path / ".venv-tools" / ("Scripts" if os.name == "nt" else "bin")
    folder.mkdir(parents=True)
    for name in ("semgrep", "bandit"):
        (folder / (f"{name}.exe" if os.name == "nt" else name)).write_text("", encoding="utf-8")

    tools = Tools.locate(tmp_path)

    assert tools.semgrep.parent == folder.resolve() and tools.bandit.stem == "bandit"


def test_missing_tools_say_how_to_install_them(tmp_path, monkeypatch):
    monkeypatch.delenv("GRAPHGATE_TOOLS", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))

    with pytest.raises(AnalyserError, match="requirements-analysers.txt"):
        Tools.locate(tmp_path)


# --- The real tools -----------------------------------------------------------------


def real_scanner():
    try:
        return default_scanner(REPO_ROOT)
    except (AnalyserError, RuleSetError) as exc:
        pytest.skip(f"analysers or pinned rules not installed: {str(exc).splitlines()[0]}")


def test_the_checked_in_first_look_adds_up():
    """data/static_first_look.json, which the paper quotes, is consistent with itself."""
    record = json.loads((REPO_ROOT / "data" / "static_first_look.json").read_text(encoding="utf-8"))

    events = record["events"]
    assert record["summary"]["events"] == len(events) > 0
    assert record["summary"]["with_introduced_finding"] == sum(bool(e["introduced"]) for e in events.values())
    groups = record["summary"]["by_class_and_scope"]
    assert sum(g["events"] for g in groups.values()) == len(events)
    assert all(f["cwes"] and set(f["cwes"]) & {22, 77, 78, 89}
               for e in events.values() for f in e["introduced"])


@pytest.mark.slow
def test_real_semgrep_and_bandit_agree_with_the_stand_ins():
    scanner = real_scanner()

    scans = scanner.scan([("app/run.py", SYSTEM), ("pkg/tests/run.py", SYSTEM), ("app/maths.py", SAFE),
                          ("app/broken.py", BROKEN)])

    assert scanner.versions() == {"semgrep": "1.179.0", "bandit": "1.9.4"}
    for path in ("app/run.py", "pkg/tests/run.py"):                # a tests/ directory is not skipped
        found = scans[(path, SYSTEM)].findings
        assert {"B605"} <= {f.rule_id for f in found if f.tool == "bandit"}
        semgrep = [f for f in found if f.tool == "semgrep"]
        assert semgrep and all(78 in f.cwes and f.rule_id.startswith("python.") for f in semgrep)
        assert all(f.path == path and f.code.strip() == "os.system(cmd)" for f in semgrep)
    assert scans[("app/maths.py", SAFE)] == type(scans[("app/maths.py", SAFE)])((), ())
    errors = scans[("app/broken.py", BROKEN)].errors
    assert any(e.startswith("semgrep:") for e in errors) and any(e.startswith("bandit:") for e in errors)
