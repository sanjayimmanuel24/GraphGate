"""Tests for static-analysis findings and their comparison across a change."""

from graphgate.gate.findings import (
    FAMILY_CWES,
    ChangeFindings,
    Finding,
    cwe_numbers,
    in_family,
    lines_of,
)


def finding(code="os.system(cmd)", line=10, rule="B605", tool="bandit", path="app.py", cwes=(78,)):
    return Finding(tool=tool, rule_id=rule, cwes=cwes, severity="high", confidence="high", path=path,
                   start_line=line, end_line=line, message="m", code=code)


def test_cwe_numbers_reads_every_form_the_tools_use():
    assert cwe_numbers(78) == (78,)
    assert cwe_numbers("CWE-89: Improper Neutralization of Special Elements used in an SQL Command") == (89,)
    assert cwe_numbers(["CWE-78: OS Command Injection", "CWE-22: Path Traversal", "CWE-78: again"]) == (22, 78)
    assert cwe_numbers(None) == () and cwe_numbers([]) == ()


def test_family_is_the_four_injection_cwes():
    assert FAMILY_CWES == {22, 77, 78, 89}
    assert in_family(finding(cwes=(78,))) and in_family(finding(cwes=(79, 89)))
    assert not in_family(finding(cwes=(95,))) and not in_family(finding(cwes=()))
    assert in_family(finding(cwes=(95,)), cwes={95})   # the family is a setting, not a constant


def test_lines_of_is_one_based_and_inclusive():
    assert lines_of("a\nb\nc\nd\n", 2, 3) == "b\nc"


def test_a_finding_survives_a_round_trip_through_json():
    original = finding(cwes=(22, 78))

    assert Finding.from_dict(original.to_dict()) == original


def test_a_finding_that_only_moved_is_not_new():
    before = (finding(line=10),)
    after = (finding(line=14, code="    os.system( cmd )"),)   # moved down and re-indented

    change = ChangeFindings(before=before, after=after)

    assert change.introduced == () and change.resolved == ()


def test_new_and_removed_findings_are_told_apart():
    kept = finding(code="os.system(a)")
    change = ChangeFindings(before=(kept, finding(code="os.system(old)")),
                            after=(kept, finding(code="os.system(new)"), finding(rule="B602", code="run(x, shell=True)")))

    assert [f.code for f in change.introduced] == ["os.system(new)", "run(x, shell=True)"]
    assert [f.code for f in change.resolved] == ["os.system(old)"]


def test_a_second_copy_of_a_flagged_line_counts_as_new():
    one = finding(line=5)
    change = ChangeFindings(before=(one,), after=(one, finding(line=20)))

    assert len(change.introduced) == 1 and change.resolved == ()


def test_the_same_code_under_another_rule_tool_or_file_is_a_different_finding():
    base = finding()

    for other in (finding(rule="B602"), finding(tool="semgrep"), finding(path="other.py")):
        assert ChangeFindings(before=(base,), after=(other,)).introduced == (other,)
