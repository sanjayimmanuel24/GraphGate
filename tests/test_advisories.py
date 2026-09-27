"""Tests for injection-advisory extraction from OSV entries."""

from graphgate.dataset.advisories import extract_injection_advisories, group_by_repo


def ghsa(id_="GHSA-aaaa-bbbb-cccc", cwes=("CWE-89",), refs=(), aliases=("CVE-2024-0001",), **extra):
    entry = {
        "id": id_,
        "aliases": list(aliases),
        "summary": "SQL injection in thing",
        "published": "2024-01-01T00:00:00Z",
        "database_specific": {"cwe_ids": list(cwes), "severity": "HIGH"},
        "affected": [{"package": {"name": "thing", "ecosystem": "PyPI"}}],
        "references": [{"type": t, "url": u} for t, u in refs],
    }
    entry.update(extra)
    return entry


COMMIT = ("WEB", "https://github.com/Owner/Thing/commit/0123456789abcdef0123456789abcdef01234567")
PACKAGE = ("PACKAGE", "https://github.com/Owner/Thing")


def test_keeps_an_injection_advisory_with_its_fix_commit():
    [adv], _ = extract_injection_advisories([ghsa(refs=[COMMIT, PACKAGE])])

    assert adv.repo == "owner/thing"
    assert adv.fix_commits == ["0123456789abcdef0123456789abcdef01234567"]
    assert adv.classes == ["sql"]
    assert adv.cve == "CVE-2024-0001"


def test_each_in_scope_cwe_maps_to_its_class():
    entries = [
        ghsa(id_=f"GHSA-{i}", cwes=(cwe,), aliases=(f"CVE-2024-000{i}",), refs=[COMMIT])
        for i, cwe in enumerate(["CWE-89", "CWE-78", "CWE-77", "CWE-22"])
    ]
    advisories, _ = extract_injection_advisories(entries)
    assert [a.classes for a in advisories] == [["sql"], ["os-command"], ["command"], ["path-traversal"]]


def test_out_of_scope_cwes_are_skipped_and_counted():
    """XSS is out of scope (CLAUDE.md); skipping it must be visible in the tally."""
    advisories, skipped = extract_injection_advisories([ghsa(cwes=("CWE-79",), refs=[COMMIT])])
    assert advisories == []
    assert skipped == {"no injection-class CWE": 1}


def test_a_mixed_advisory_keeps_only_its_in_scope_cwes():
    [adv], _ = extract_injection_advisories([ghsa(cwes=("CWE-79", "CWE-89"), refs=[COMMIT])])
    assert adv.cwes == ["CWE-89"]


def test_withdrawn_and_non_ghsa_entries_are_skipped():
    entries = [
        ghsa(refs=[COMMIT], withdrawn="2024-02-01T00:00:00Z"),
        {"id": "PYSEC-2024-1", "references": [{"type": "WEB", "url": COMMIT[1]}]},
        {"id": "MAL-2024-1"},
    ]
    advisories, skipped = extract_injection_advisories(entries)
    assert advisories == []
    assert skipped == {"withdrawn": 1, "not GHSA (no CWE ids)": 2}


def test_duplicate_cves_are_counted_once():
    entries = [ghsa(id_="GHSA-1", refs=[COMMIT]), ghsa(id_="GHSA-2", refs=[COMMIT])]
    advisories, skipped = extract_injection_advisories(entries)
    assert [a.id for a in advisories] == ["GHSA-1"]
    assert skipped == {"duplicate CVE": 1}


def test_commit_urls_inside_pull_requests_and_git_suffixes_are_parsed():
    refs = [
        ("WEB", "https://github.com/owner/thing/pull/42/commits/abcdef1234567"),
        ("FIX", "https://github.com/owner/thing.git/commit/1234567abcdef"),
    ]
    [adv], _ = extract_injection_advisories([ghsa(refs=refs)])
    assert adv.repo == "owner/thing"
    assert adv.fix_commits == ["abcdef1234567", "1234567abcdef"]


def test_backport_commits_are_all_kept():
    refs = [("WEB", f"https://github.com/owner/thing/commit/{c * 40}") for c in "abc"]
    [adv], _ = extract_injection_advisories([ghsa(refs=refs)])
    assert len(adv.fix_commits) == 3


def test_git_range_fixed_events_count_as_fix_commits():
    entry = ghsa(refs=[PACKAGE])
    entry["affected"][0]["ranges"] = [{
        "type": "GIT",
        "repo": "https://github.com/owner/thing",
        "events": [{"introduced": "0"}, {"fixed": "f" * 40}],
    }]
    [adv], _ = extract_injection_advisories([entry])
    assert adv.fix_commits == ["f" * 40]


def test_the_repo_with_most_fix_commits_wins_over_a_vendored_copy():
    refs = [
        ("WEB", "https://github.com/owner/thing/commit/" + "a" * 40),
        ("WEB", "https://github.com/owner/thing/commit/" + "b" * 40),
        ("WEB", "https://github.com/someone/vendored/commit/" + "c" * 40),
    ]
    [adv], _ = extract_injection_advisories([ghsa(refs=refs)])
    assert adv.repo == "owner/thing"
    assert adv.other_repos == ["someone/vendored"]


def test_advisory_without_a_fix_commit_is_kept_but_not_grouped():
    """No fix commit means no vulnerable/fixed pair to invert — it cannot become a
    ground-truth event, but it stays in the extract for the audit trail."""
    advisories, _ = extract_injection_advisories([ghsa(refs=[PACKAGE])])
    assert advisories[0].repo == "owner/thing"
    assert advisories[0].fix_commits == []
    assert group_by_repo(advisories) == {}


def test_group_by_repo_collects_advisories_per_project():
    entries = [
        ghsa(id_="GHSA-1", aliases=("CVE-1",), refs=[COMMIT]),
        ghsa(id_="GHSA-2", aliases=("CVE-2",), refs=[COMMIT]),
        ghsa(id_="GHSA-3", aliases=("CVE-3",),
             refs=[("WEB", "https://github.com/other/proj/commit/" + "d" * 40)]),
    ]
    advisories, _ = extract_injection_advisories(entries)
    groups = group_by_repo(advisories)
    assert {k: [a.id for a in v] for k, v in groups.items()} == {
        "owner/thing": ["GHSA-1", "GHSA-2"],
        "other/proj": ["GHSA-3"],
    }
