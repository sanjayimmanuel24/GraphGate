"""Tests for stripping security-revealing comments from extracted code."""

import ast
import textwrap

import pytest

from graphgate.dataset.scrub import REVEALING, scrub


@pytest.mark.parametrize("text", [
    "# fix CVE-2023-41040", "# see GHSA-cwvm-v4w8-q58c", "# CWE-22", "# reported via huntr",
    "# prevent path traversal", "# avoid SQL injection", "# security fix", "# RCE",
    "# block malicious input", "# arbitrary file read",
])
def test_revealing_wording_matches(text):
    assert REVEALING.search(text)


@pytest.mark.parametrize("text", [
    "# resolve the path", "# normalise the name", "# validate input", "# sanitize the header",
    "# build the query", "# join with the root",
])
def test_neutral_wording_does_not_match(text):
    assert not REVEALING.search(text)


def test_removes_whole_line_comments_and_records_them():
    source = "def f(p):\n    # fix CVE-2024-1: block traversal\n    return p\n"

    result = scrub(source)

    assert result.text == "def f(p):\n    return p\n"
    assert result.removed == [{"line": 2, "kind": "comment",
                               "text": "# fix CVE-2024-1: block traversal"}]


def test_removes_trailing_comments_but_keeps_the_code():
    result = scrub("x = clean(p)  # prevents injection\n")

    assert result.text == "x = clean(p)\n"


def test_keeps_neutral_comments():
    source = "# resolve the path first\nx = 1  # counter\n"

    assert scrub(source).text == source


def test_drops_only_the_revealing_docstring_paragraph():
    source = textwrap.dedent('''\
        def check(path):
            """Check a path.

            Rejects '..' to stop directory traversal (CVE-2023-1).

            Returns the path.
            """
            return path
        ''')

    result = scrub(source)

    assert '"""Check a path.\n\n    Returns the path.\n    """' in result.text
    assert result.removed[0]["kind"] == "docstring"
    ast.parse(result.text)


def test_a_fully_revealing_docstring_is_removed():
    source = 'def f():\n    """Security fix for CVE-2020-1."""\n    return 1\n'

    assert scrub(source).text == "def f():\n    return 1\n"


def test_a_fully_revealing_docstring_that_is_the_whole_body_becomes_pass():
    source = 'def f():\n    """Security fix."""\n'

    result = scrub(source)

    assert result.text == "def f():\n    pass\n"
    ast.parse(result.text)


def test_string_literals_are_flagged_never_changed():
    source = 'raise ValueError("path traversal attempt")\n'

    result = scrub(source)

    assert result.text == source
    assert result.flagged_strings == [{"line": 1, "kind": "string",
                                       "text": '"path traversal attempt"'}]


def test_identical_text_is_scrubbed_identically():
    source = "import os\n# security: keep\ny = os.sep\n"

    assert scrub(source).text == scrub(source).text == "import os\ny = os.sep\n"
