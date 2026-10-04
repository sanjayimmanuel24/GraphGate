"""Tests for trimming a Python file to named symbols."""

import textwrap

from graphgate.dataset.slicing import WIRING, request_tree, trim

SOURCE = textwrap.dedent('''\
    """Module doc."""
    import os
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from pathlib import Path

    try:
        import simplejson as json
    except ImportError:
        json = None

    LIMIT = 10
    UNUSED = {"a": 1}


    def helper(x):
        return x[:LIMIT]


    def unrelated():
        return 1


    class Store:
        """Stores things."""

        allowed = ["a", "b"]

        def __init__(self, root):
            self.root = root

        # Reads a file under the root.
        @property
        def name(self):
            return os.path.basename(self.root)

        def read(self, rel):
            path = os.path.join(self.root, helper(rel))
            self.check(path)
            return open(path).read()

        def check(self, path):
            return path in self.allowed

        def other(self):  # not needed
            return None


    if __name__ == "__main__":
        print(unrelated())
    ''')


def test_request_tree_whole_class_wins_over_members():
    assert request_tree(["A.m", "A", "f"]) == {"A": {}, "f": {}}
    assert request_tree(["A", "A.m"]) == {"A": {}}
    assert request_tree(["A.m", "A.n"]) == {"A": {"m": {}, "n": {}}}


def test_keeps_scaffolding_and_requested_symbols_verbatim():
    result = trim(SOURCE, ["helper", "Store.read", "Store.check", "LIMIT"])

    assert result.syntax_error is None
    assert result.missing == []
    text = result.text
    # Module docstring, imports and the import-only blocks survive.
    assert text.startswith('"""Module doc."""\nimport os\n')
    assert "if TYPE_CHECKING:\n    from pathlib import Path\n" in text
    assert "except ImportError:\n    json = None\n" in text
    # Requested symbols, verbatim.
    assert "LIMIT = 10\n" in text
    assert "def helper(x):\n    return x[:LIMIT]\n" in text
    assert "    def read(self, rel):\n        path = os.path.join(self.root, helper(rel))\n" in text
    # Class header, docstring and class-level assignments go with a partial class.
    assert 'class Store:\n    """Stores things."""\n\n    allowed = ["a", "b"]\n' in text
    # Everything else is cut.
    for gone in ("UNUSED", "def unrelated", "def other", "__main__", "def __init__", "def name"):
        assert gone not in text


def test_blank_lines_follow_pep8_between_kept_definitions():
    text = trim(SOURCE, ["helper", "Store.read", "Store.check"]).text

    assert "\n\n\ndef helper(x):" in text           # two blank lines at module level
    assert "\n\n\nclass Store:" in text
    assert "        return open(path).read()\n\n    def check" in text  # one inside a class


def test_leading_comment_and_decorator_travel_with_their_method():
    text = trim(SOURCE, ["Store.name"]).text

    assert "    # Reads a file under the root.\n    @property\n    def name(self):" in text


def test_trailing_comment_of_a_dropped_statement_is_not_pulled_in():
    source = "import os\nx = 1  # note\ny = 2\n"

    text = trim(source, ["y"]).text

    assert text == "import os\n\ny = 2\n"


def test_whole_class_is_kept_entire():
    text = trim(SOURCE, ["Store"]).text

    assert "def other(self):  # not needed" in text
    assert "def __init__" in text


def test_reports_missing_symbols():
    result = trim(SOURCE, ["helper", "Store.nope", "nothing"])

    assert result.missing == ["Store.nope", "nothing"]


def test_reports_references_the_cut_removed():
    """read() calls helper(), self.check() and uses LIMIT via helper: cut helper and check."""
    result = trim(SOURCE, ["Store.read"])

    assert result.dropped_references == ["Store.check", "helper"]


def test_class_attribute_references_are_satisfied_by_kept_assignments():
    result = trim(SOURCE, ["Store.check"])

    assert "Store.allowed" not in result.dropped_references


def test_class_qualified_member_access_is_checked_too():
    source = textwrap.dedent('''\
        class A:
            def m(self):
                return A.n()

            @staticmethod
            def n():
                return 1
        ''')

    assert trim(source, ["A.m"]).dropped_references == ["A.n"]


def test_nested_class_members_can_be_requested():
    source = textwrap.dedent('''\
        class Outer:
            class Inner:
                def keep(self):
                    return 1

                def drop(self):
                    return 2

            def also_drop(self):
                return 3
        ''')

    text = trim(source, ["Outer.Inner.keep"]).text

    assert "def keep" in text and "def drop" not in text and "also_drop" not in text
    assert text.startswith("class Outer:\n    class Inner:\n")


def test_trimmed_output_always_parses():
    for symbols in (["helper"], ["Store.read"], ["Store"], ["LIMIT", "Store.name"]):
        assert trim(SOURCE, symbols).syntax_error is None


# --- Opt-in module-level wiring ---------------------------------------------

GRAMMAR = textwrap.dedent('''\
    from pyparsing import Forward, ParserElement, Word, alphas

    ParserElement.enablePackrat()

    word = Word(alphas)
    clause = Forward()
    unused = Forward()


    class Term:
        def __init__(self, tokens):
            self.tokens = tokens


    def helper():
        return 1


    # Attach the parse action.
    word.setParseAction(lambda t: t[0])
    clause << word
    clause.addParseAction(Term)
    unused << word
    print("loaded")
    ''')


def test_wiring_marker_keeps_statements_that_refer_to_kept_names():
    text = trim(GRAMMAR, ["clause", "Term", WIRING]).text

    assert "clause << word\n" in text
    assert "clause.addParseAction(Term)\n" in text
    # A statement that mentions only names the slice dropped stays out.
    assert "print(" not in text and "enablePackrat" not in text
    assert "word.setParseAction" not in text  # `word` itself was not requested


def test_wiring_statement_brings_its_leading_comment():
    text = trim(GRAMMAR, ["word", WIRING]).text

    assert "# Attach the parse action.\nword.setParseAction(lambda t: t[0])\n" in text


def test_without_the_marker_nothing_changes():
    symbols = ["clause", "Term"]

    assert "clause << word" not in trim(GRAMMAR, symbols).text
    # The marker only adds; everything kept without it is still there, in order.
    plain = trim(GRAMMAR, symbols).text.split("\n")
    wired = trim(GRAMMAR, symbols + [WIRING]).text.split("\n")
    assert [line for line in wired if line in plain and line] == [line for line in plain if line]


def test_wiring_marker_is_not_reported_missing_and_output_parses():
    result = trim(GRAMMAR, ["clause", "Term", WIRING])

    assert result.missing == []
    assert result.syntax_error is None


def test_wiring_keeps_a_block_that_registers_a_kept_handler():
    source = textwrap.dedent('''\
        from ui import column, upload


        def handle(event):
            return open(event.name).read()


        def other():
            return 0


        with column():
            box = upload(on_upload=handle)
        ''')

    text = trim(source, ["handle", WIRING]).text

    assert "with column():\n    box = upload(on_upload=handle)\n" in text
    assert "def other" not in text
