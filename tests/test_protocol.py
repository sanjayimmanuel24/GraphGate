"""Tests for the model request/response contract."""

import pytest

from graphgate.harness.protocol import (
    ResponseParseError,
    parse_file_blocks,
    render_user_prompt,
)


def test_parses_single_file_block():
    response = """\
### FILE: app.py
```python
def run():
    return 1
```
"""
    assert parse_file_blocks(response) == {"app.py": "def run():\n    return 1"}


def test_parses_multiple_file_blocks():
    response = """\
### FILE: app.py
```python
import db
```

### FILE: db/query.py
```python
def fetch(uid):
    return uid
```
"""
    files = parse_file_blocks(response)
    assert set(files) == {"app.py", "db/query.py"}
    assert files["db/query.py"] == "def fetch(uid):\n    return uid"


def test_ignores_prose_around_blocks():
    """Models add commentary despite instructions; that must not break parsing."""
    response = """\
Sure, here's the refactored version:

### FILE: app.py
```python
x = 1
```

Let me know if you'd like anything else.
"""
    assert parse_file_blocks(response) == {"app.py": "x = 1"}


def test_tolerates_missing_language_tag():
    response = "### FILE: app.py\n```\nx = 1\n```\n"
    assert parse_file_blocks(response) == {"app.py": "x = 1"}


def test_preserves_blank_lines_inside_a_file():
    response = "### FILE: app.py\n```python\na = 1\n\nb = 2\n```\n"
    assert parse_file_blocks(response) == {"app.py": "a = 1\n\nb = 2"}


def test_raises_when_no_blocks_present():
    """A parse failure must surface, not degrade into a silent no-op turn."""
    with pytest.raises(ResponseParseError, match="no '### FILE:"):
        parse_file_blocks("I've updated the file for you.")


def test_raises_on_fenced_block_without_file_marker():
    with pytest.raises(ResponseParseError):
        parse_file_blocks("```python\nx = 1\n```")


def test_user_prompt_includes_every_file_and_the_instruction():
    prompt = render_user_prompt({"b.py": "b = 2", "a.py": "a = 1"}, "improve readability")
    assert "### FILE: a.py" in prompt
    assert "### FILE: b.py" in prompt
    assert "Refinement instruction: improve readability" in prompt
    # Sorted, so the same snapshot renders identically across runs — otherwise
    # the prompt hash would vary and defeat caching in step 1.4.
    assert prompt.index("a.py") < prompt.index("b.py")
