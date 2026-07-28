"""The request/response contract with the code-generation model.

The system prompt and the parser are two halves of one agreement, so they live
together — changing the expected format means changing both.

The model returns **whole files**, not diffs; the harness computes the diff
(see ``diff.py``).
"""

from __future__ import annotations

import re

FILE_MARKER = "### FILE:"

SYSTEM_PROMPT = f"""\
You are a code-generation assistant refining a small Python codebase across \
several turns. On each turn you receive the current contents of every file and \
one refinement instruction.

Rewrite whatever files the instruction requires and return their COMPLETE new \
contents. Do not return diffs, patches, or partial files.

Format your reply as one block per modified file, exactly like this:

{FILE_MARKER} path/to/file.py
```python
<complete new contents of that file>
```

Rules:
- Use the same relative path you were given.
- Return only files you actually changed. Omit untouched files entirely.
- Emit no prose outside the blocks.
"""

_FILE_BLOCK = re.compile(
    r"^###[ \t]*FILE:[ \t]*(?P<path>\S+)[ \t]*\r?\n"
    r"```[a-zA-Z0-9_+-]*[ \t]*\r?\n"
    r"(?P<body>.*?)"
    r"\r?\n?```",
    re.MULTILINE | re.DOTALL,
)


class ResponseParseError(ValueError):
    """The model's reply did not follow the file-block contract.

    Raised rather than defaulted to "no changes": a turn silently treated as a
    no-op would understate degradation and quietly corrupt the curve.
    """


def render_user_prompt(files: dict[str, str], instruction: str) -> str:
    """Current code state plus this turn's refinement instruction."""
    parts = ["Current files:", ""]
    for path in sorted(files):
        parts.append(f"{FILE_MARKER} {path}")
        parts.append("```python")
        parts.append(files[path])
        parts.append("```")
        parts.append("")
    parts.append(f"Refinement instruction: {instruction}")
    return "\n".join(parts)


def parse_file_blocks(text: str) -> dict[str, str]:
    """Extract ``{path: contents}`` from a model reply.

    Raises :class:`ResponseParseError` if no block is found, so the driver can
    record the failure explicitly instead of advancing with a stale snapshot.
    """
    files = {match["path"]: match["body"] for match in _FILE_BLOCK.finditer(text)}
    if not files:
        preview = text[:200].replace("\n", "\\n")
        raise ResponseParseError(
            f"no '{FILE_MARKER} <path>' blocks found in response; got: {preview!r}"
        )
    return files
