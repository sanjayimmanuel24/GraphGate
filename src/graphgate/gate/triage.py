"""LLM triage of a change (BUILD_PLAN 3.2).

The last stage of a gate. The model is shown one change as a unified diff and a
numbered list of *items*, and gives each item one of three labels with a short
rationale. It judges what it is handed; finding things to judge is the job of
the stages before it.

An item is either something a deterministic stage flagged (a group of
static-analysis findings on one piece of code) or, for the diff-review
baseline only, the change as a whole. Condition C will add graph-difference
flags as a third kind without changing anything here.

The prompt is part of the experiment. It was written before any live call and
carries a version; change the wording only together with ``PROMPT_VERSION``,
and never after a condition has been run with it. A test pins its hash. The
system prompt says nothing about which context a condition has, so the same
text serves every condition; what differs between them is the user message.

The model sees the diff and the items and nothing else: no trace id, no event
id, no advisory, no label. Those would hand it the answer.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Sequence

from graphgate.gate.findings import Finding
from graphgate.llm.base import CodeGenClient, CompletionError, RefusalError

EXPLOITABLE = "exploitable-regression"
BENIGN = "benign-refactor"
UNCERTAIN = "uncertain"
LABELS = (EXPLOITABLE, BENIGN, UNCERTAIN)

PROMPT_VERSION = 1

SYSTEM_PROMPT = """\
You are the review step of a security gate that checks one code change at a \
time in a Python project. The gate covers the injection family only: SQL \
injection, operating-system command injection and path traversal.

You are given the change as a unified diff, followed by a numbered list of \
items to judge. An item is either a piece of code in the changed files that \
an automated check flagged, or the change as a whole. Judge every item, and \
only those items. Base each judgement only on what this message shows you; \
you cannot see anything else in the repository.

Give each item one label:
- "exploitable-regression": the change introduces an injection flaw, or removes \
or weakens a protection against one, in a way an attacker could plausibly use;
- "benign-refactor": the change does not make injection easier;
- "uncertain": what you are shown is not enough to decide.

Reply with a single JSON object and nothing else, in this form:
{"items": [{"id": "<item id>", "label": "<one of the three labels>", \
"rationale": "<one or two sentences>"}]}
"""

CHANGE_ITEM_ID = "C0"
CHANGE_ITEM_TEXT = ("The change as a whole: does it introduce or re-open an SQL injection, "
                    "command injection or path traversal flaw?")


def prompt_sha256() -> str:
    return hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Item:
    """One thing the model is asked to judge."""

    id: str
    kind: str   # "finding" for flagged code, "change" for the change as a whole
    text: str   # the wording shown to the model


@dataclass(frozen=True)
class Verdict:
    label: str
    rationale: str


class TriageParseError(ValueError):
    """The model's reply is not the JSON object it was asked for."""


def finding_items(findings: Sequence[Finding]) -> list[Item]:
    """One item per flagged piece of code, listing every rule that reported it.

    Several rules often fire on one line; asking about that line once keeps
    the prompt short and stops one risky line from being voted on five times.
    """
    groups: dict[tuple[str, int, int], list[Finding]] = {}
    for finding in findings:
        groups.setdefault((finding.path, finding.start_line, finding.end_line), []).append(finding)
    items = []
    for number, key in enumerate(sorted(groups), start=1):
        path, start, end = key
        group = sorted(groups[key], key=lambda f: (f.tool, f.rule_id))
        where = f"line {start}" if start == end else f"lines {start}-{end}"
        lines = [f"{path}, {where}, reported by:"]
        for f in group:
            cwes = ", ".join(f"CWE-{c}" for c in f.cwes)
            lines.append(f"  - {f.tool} {f.rule_id} ({cwes}; severity {f.severity}): {f.message}")
        lines.append("  Code:")
        lines.extend(f"      {line}" for line in group[0].code.splitlines())
        items.append(Item(f"F{number}", "finding", "\n".join(lines)))
    return items


def change_item() -> Item:
    return Item(CHANGE_ITEM_ID, "change", CHANGE_ITEM_TEXT)


def render_user_prompt(diff: str, items: Sequence[Item]) -> str:
    parts = ["Change (unified diff):", "```diff", diff, "```", "", "Items to judge:"]
    parts.extend(f"- {item.id}: {item.text}" for item in items)
    return "\n".join(parts)


def parse_reply(text: str, items: Sequence[Item]) -> dict[str, Verdict]:
    """The verdict for every item, or :class:`TriageParseError`.

    A code fence or a sentence around the object is tolerated, since models
    add them whatever they are told. Anything else is refused outright: a
    missing item, an extra one, or a label outside the three is an error, never
    a guess at what the model meant.
    """
    body = text.strip()
    start, end = body.find("{"), body.rfind("}")
    if start == -1 or end < start:
        raise TriageParseError(f"no JSON object in the reply: {body[:120]!r}")
    try:
        data = json.loads(body[start:end + 1])
    except json.JSONDecodeError as exc:
        raise TriageParseError(f"the reply is not valid JSON ({exc.msg}): {body[:120]!r}") from exc
    entries = data.get("items") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise TriageParseError('the reply has no "items" list')

    verdicts: dict[str, Verdict] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) for k in ("id", "label", "rationale")):
            raise TriageParseError(f"malformed item in the reply: {str(entry)[:120]!r}")
        if entry["label"] not in LABELS:
            raise TriageParseError(f"item {entry['id']}: unknown label {entry['label']!r}")
        if entry["id"] in verdicts:
            raise TriageParseError(f"item {entry['id']} is judged twice")
        verdicts[entry["id"]] = Verdict(entry["label"], " ".join(entry["rationale"].split()))
    wanted = {item.id for item in items}
    if set(verdicts) != wanted:
        missing, extra = sorted(wanted - set(verdicts)), sorted(set(verdicts) - wanted)
        raise TriageParseError("the reply does not match the items asked about"
                               + (f"; missing {', '.join(missing)}" if missing else "")
                               + (f"; not asked {', '.join(extra)}" if extra else ""))
    return verdicts


# Outcomes of a triage call. Only TRIAGED carries verdicts.
TRIAGED = "triaged"
REFUSED = "refused"    # the model declined: a model outcome, reported in its own right
ERROR = "error"        # the call failed, or the reply could not be used


@dataclass(frozen=True)
class TriageResult:
    outcome: str
    verdicts: dict[str, Verdict]
    detail: str | None            # why there are no verdicts, for REFUSED and ERROR
    call: dict[str, Any]          # what was sent and what came back, for the record

    @property
    def ok(self) -> bool:
        return self.outcome == TRIAGED


def triage(client: CodeGenClient, diff: str, items: Sequence[Item], *, replication: int) -> TriageResult:
    """Ask the model about ``items``. Never raises for a bad answer: the
    outcome says what happened, so a gate can record it instead of crashing."""
    user = render_user_prompt(diff, items)
    call: dict[str, Any] = {"prompt_version": PROMPT_VERSION, "prompt_sha256": prompt_sha256(),
                            "params": client.describe_params(), "replication": replication}
    try:
        completion = client.complete(SYSTEM_PROMPT, user, replication=replication)
    except RefusalError as refusal:
        call.update(prompt_hash=refusal.prompt_hash, model=refusal.model, resolved_model=refusal.resolved_model,
                    usage=dict(refusal.usage), latency_ms=refusal.latency_ms, cached=False,
                    response_text=refusal.partial_text, refusal_category=refusal.category,
                    refusal_explanation=refusal.explanation)
        return TriageResult(REFUSED, {}, f"model declined (category={refusal.category or 'unspecified'})", call)
    except CompletionError as exc:
        return TriageResult(ERROR, {}, f"call failed: {exc}", call)

    call.update(prompt_hash=completion.prompt_hash, model=completion.model,
                resolved_model=completion.resolved_model, usage=dict(completion.usage),
                latency_ms=completion.latency_ms, cached=completion.cached, response_text=completion.text)
    if completion.stop_reason == "max_tokens":
        return TriageResult(ERROR, {}, "reply cut off at max_tokens", call)
    try:
        return TriageResult(TRIAGED, parse_reply(completion.text, items), None, call)
    except TriageParseError as exc:
        return TriageResult(ERROR, {}, f"unusable reply: {exc}", call)

