"""Tests for the LLM triage step (BUILD_PLAN 3.2)."""

import json

import pytest

from graphgate.gate.findings import Finding
from graphgate.gate.triage import (
    BENIGN,
    ERROR,
    EXPLOITABLE,
    PROMPT_VERSION,
    REFUSED,
    SYSTEM_PROMPT,
    TRIAGED,
    UNCERTAIN,
    Item,
    TriageParseError,
    change_item,
    finding_items,
    parse_reply,
    prompt_sha256,
    render_user_prompt,
    triage,
)
from graphgate.llm.base import CompletionError, RefusalError

DIFF = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,2 @@\n def read(name):\n-    check(name)\n     return open(name).read()"


def finding(rule="B605", tool="bandit", path="app.py", line=5, end=None, code="os.system(cmd)",
            message="Starting a process with a shell.", cwes=(78,), severity="high"):
    return Finding(tool=tool, rule_id=rule, cwes=cwes, severity=severity, confidence="high", path=path,
                   start_line=line, end_line=end or line, message=message, code=code)


def reply(**labels):
    return json.dumps({"items": [{"id": k, "label": v, "rationale": f"because {k}"} for k, v in labels.items()]})


ITEMS = [Item("F1", "finding", "app.py, line 5"), Item("C0", "change", "the change")]


# --- The prompt -----------------------------------------------------------------


def test_the_prompt_is_fixed_until_its_version_is_bumped():
    """Editing the wording changes what every condition measures. If this fails,
    the change was deliberate only if PROMPT_VERSION went up with it, and no
    condition has been run with the old wording that will be compared with new runs."""
    assert (PROMPT_VERSION, prompt_sha256()) == (
        1, "907894e26a77193be9312021ddb8e711582db45efba343c987f75924cb6deb7e")


def test_the_prompt_names_the_family_the_labels_and_the_reply_format():
    for needle in ("SQL injection", "command injection", "path traversal", EXPLOITABLE, BENIGN, UNCERTAIN,
                   '{"items": [', "only those items", "cannot see anything else in the repository"):
        assert needle in SYSTEM_PROMPT


def test_the_request_holds_the_diff_and_the_items_and_nothing_else():
    user = render_user_prompt(DIFF, ITEMS)

    assert user == ("Change (unified diff):\n```diff\n" + DIFF + "\n```\n\nItems to judge:\n"
                    "- F1: app.py, line 5\n- C0: the change")


def test_findings_on_one_piece_of_code_become_one_item():
    items = finding_items([
        finding("B605", line=13),
        finding("python.lang.security.dangerous-system-call", tool="semgrep", line=13, message="Dynamic call."),
        finding("B608", line=22, cwes=(89,), severity="medium", code="cur.execute(q % name)",
                message="Possible SQL injection."),
        finding("python.django.sql-injection", tool="semgrep", path="a/db.py", line=3, end=4, cwes=(89,),
                code="q = build(name)\ncur.execute(q)", message="Tainted query."),
    ])

    assert [(i.id, i.kind) for i in items] == [("F1", "finding"), ("F2", "finding"), ("F3", "finding")]
    assert items[0].text.startswith("a/db.py, lines 3-4, reported by:")          # ordered by file, then line
    assert "      q = build(name)\n      cur.execute(q)" in items[0].text         # the flagged code, verbatim
    both = items[1].text
    assert both.startswith("app.py, line 13, reported by:")
    assert "bandit B605 (CWE-78; severity high): Starting a process with a shell." in both
    assert "semgrep python.lang.security.dangerous-system-call (CWE-78; severity high): Dynamic call." in both
    assert "B608" in items[2].text and "CWE-89" in items[2].text


def test_no_findings_means_no_finding_items():
    assert finding_items([]) == []
    assert (change_item().id, change_item().kind) == ("C0", "change")


# --- Reading the reply ------------------------------------------------------------


def test_a_well_formed_reply_gives_one_verdict_per_item():
    verdicts = parse_reply(reply(F1=EXPLOITABLE, C0=UNCERTAIN), ITEMS)

    assert verdicts["F1"].label == EXPLOITABLE and verdicts["F1"].rationale == "because F1"
    assert verdicts["C0"].label == UNCERTAIN


@pytest.mark.parametrize("wrap", [
    "```json\n{}\n```",
    "```\n{}\n```",
    "Here is my assessment:\n{}\nLet me know if you need more.",
])
def test_a_fence_or_a_sentence_around_the_object_is_tolerated(wrap):
    text = wrap.replace("{}", reply(F1=BENIGN, C0=BENIGN))

    assert parse_reply(text, ITEMS)["F1"].label == BENIGN


@pytest.mark.parametrize("text, message", [
    ("I cannot judge this.", "no JSON object"),
    ('{"items": [{"id": "F1", "label": "benign-refactor", "rationale": "x"}', "no JSON object|not valid JSON"),
    ('{"verdict": "ok"}', 'no "items" list'),
    ('{"items": [{"id": "F1", "label": "benign-refactor"}]}', "malformed item"),
    (reply(F1="safe", C0=BENIGN), "unknown label 'safe'"),
    (reply(F1=BENIGN), "missing C0"),
    (reply(F1=BENIGN, C0=BENIGN, F9=EXPLOITABLE), "not asked F9"),
    ('{"items": [{"id": "F1", "label": "uncertain", "rationale": "a"}, {"id": "F1", "label": "uncertain", '
     '"rationale": "b"}, {"id": "C0", "label": "uncertain", "rationale": "c"}]}', "judged twice"),
])
def test_a_reply_that_is_not_what_was_asked_for_is_refused_not_guessed_at(text, message):
    with pytest.raises(TriageParseError, match=message):
        parse_reply(text, ITEMS)


# --- One call ---------------------------------------------------------------------


def test_triage_returns_verdicts_and_the_record_of_the_call(fake_client):
    client = fake_client([reply(F1=EXPLOITABLE, C0=BENIGN)])

    result = triage(client, DIFF, ITEMS, replication=2)

    assert result.ok and result.outcome == TRIAGED and result.detail is None
    assert result.verdicts["F1"].label == EXPLOITABLE
    call = result.call
    assert (call["prompt_version"], call["prompt_sha256"]) == (PROMPT_VERSION, prompt_sha256())
    assert call["model"] == "fake-model" and call["replication"] == 2 and call["cached"] is False
    assert call["usage"] == {"input_tokens": 5, "output_tokens": 7} and call["response_text"].startswith("{")
    assert call["prompt_hash"] == client.request_hash(SYSTEM_PROMPT, render_user_prompt(DIFF, ITEMS))
    assert client.replications_seen == [2]            # each replication is its own sample in the cache


def test_a_refusal_is_its_own_outcome_with_its_category(fake_client):
    refusal = RefusalError(prompt_hash="", model="", category="cyber", explanation="declined",
                           partial_text="", usage={"input_tokens": 9}, latency_ms=3.0)

    result = triage(fake_client([refusal]), DIFF, ITEMS, replication=0)

    assert (result.outcome, result.ok, result.verdicts) == (REFUSED, False, {})
    assert "category=cyber" in result.detail
    assert result.call["refusal_category"] == "cyber" and result.call["usage"] == {"input_tokens": 9}


@pytest.mark.parametrize("response, detail", [
    (CompletionError("rate limited"), "call failed: rate limited"),
    ("I think this change is fine.", "unusable reply: no JSON object"),
    ((reply(F1=BENIGN, C0=BENIGN)[:40], "max_tokens"), "reply cut off at max_tokens"),
])
def test_a_failed_call_or_unusable_reply_is_an_error_never_a_verdict(fake_client, response, detail):
    result = triage(fake_client([response]), DIFF, ITEMS, replication=0)

    assert (result.outcome, result.verdicts) == (ERROR, {})
    assert result.detail.startswith(detail)
