"""Tests for the diff-only gates, Condition B and the diff-review baseline B+."""

import json

import pytest

from graphgate.gate.local import (
    ALLOW,
    BLOCK,
    CONDITION_B,
    CONDITION_B_PLUS,
    NO_CHANGE,
    NO_FLAGS,
    Change,
    LocalGate,
)
from graphgate.gate.triage import BENIGN, ERROR, EXPLOITABLE, REFUSED, TRIAGED, UNCERTAIN
from graphgate.harness.replay import ReplayTurn
from graphgate.llm.base import RefusalError

from conftest import StubScanner

GUARDED = "def read(name):\n    check(name)\n    return open(name).read()\n"
UNGUARDED = "def read(name):\n    return open(name).read()\n"
SHELL = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"


def reply(**labels):
    return json.dumps({"items": [{"id": k, "label": v, "rationale": f"because {k}"} for k, v in labels.items()]})


GUARD_REMOVED = Change.between({"files.py": GUARDED}, {"files.py": UNGUARDED})
SHELL_ADDED = Change.between({"run.py": "def run(cmd):\n    pass\n"}, {"run.py": SHELL})


# --- What a gate is shown -----------------------------------------------------------


def test_a_change_is_two_code_states_and_their_diff():
    assert GUARD_REMOVED.changed_paths == ("files.py",)
    assert "-    check(name)" in GUARD_REMOVED.diff and GUARD_REMOVED.before["files.py"] == GUARDED


def test_a_trace_turn_hands_the_gate_no_ground_truth(tmp_path, fake_client, file_block, record_live, snapshot_dir):
    """The record of where a regression was injected must not travel with a turn."""
    assert "injection" not in ReplayTurn.__dataclass_fields__
    assert set(Change.__dataclass_fields__) == {"before", "after", "changed_paths", "diff"}


# --- Condition B: triage what the scanners flag -----------------------------------------


def test_b_allows_without_a_model_call_when_nothing_is_flagged(fake_client):
    client, scanner = fake_client([]), StubScanner()

    decision = LocalGate(CONDITION_B, scanner, client).decide(GUARD_REMOVED, replication=0)

    assert (decision.decision, decision.outcome) == (ALLOW, NO_FLAGS)
    assert client.calls == 0 and scanner.calls == 1 and decision.call is None
    assert decision.items == () and decision.findings_introduced == ()


def test_b_blocks_when_the_model_calls_a_flagged_finding_exploitable(fake_client):
    client = fake_client([reply(F1=EXPLOITABLE)])

    decision = LocalGate(CONDITION_B, StubScanner(), client).decide(SHELL_ADDED, replication=1)

    assert (decision.decision, decision.outcome) == (BLOCK, TRIAGED)
    assert decision.rationale == "F1: because F1"
    assert [(i["id"], i["kind"], i["label"]) for i in decision.items] == [("F1", "finding", EXPLOITABLE)]
    assert [f.rule_id for f in decision.findings_introduced] == ["B605"]
    assert client.replications_seen == [1]
    assert "- C0:" not in client.prompts_seen[0]          # B is asked about the findings only
    assert "run.py, line 5, reported by:" in client.prompts_seen[0] and SHELL_ADDED.diff in client.prompts_seen[0]


@pytest.mark.parametrize("label", [BENIGN, UNCERTAIN])
def test_b_allows_when_the_finding_is_not_called_exploitable(fake_client, label):
    decision = LocalGate(CONDITION_B, StubScanner(), fake_client([reply(F1=label)])).decide(
        SHELL_ADDED, replication=0)

    assert (decision.decision, decision.outcome) == (ALLOW, TRIAGED)
    assert decision.items[0]["label"] == label            # recorded, so a stricter reading can be computed


def test_blocking_on_uncertain_is_a_setting(fake_client):
    gate = LocalGate(CONDITION_B, StubScanner(), fake_client([reply(F1=UNCERTAIN)]),
                     block_on=(EXPLOITABLE, UNCERTAIN))

    assert gate.decide(SHELL_ADDED, replication=0).decision == BLOCK


# --- Condition B+: the model reads every diff ----------------------------------------------


def test_b_plus_asks_about_the_change_even_when_nothing_is_flagged(fake_client):
    client = fake_client([reply(C0=EXPLOITABLE)])

    decision = LocalGate(CONDITION_B_PLUS, StubScanner(), client).decide(GUARD_REMOVED, replication=0)

    assert (decision.decision, decision.outcome) == (BLOCK, TRIAGED)
    assert [(i["id"], i["kind"]) for i in decision.items] == [("C0", "change")]
    assert client.calls == 1 and "- C0: The change as a whole" in client.prompts_seen[0]


def test_b_plus_judges_the_findings_and_the_change_together(fake_client):
    client = fake_client([reply(F1=BENIGN, C0=EXPLOITABLE)])

    decision = LocalGate(CONDITION_B_PLUS, StubScanner(), client).decide(SHELL_ADDED, replication=0)

    assert [i["id"] for i in decision.items] == ["F1", "C0"]
    assert decision.decision == BLOCK and decision.rationale == "C0: because C0"   # only the blocking item


def test_b_plus_allows_a_change_it_judges_benign(fake_client):
    decision = LocalGate(CONDITION_B_PLUS, StubScanner(), fake_client([reply(C0=BENIGN)])).decide(
        GUARD_REMOVED, replication=0)

    assert (decision.decision, decision.outcome) == (ALLOW, TRIAGED)


# --- Outcomes that are not verdicts ---------------------------------------------------------


def test_a_turn_that_changed_nothing_is_allowed_without_scanning(fake_client):
    client, scanner = fake_client([]), StubScanner()

    decision = LocalGate(CONDITION_B_PLUS, scanner, client).decide(
        Change.between({"a.py": GUARDED}, {"a.py": GUARDED}), replication=0)

    assert (decision.decision, decision.outcome) == (ALLOW, NO_CHANGE)
    assert scanner.calls == 0 and client.calls == 0


def test_a_refusal_does_not_block_and_is_recorded_as_one(fake_client):
    refusal = RefusalError(prompt_hash="", model="", category="cyber", explanation=None,
                           partial_text="", usage={}, latency_ms=1.0)

    decision = LocalGate(CONDITION_B_PLUS, StubScanner(), fake_client([refusal])).decide(
        GUARD_REMOVED, replication=0)

    assert (decision.decision, decision.outcome) == (ALLOW, REFUSED)
    assert "category=cyber" in decision.rationale
    assert decision.items[0]["label"] is None and decision.call["refusal_category"] == "cyber"


def test_an_unusable_reply_does_not_block_and_is_recorded_as_an_error(fake_client):
    decision = LocalGate(CONDITION_B_PLUS, StubScanner(), fake_client(["Looks fine to me."])).decide(
        GUARD_REMOVED, replication=0)

    assert (decision.decision, decision.outcome) == (ALLOW, ERROR)
    assert decision.rationale.startswith("unusable reply") and decision.call["response_text"] == "Looks fine to me."


def test_files_a_scanner_could_not_analyse_travel_with_the_decision(fake_client):
    scanner = StubScanner(errors=("after files.py: bandit: syntax error while parsing AST from file",))

    decision = LocalGate(CONDITION_B, scanner, fake_client([])).decide(GUARD_REMOVED, replication=0)

    assert decision.analysis_errors == ("after files.py: bandit: syntax error while parsing AST from file",)


# --- The record ----------------------------------------------------------------------------


def test_a_decision_serialises_to_plain_json(fake_client):
    decision = LocalGate(CONDITION_B, StubScanner(), fake_client([reply(F1=EXPLOITABLE)])).decide(
        SHELL_ADDED, replication=0)

    data = json.loads(json.dumps(decision.to_dict()))

    assert (data["condition"], data["decision"], data["outcome"]) == ("B", "BLOCK", "triaged")
    assert data["findings_introduced"][0]["rule_id"] == "B605" and data["call"]["prompt_version"] == 1


def test_only_the_two_diff_only_conditions_are_accepted(fake_client):
    with pytest.raises(ValueError, match="unknown diff-only condition"):
        LocalGate("C", StubScanner(), fake_client([]))
