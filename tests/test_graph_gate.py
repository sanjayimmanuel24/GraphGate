"""Condition C: the scanners, the graph rules, then triage of what they flag (BUILD_PLAN 5.2)."""

import json

from graphgate.gate import graph_gate
from graphgate.gate.graph_gate import CONDITION_C, GraphGate, describe, flag_items
from graphgate.gate.local import ALLOW, BLOCK, NO_CHANGE, NO_FLAGS, UNTRIAGED, Change
from graphgate.gate.triage import BENIGN, EXPLOITABLE, SYSTEM_PROMPT, TRIAGED, UNCERTAIN
from graphgate.graph.delta import Flag
from graphgate.graph.link import AS_PROPOSED

from conftest import StubScanner

API = "from store import save\n\n\ndef upload(name, data):\n    {check}save(name, data)\n"
STORE = "def save(name, data):\n    with open(name, 'w') as handle:\n        handle.write(data)\n"
CHECKED = API.format(check="if '..' in name:\n        raise ValueError(name)\n    ")
UNCHECKED = API.format(check="")

GUARD_DROPPED = Change.between({"api.py": CHECKED, "store.py": STORE}, {"api.py": UNCHECKED, "store.py": STORE})
RENAMED = Change.between({"api.py": UNCHECKED, "store.py": STORE},
                         {"api.py": UNCHECKED.replace("data", "body"), "store.py": STORE})


def reply(**labels):
    return json.dumps({"items": [{"id": k, "label": v, "rationale": f"because {k}"} for k, v in labels.items()]})


def test_a_dropped_guard_is_flagged_triaged_and_blocked(fake_client):
    client = fake_client([reply(G1=EXPLOITABLE)])

    decision = GraphGate(StubScanner(), client).decide(GUARD_DROPPED, replication=2)

    assert (decision.condition, decision.decision, decision.outcome) == (CONDITION_C, BLOCK, TRIAGED)
    assert decision.rationale == "G1: because G1"
    assert [(f["rule"], f["item"]) for f in decision.flags] == [("R3", "G1")]
    assert [(i["id"], i["kind"], i["label"]) for i in decision.items] == [("G1", "flag", EXPLOITABLE)]
    assert client.calls == 1 and client.replications_seen == [2]
    assert set(decision.seconds) == {"scan", "graph"}


def test_the_model_is_shown_code_the_diff_does_not_touch(fake_client):
    """What C adds to the model's view: the function behind the change, in another file."""
    client = fake_client([reply(G1=BENIGN)])

    GraphGate(StubScanner(), client).decide(GUARD_DROPPED, replication=0)

    prompt = client.prompts_seen[0]
    diff, items = prompt.split("Items to judge:")
    assert "store.py" not in diff                                  # the diff is api.py alone
    assert "Graph check R3 (a guard is gone)" in items
    assert "# store.py, lines 1-3" in items and "with open(name, 'w') as handle:" in items
    assert "# api.py, lines 4-5" in items


def test_benign_and_uncertain_verdicts_do_not_block(fake_client):
    for label in (BENIGN, UNCERTAIN):
        decision = GraphGate(StubScanner(), fake_client([reply(G1=label)])).decide(GUARD_DROPPED, replication=0)

        assert (decision.decision, decision.outcome) == (ALLOW, TRIAGED) and decision.items[0]["label"] == label


def test_nothing_flagged_means_no_model_call(fake_client):
    client = fake_client([])

    decision = GraphGate(StubScanner(), client).decide(RENAMED, replication=0)

    assert (decision.decision, decision.outcome, decision.flags) == (ALLOW, NO_FLAGS, ())
    assert client.calls == 0 and decision.call is None


def test_a_turn_that_changed_nothing_is_allowed_unseen(fake_client):
    same = Change.between({"api.py": CHECKED}, {"api.py": CHECKED})

    decision = GraphGate(StubScanner(), fake_client([])).decide(same, replication=0)

    assert (decision.decision, decision.outcome) == (ALLOW, NO_CHANGE)


def test_scanner_findings_and_graph_flags_are_judged_together(fake_client):
    shell = UNCHECKED.replace("save(name, data)", "import os\n    os.system('ls ' + name)")
    change = Change.between({"api.py": CHECKED, "store.py": STORE}, {"api.py": shell, "store.py": STORE})
    client = fake_client([reply(F1=BENIGN, G1=BENIGN, G2=EXPLOITABLE)])

    decision = GraphGate(StubScanner(), client).decide(change, replication=0)

    assert [i["id"] for i in decision.items] == ["F1", "G1", "G2"]
    assert [i["kind"] for i in decision.items] == ["finding", "flag", "flag"]
    assert decision.decision == BLOCK and len(decision.findings_introduced) == 1


def test_without_triage_any_flag_blocks_and_no_model_is_needed():
    gate = GraphGate(StubScanner(), None, use_triage=False)

    blocked, allowed = gate.decide(GUARD_DROPPED, replication=0), gate.decide(RENAMED, replication=0)

    assert (blocked.decision, blocked.outcome, blocked.call) == (BLOCK, UNTRIAGED, None)
    assert blocked.items[0]["label"] is None
    assert (allowed.decision, allowed.outcome) == (ALLOW, NO_FLAGS)


def test_the_graph_settings_decide_what_is_flagged():
    """With the proposal's literal settings a test that raises is not a guard."""
    literal = GraphGate(StubScanner(), None, config=AS_PROPOSED, use_triage=False)

    assert literal.decide(GUARD_DROPPED, replication=0).decision == ALLOW
    assert GraphGate(StubScanner(), None, use_triage=False).config.structural_guards is True


def test_the_system_prompt_is_the_one_every_condition_uses(fake_client):
    class Spy:
        def __init__(self, inner):
            self.inner, self.systems = inner, []

        def describe_params(self):
            return self.inner.describe_params()

        def complete(self, system, user, *, replication):
            self.systems.append(system)
            return self.inner.complete(system, user, replication=replication)

    spy = Spy(fake_client([reply(G1=BENIGN)]))

    GraphGate(StubScanner(), spy).decide(GUARD_DROPPED, replication=0)

    assert spy.systems == [SYSTEM_PROMPT]


def test_a_file_is_parsed_once_however_often_it_is_seen(monkeypatch):
    parsed = []
    real = graph_gate.extract
    monkeypatch.setattr(graph_gate, "extract", lambda path, text: parsed.append(path) or real(path, text))
    gate = GraphGate(StubScanner(), None, use_triage=False)

    gate.decide(GUARD_DROPPED, replication=0)
    gate.decide(GUARD_DROPPED, replication=1)

    assert sorted(parsed) == ["api.py", "api.py", "store.py"]      # two versions of api.py, one of store.py


def many_flags(count):
    gate = GraphGate(StubScanner(), None)
    before, after = gate.graph(GUARD_DROPPED.before), gate.graph(GUARD_DROPPED.after)
    flags = [Flag("R2", "new path", nodes=(f"api.py::upload#{name}", f"sink@store.py::save::open{n}"))
             for n in range(count) for name in ("name", "data")]
    return flag_items(flags, GUARD_DROPPED, before, after, max_items=3), flags


def test_flags_are_grouped_and_what_is_not_shown_is_still_recorded():
    (items, record), flags = many_flags(5)

    assert [item.id for item in items] == ["G1", "G2", "G3"]       # one item per sink, three shown
    assert len(record) == len(flags) == 10
    assert [r["item"] for r in record] == ["G1", "G1", "G2", "G2", "G3", "G3", None, None, None, None]


def test_code_shown_with_an_item_is_cut_to_its_budget():
    gate = GraphGate(StubScanner(), None)
    before, after = gate.graph(GUARD_DROPPED.before), gate.graph(GUARD_DROPPED.after)
    flag = Flag("R3", "guard gone", nodes=("api.py::upload", "store.py::save"))

    whole, _ = flag_items([flag], GUARD_DROPPED, before, after)
    cut, _ = flag_items([flag], GUARD_DROPPED, before, after, max_code_chars=60)

    assert "def save(name, data):" in whole[0].text and "not shown" not in whole[0].text
    assert "def save(name, data):" not in cut[0].text and "more function(s) not shown" in cut[0].text


def test_nodes_are_described_in_words():
    gate = GraphGate(StubScanner(), None)
    graph = gate.graph(GUARD_DROPPED.before)
    guard = next(n for n in graph.nodes if n.startswith("guard@"))

    assert describe(graph, "api.py::upload#name") == "parameter `name` of `upload`"
    assert describe(graph, "sink@store.py::save::builtins.open") == "the call to `builtins.open` in `save`"
    assert describe(graph, "api.py::upload") == "`upload` (api.py)"
    assert describe(graph, guard) == "the test `if ' .. ' in _` in `upload`"
    assert describe(graph, "ext::builtins.ValueError") == "`builtins.ValueError`"
