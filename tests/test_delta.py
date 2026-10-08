"""Rules R1 to R4, each on graphs small enough to draw by hand (BUILD_PLAN 4.5).

Every rule is shown firing and, next to it, the nearest cases where it must
stay silent. No graph here comes from parsed code.
"""

from graphgate.graph.delta import (
    Flag,
    apply_rules,
    changed_symbols,
    guard_elimination,
    guarded_symbols,
    neighbourhood,
    new_paths,
    path_shortening,
    sanitizer_removal,
    symbols_on_paths,
)
from graphgate.graph.model import CALL, SANITIZE, TAINT, add_edge, new_graph


def graph(*, sources=(), sinks=(), sanitizers=(), symbols=(), taint=(), sanitize=(), call=()):
    """Build a graph from lists: ``taint`` entries are (from, to) or (from, to, via)."""
    g = new_graph()
    for name in sources:
        g.add_node(name, source="request")
    for name in sinks:
        g.add_node(name, sink="sql")
    for name in sanitizers:
        g.add_node(name, sanitizer="library")
    for name in symbols:
        g.add_node(name, kind="function", digest=name)
    for u, v, *via in taint:
        add_edge(g, u, v, TAINT, via=via)
    for u, v in sanitize:
        add_edge(g, u, v, SANITIZE, uses=["check"])
    for u, v in call:
        add_edge(g, u, v, CALL)
    return g


def rules(flags):
    return [flag.rule for flag in flags]


# --- R1: sanitizer removal -----------------------------------------------------------

def sanitized_flow():
    """view reads a request value, quotes it and runs it."""
    return graph(sources=["req"], sinks=["run"], sanitizers=["quote"], symbols=["view"],
                 taint=[("req", "quote", "view"), ("quote", "run", "view")], sanitize=[("view", "quote")])


def test_r1_fires_when_the_sanitizer_is_gone_and_its_caller_remains():
    after = graph(sources=["req"], sinks=["run"], symbols=["view"], taint=[("req", "run", "view")])

    flags = sanitizer_removal(sanitized_flow(), after)

    assert flags == [Flag("R1", "sanitizer quote is gone while 1 caller(s) remain", nodes=("quote", "view"),
                          detail={"how": "absent"})]


def test_r1_is_silent_when_the_caller_went_with_the_sanitizer():
    after = graph(sources=["req"], sinks=["run"])

    assert sanitizer_removal(sanitized_flow(), after) == []


def test_r1_fires_when_a_caller_routes_the_value_around_a_sanitizer_it_still_calls():
    after = sanitized_flow()
    add_edge(after, "req", "run", TAINT, via=["view"])

    flags = sanitizer_removal(sanitized_flow(), after)

    assert rules(flags) == ["R1"] and flags[0].nodes == ("quote", "view")
    assert flags[0].detail == {"how": "bypassed", "receives_unsanitized": ["run"]}


def test_r1_bypass_is_per_caller_when_another_caller_keeps_the_sanitizer():
    before = sanitized_flow()
    before.add_node("job", kind="function", digest="job")
    add_edge(before, "job", "quote", SANITIZE, uses=["transform"])
    after = before.copy()
    after.remove_edge("view", "quote", SANITIZE)
    after.remove_edge("req", "quote", TAINT)
    after.remove_edge("quote", "run", TAINT)
    add_edge(after, "req", "run", TAINT, via=["view"])

    flags = sanitizer_removal(before, after)

    assert [(f.nodes, f.detail["how"]) for f in flags] == [(("quote", "view"), "bypassed")]


def test_r1_is_silent_when_the_caller_drops_the_sanitizer_together_with_the_use():
    before = sanitized_flow()
    before.add_node("job", kind="function", digest="job")
    add_edge(before, "job", "quote", SANITIZE, uses=["transform"])     # keeps the node alive
    after = before.copy()
    for u, v, kind in (("view", "quote", SANITIZE), ("req", "quote", TAINT), ("quote", "run", TAINT)):
        after.remove_edge(u, v, kind)

    assert sanitizer_removal(before, after) == []


def test_r1_is_silent_when_the_unsanitized_route_was_already_there():
    before = sanitized_flow()
    add_edge(before, "req", "run", TAINT, via=["view"])

    assert sanitizer_removal(before, before.copy()) == []


def test_r1_ignores_a_value_another_symbol_passes_unsanitized():
    after = sanitized_flow()
    add_edge(after, "req", "run", TAINT, via=["other"])

    assert sanitizer_removal(sanitized_flow(), after) == []


# --- R2: new source-to-sink path -----------------------------------------------------

def test_r2_fires_on_a_path_that_did_not_exist():
    before = graph(sources=["req"], sinks=["run"], taint=[("req", "helper#x", "view")])
    after = graph(sources=["req"], sinks=["run"],
                  taint=[("req", "helper#x", "view"), ("helper#x", "run", "helper")])

    flags = new_paths(before, after)

    assert rules(flags) == ["R2"] and flags[0].nodes == ("req", "run")
    assert flags[0].path == ("req", "helper#x", "run")
    assert flags[0].detail == {"sink": "sql", "source": "request"}


def test_r2_is_silent_when_the_path_was_already_there():
    same = graph(sources=["req"], sinks=["run"], taint=[("req", "run", "view")])

    assert new_paths(same, same.copy()) == []


def test_r2_does_not_count_a_path_through_a_sanitizer():
    before = graph(sources=["req"], sinks=["run"])

    assert new_paths(before, sanitized_flow()) == []


def test_r2_fires_when_the_sanitizer_on_the_only_path_is_removed():
    after = graph(sources=["req"], sinks=["run"], symbols=["view"], taint=[("req", "run", "view")])

    assert rules(new_paths(sanitized_flow(), after)) == ["R2"]


def test_r2_is_per_source_and_sink_pair():
    before = graph(sources=["req", "env"], sinks=["run", "open"], taint=[("req", "run")])
    after = graph(sources=["req", "env"], sinks=["run", "open"], taint=[("req", "run"), ("env", "open")])

    assert [f.nodes for f in new_paths(before, after)] == [("env", "open")]


def test_r2_is_silent_when_a_joined_pair_gets_a_second_route():
    before = graph(sources=["req"], sinks=["run"], taint=[("req", "a#x"), ("a#x", "run")])
    after = before.copy()
    add_edge(after, "req", "b#y", TAINT)
    add_edge(after, "b#y", "run", TAINT)

    assert new_paths(before, after) == []


# --- R3: guard elimination -----------------------------------------------------------

def guarded_flow():
    """handler reads a request value, has it checked, and passes it to a sink."""
    return graph(sources=["req"], sinks=["run"], sanitizers=["check_name"], symbols=["handler"],
                 taint=[("req", "run", "handler")], sanitize=[("handler", "check_name")])


def test_r3_fires_when_a_guard_on_a_live_path_disappears():
    after = guarded_flow()
    after.remove_edge("handler", "check_name", SANITIZE)

    flags = guard_elimination(guarded_flow(), after)

    assert flags == [Flag("R3", "handler no longer applies check_name", nodes=("handler", "check_name"),
                          detail={"uses": ["check"], "added_instead": []})]


def test_r3_is_silent_while_the_guard_edge_is_still_there():
    assert guard_elimination(guarded_flow(), guarded_flow()) == []


def test_r3_is_silent_for_a_symbol_that_is_on_no_source_to_sink_path():
    before = graph(sinks=["run"], sanitizers=["check_name"], symbols=["handler"],
                   taint=[("handler#x", "run", "handler")], sanitize=[("handler", "check_name")])
    after = before.copy()
    after.remove_edge("handler", "check_name", SANITIZE)

    assert guard_elimination(before, after) == []


def test_r3_is_silent_when_the_path_went_away_with_the_guard():
    after = graph(sources=["req"], sinks=["run"], sanitizers=["check_name"], symbols=["handler"])

    assert guard_elimination(guarded_flow(), after) == []


def test_r3_reports_what_took_the_place_of_a_guard():
    after = guarded_flow()
    after.remove_edge("handler", "check_name", SANITIZE)
    add_edge(after, "handler", "guard@handler::abc", SANITIZE, uses=["check"])

    flags = guard_elimination(guarded_flow(), after)

    assert flags[0].detail["added_instead"] == ["guard@handler::abc"]


def test_r3_reaches_into_a_validation_function_that_guards_a_live_path():
    """The path never runs through check_name, but a guard inside it protects the path."""
    before = guarded_flow()
    add_edge(before, "check_name", "helper", CALL)
    add_edge(before, "check_name", "guard@check_name::1", SANITIZE, uses=["check"])
    add_edge(before, "helper", "guard@helper::2", SANITIZE, uses=["check"])
    after = before.copy()
    after.remove_edge("check_name", "guard@check_name::1", SANITIZE)
    after.remove_edge("helper", "guard@helper::2", SANITIZE)

    flags = guard_elimination(before, after)

    assert [f.nodes for f in flags] == [("check_name", "guard@check_name::1"), ("helper", "guard@helper::2")]


def test_guarded_symbols_are_the_path_symbols_and_their_guards():
    g = guarded_flow()
    add_edge(g, "check_name", "helper", CALL)
    add_edge(g, "handler", "logger", CALL)             # an ordinary callee is not a guard

    assert symbols_on_paths(g) == {"req", "run", "handler"}
    assert guarded_symbols(g) == {"req", "run", "handler", "check_name", "helper"}


# --- R4: path shortening -------------------------------------------------------------

def layered(*, direct):
    """Request value through a validating layer to the store, or straight to it."""
    hops = [("req", "store#q", "view")] if direct else [("req", "layer#v", "view"), ("layer#v", "store#q", "layer")]
    return graph(sources=["req"], sinks=["run"], taint=[*hops, ("store#q", "run", "store")])


def test_r4_fires_when_the_shortest_path_loses_a_hop():
    flags = path_shortening(layered(direct=False), layered(direct=True))

    assert rules(flags) == ["R4"] and flags[0].nodes == ("req", "run")
    assert flags[0].path == ("req", "store#q", "run")
    assert flags[0].detail == {"hops_before": 3, "hops_after": 2,
                               "path_before": ["req", "layer#v", "store#q", "run"]}


def test_r4_is_silent_when_the_path_keeps_its_length_or_grows():
    assert path_shortening(layered(direct=True), layered(direct=True)) == []
    assert path_shortening(layered(direct=True), layered(direct=False)) == []


def test_r4_leaves_a_pair_that_was_not_joined_before_to_r2():
    before = graph(sources=["req"], sinks=["run"])
    after = layered(direct=True)

    assert path_shortening(before, after) == [] and rules(new_paths(before, after)) == ["R2"]


def test_r4_measures_the_sanitizer_free_path_only():
    """A shorter route that passes a sanitizer does not shorten anything."""
    after = layered(direct=False)
    after.add_node("quote", sanitizer="library")
    add_edge(after, "req", "quote", TAINT, via=["view"])
    add_edge(after, "quote", "run", TAINT, via=["view"])

    assert path_shortening(layered(direct=False), after) == []


# --- the delta: changed symbols and their neighbourhood ------------------------------

def chain():
    """req -> a -> b -> c -> run, one symbol per hop."""
    return graph(sources=["req"], sinks=["run"], symbols=["a", "b", "c"],
                 taint=[("req", "a#x", "a"), ("a#x", "b#x", "a"), ("b#x", "c#x", "b")],
                 call=[("a", "b"), ("b", "c")])


def with_ports(g):
    for port in ("a#x", "b#x", "c#x"):
        g.nodes[port]["symbol"] = port[0]
    g.nodes["req"]["symbol"] = "a"
    g.nodes["run"]["symbol"] = "c"
    return g


def test_changed_symbols_are_added_removed_or_edited_symbols_only():
    before, after = with_ports(chain()), with_ports(chain())
    after.nodes["b"]["digest"] = "edited"
    after.add_node("d", kind="function", digest="d")
    after.remove_node("c")
    after.add_node("c#x", symbol="c")                  # a port is not a symbol

    assert changed_symbols(before, after) == {"b", "c", "d"}


def test_neighbourhood_counts_hops_between_symbols_not_ports():
    g = with_ports(chain())

    assert neighbourhood(g, g, {"a"}, 0) == {"a"}
    assert neighbourhood(g, g, {"a"}, 1) == {"a", "b"}
    assert neighbourhood(g, g, {"a"}, 2) == {"a", "b", "c"}


def test_apply_rules_returns_nothing_when_no_symbol_changed():
    g = with_ports(chain())

    assert apply_rules(g, g.copy()) == []


def test_apply_rules_sees_only_what_is_near_the_change():
    """c gains the sink call; the source is two symbols away."""
    before, after = with_ports(chain()), with_ports(chain())
    add_edge(after, "c#x", "run", TAINT, via=["c"])
    after.nodes["c"]["digest"] = "edited"

    assert rules(apply_rules(before, after, hops=1)) == []       # a, which reads the source, is out of view
    assert rules(apply_rules(before, after, hops=2)) == ["R2"]
    assert rules(apply_rules(before, after, hops=None)) == ["R2"]


def test_apply_rules_runs_only_the_rules_asked_for():
    before, after = with_ports(chain()), with_ports(chain())
    add_edge(after, "c#x", "run", TAINT, via=["c"])
    after.nodes["c"]["digest"] = "edited"

    assert apply_rules(before, after, rules=("R1", "R3", "R4")) == []
