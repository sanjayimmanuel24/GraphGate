"""Run rules R1 to R4 over each event's regression (BUILD_PLAN 4.5).

    python scripts/delta_events.py
    python scripts/delta_events.py mako-2h4p gitpython-2f96

Treats every validated event's regression as one change, clean slice to
regressed slice, builds the code graph of both and prints the flags the rules
raise. The counterpart of scripts/scan_events.py for the graph rules.

It is a first look, not a gate result: no model turn is involved and no
triage, the graphs cover the event's slice and not the whole repository, and
whether the rules also fire on harmless changes can only be measured on
recorded traces.

What was fixed before the first run and is reported whatever it shows:
- the graph settings of Condition C (link.GRAPHGATE) and, beside them, the
  other three combinations (link.SETTINGS);
- the rules' depth of 2 symbols around the change, with 1, 3 and no bound
  beside it for Condition C's settings;
- a control: the same rules on the reverse change, regressed to clean, which is
  the fix. A detector that flags the fix as often as the regression only
  detects that something changed.

Without event ids the result is written to data/delta_first_look.json. With
event ids it is only printed, so a partial run cannot replace the full record.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from graphgate.dataset.traceplan import select_events
from graphgate.graph.delta import DEFAULT_HOPS, apply_rules, changed_symbols, free_paths
from graphgate.graph.link import SETTINGS, build_graph
from graphgate.graph.model import with_role
from graphgate.harness.snapshot import load_snapshot

SCHEMA_VERSION = 1
PRIMARY = "graphgate"
DEPTHS = (1, 2, 3, None)
RULE_NAMES = ("R1", "R2", "R3", "R4")


def load_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def rules_fired(flags) -> list[str]:
    return sorted({flag.rule for flag in flags})


def tally(record: dict, key) -> dict:
    """Events flagged, overall and by class and scope, for one way of reading an entry."""
    groups: dict[str, dict[str, int]] = {}
    for entry in record.values():
        group = groups.setdefault(f"{entry['vulnerability_class']}/{entry['scope']}", {"events": 0, "flagged": 0})
        group["events"] += 1
        group["flagged"] += bool(key(entry))
    by_scope = {scope: {"events": sum(g["events"] for n, g in groups.items() if n.endswith("/" + scope)),
                        "flagged": sum(g["flagged"] for n, g in groups.items() if n.endswith("/" + scope))}
                for scope in ("cross_file", "local")}
    return {"events": len(record), "flagged": sum(g["flagged"] for g in groups.values()),
            "by_scope": by_scope, "by_class_and_scope": {name: groups[name] for name in sorted(groups)}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("events", nargs="*", help="event ids to preview (nothing is written)")
    parser.add_argument("--events-dir", type=Path, default=Path("data/events"))
    parser.add_argument("--signoff", type=Path, default=Path("data/validation_signoff.json"))
    parser.add_argument("--ai-review", type=Path, default=Path("data/validation_ai_review.json"))
    parser.add_argument("--out", type=Path, default=Path("data/delta_first_look.json"))
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    ai_review = {r["event_id"]: r for r in load_json(args.ai_review, {"results": []})["results"]}
    decisions = load_json(args.signoff, {"decisions": {}})["decisions"]
    selected = tuple(args.events) or select_events(args.events_dir, ai_review, decisions).events
    if not selected:
        print(f"no validated event in {args.signoff.as_posix()}")
        return 1

    record = {}
    for event_id in selected:
        event_dir = args.events_dir / event_id
        clean, regressed = load_snapshot(event_dir / "clean").files, load_snapshot(event_dir / "regressed").files
        facts = json.loads((event_dir / "event.json").read_text(encoding="utf-8"))
        entry = {"vulnerability_class": facts["vulnerability_class"], "scope": facts["scope"], "settings": {}}
        for name, config in SETTINGS.items():
            before, after = build_graph(clean, config=config), build_graph(regressed, config=config)
            flags = apply_rules(before, after, hops=DEFAULT_HOPS)
            entry["settings"][name] = {
                "rules": rules_fired(flags), "flags": len(flags),
                "fix_rules": rules_fired(apply_rules(after, before, hops=DEFAULT_HOPS)),
            }
            if name == PRIMARY:
                entry["changed_symbols"] = sorted(changed_symbols(before, after))
                entry["unknown_calls"] = after.graph["stats"]["unknown_calls"]
                entry["calls"] = after.graph["stats"]["calls_total"]
                entry["by_depth"] = {str(depth): rules_fired(apply_rules(before, after, hops=depth))
                                     for depth in DEPTHS}
                entry["flag_summaries"] = [f"{flag.rule}: {flag.summary}" for flag in flags][:12]
                # What the slice's graph holds at all. Descriptive: added after the first run
                # to explain its misses, and it changes no flag.
                edges_of = lambda graph: set(graph.edges(keys=True))
                entry["graph"] = {"sinks": len(with_role(before, "sink")),
                                  "source_sink_pairs": len(free_paths(before)),
                                  "edges_changed": edges_of(before) != edges_of(after)}
        record[event_id] = entry
        primary = entry["settings"][PRIMARY]
        print(f"{event_id:<20} [{facts['vulnerability_class']}, {facts['scope']}] "
              f"{', '.join(primary['rules']) or 'no flag':<14} "
              f"fix: {', '.join(primary['fix_rules']) or 'no flag':<14} "
              f"as proposed: {', '.join(entry['settings']['as-proposed']['rules']) or 'no flag'}")

    summary = {
        "settings": {name: tally(record, lambda e, n=name: e["settings"][n]["rules"]) for name in SETTINGS},
        "control_fix_flagged": {name: tally(record, lambda e, n=name: e["settings"][n]["fix_rules"])["flagged"]
                                for name in SETTINGS},
        "by_rule": {rule: sum(rule in e["settings"][PRIMARY]["rules"] for e in record.values())
                    for rule in RULE_NAMES},
        "control_fix_by_rule": {rule: sum(rule in e["settings"][PRIMARY]["fix_rules"] for e in record.values())
                                for rule in RULE_NAMES},
        "by_depth": {str(depth): sum(bool(e["by_depth"][str(depth)]) for e in record.values())
                     for depth in DEPTHS},
        "slice_graphs": {"without_a_sink": sum(e["graph"]["sinks"] == 0 for e in record.values()),
                         "without_a_source_to_sink_path": sum(e["graph"]["source_sink_pairs"] == 0
                                                              for e in record.values()),
                         "regression_changes_an_edge": sum(e["graph"]["edges_changed"] for e in record.values())},
    }
    print()
    for name in SETTINGS:
        result = summary["settings"][name]
        print(f"{name:<26} flags {result['flagged']:>2} of {result['events']} regressions "
              f"(cross-file {result['by_scope']['cross_file']['flagged']} of "
              f"{result['by_scope']['cross_file']['events']}, local {result['by_scope']['local']['flagged']} of "
              f"{result['by_scope']['local']['events']}); flags {summary['control_fix_flagged'][name]} of the fixes")
    print(f"by rule ({PRIMARY}): {summary['by_rule']}; on the fixes: {summary['control_fix_by_rule']}")
    print(f"by depth ({PRIMARY}): {summary['by_depth']}")
    print(f"slice graphs: {summary['slice_graphs']}")

    if args.events:
        print("preview only: nothing written")
        return 0
    args.out.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "note": "Each validated event's regression taken as one change (clean slice to regressed slice), the "
                "code graph of both built, and rules R1 to R4 applied. A first look, not a gate result: no "
                "model turn and no triage is involved, the graphs cover the slice and not the repository, "
                "and the false-alarm rate on harmless changes is not measured here. 'fix_rules' is the "
                "control: the same rules on the reverse change.",
        "primary_setting": PRIMARY,
        "settings": {name: config.to_dict() for name, config in SETTINGS.items()},
        "hops": DEFAULT_HOPS,
        "summary": summary,
        "events": {event_id: record[event_id] for event_id in sorted(record)},
    }, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.out.as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
