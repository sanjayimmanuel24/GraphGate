"""Walk one event's regression through the gate's stages and print each (a demonstration).

    python scripts/demo_gate.py nicegui-hxp3
    python scripts/demo_gate.py gitpython-2f96 --fix

Takes a validated event's regression as one change, clean slice to regressed
slice, and shows what each stage of the gate makes of it:

1. the change itself, as a diff;
2. what Semgrep and Bandit say the change introduces (Condition B's input);
3. what the graph rules flag, on the slice alone and with the rest of the
   repository around it (Condition C's two views);
4. the items the triage model would be asked to judge, word for word.

No model is called: the last step prints the question, not an answer, and the
decision shown is the one without triage, where whatever is flagged blocks.
--fix runs the reverse change, the fix, as a control. Reads local files only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from graphgate.dataset.leakage import load_exclusions
from graphgate.gate.analysers import FindingCache, default_scanner
from graphgate.gate.graph_gate import GraphGate
from graphgate.gate.local import CONDITION_B, Change, LocalGate
from graphgate.gate.triage import render_user_prompt
from graphgate.graph.overlay import SnapshotMissing, view_for_event
from graphgate.harness.snapshot import load_snapshot


def heading(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("event", help="event id, for example nicegui-hxp3")
    parser.add_argument("--fix", action="store_true", help="show the reverse change, the fix, as a control")
    parser.add_argument("--events-dir", type=Path, default=Path("data/events"))
    parser.add_argument("--repo-snapshots", type=Path, default=Path("data/interim/repo_snapshots"))
    parser.add_argument("--leakage", type=Path, default=Path("data/leakage_exclusions.json"))
    parser.add_argument("--analysis-cache", type=Path, default=Path("runs/analysis-cache.sqlite"))
    parser.add_argument("--diff-lines", type=int, default=40, help="lines of the diff to print")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    event_dir = args.events_dir / args.event
    if not event_dir.is_dir():
        raise SystemExit(f"no event {args.event} in {args.events_dir.as_posix()}")
    clean, regressed = load_snapshot(event_dir / "clean").files, load_snapshot(event_dir / "regressed").files
    change = Change.between(regressed, clean) if args.fix else Change.between(clean, regressed)

    heading(f"1. The change: {args.event}, {'the fix (control)' if args.fix else 'the regression'}")
    lines = change.diff.splitlines()
    print("\n".join(lines[:args.diff_lines]))
    if len(lines) > args.diff_lines:
        print(f"... ({len(lines) - args.diff_lines} more line(s) of diff)")

    args.analysis_cache.parent.mkdir(parents=True, exist_ok=True)
    with FindingCache(args.analysis_cache) as cache:
        scanner = default_scanner(cache=cache)
        heading("2. Static analysis of the change (Semgrep and Bandit)")
        local = LocalGate(CONDITION_B, scanner, None, use_triage=False).decide(change, replication=0)
        print(f"findings the change introduces: {len(local.findings_introduced)}")
        for finding in local.findings_introduced:
            print(f"  {finding.path}:{finding.start_line}  {finding.tool} {finding.rule_id.split('.')[-1]}")
        print(f"Condition B without triage: {local.decision}")

        heading("3. The graph rules R1 to R4")
        left_out = load_exclusions(args.leakage).get(args.event) if args.leakage.exists() else None
        views = {"slice alone (C-slice)": None}
        try:
            views["with the repository (C, registered)"] = view_for_event(
                event_dir, args.repo_snapshots,
                exclude_files=left_out.files if left_out else (),
                exclude_symbols=left_out.symbols if left_out else ())
        except SnapshotMissing as missing:
            print(f"repository view not shown: {missing}")
        decisions = {}
        for name, view in views.items():
            gate = GraphGate(scanner, None, use_triage=False, view=view)
            decision = decisions[name] = gate.decide(change, replication=0)
            stats = gate.graph(change.after).graph["stats"]
            rules = sorted({flag["rule"] for flag in decision.flags})
            print(f"{name}: graph of {stats['files']} file(s), {stats['symbols']} symbol(s), "
                  f"{stats['unknown_calls']} of {stats['calls_total']} call(s) unresolved")
            print(f"    flags: {len(decision.flags)}  rules: {', '.join(rules) or 'none'}  "
                  f"-> without triage: {decision.decision}  ({decision.seconds['graph']:.2f} s)")

    shown = decisions[list(decisions)[-1]]
    heading("4. What the triage model would be asked (no model is called here)")
    if not shown.items:
        print("nothing was flagged, so nothing is sent to the model: the change is allowed")
    else:
        items = [type("Item", (), item) for item in shown.items]
        prompt = render_user_prompt("<the diff shown above>", items)
        print(prompt.split("Items to judge:")[1].strip())
        print("\nThe model labels each item exploitable-regression, benign-refactor or uncertain;")
        print("the change is blocked only if an item is judged an exploitable regression.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
