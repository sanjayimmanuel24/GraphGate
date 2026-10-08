"""Run Semgrep and Bandit over each event's regression (BUILD_PLAN 3.1).

    python scripts/scan_events.py
    python scripts/scan_events.py piccolo-xq59 mako-2h4p

Treats every validated event's regression as one change, clean slice to
regressed slice, and prints the injection-family findings that change
introduces or removes. It is a check that the wrapper works on the project's
real code, and a first look at what the two tools can see.

It is not a gate result: no model turn is involved, no triage, and a finding
"introduced" here still has to survive both in Condition B. Reads local files
only and makes no network or API call.

Without event ids the result is also written to data/static_first_look.json,
which the paper reads. With event ids it is only printed, so a partial run
cannot replace the full record.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from graphgate.dataset.traceplan import select_events
from graphgate.gate.analysers import FindingCache, default_scanner
from graphgate.harness.snapshot import load_snapshot

SCHEMA_VERSION = 1


def load_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("events", nargs="*", help="event ids to preview (nothing is written)")
    parser.add_argument("--events-dir", type=Path, default=Path("data/events"))
    parser.add_argument("--signoff", type=Path, default=Path("data/validation_signoff.json"))
    parser.add_argument("--ai-review", type=Path, default=Path("data/validation_ai_review.json"))
    parser.add_argument("--rules-manifest", type=Path, default=Path("data/semgrep_rules.json"))
    parser.add_argument("--out", type=Path, default=Path("data/static_first_look.json"))
    parser.add_argument("--cache", type=Path, default=Path("runs/analysis-cache.sqlite"),
                        help="scan results kept by file content (default: %(default)s)")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    ai_review = {r["event_id"]: r for r in load_json(args.ai_review, {"results": []})["results"]}
    decisions = load_json(args.signoff, {"decisions": {}})["decisions"]
    selected = tuple(args.events) or select_events(args.events_dir, ai_review, decisions).events
    if not selected:
        print(f"no validated event in {args.signoff.as_posix()}")
        return 1

    events = {}
    for event_id in selected:
        event_dir = args.events_dir / event_id
        clean, regressed = load_snapshot(event_dir / "clean").files, load_snapshot(event_dir / "regressed").files
        changed = sorted(p for p in set(clean) | set(regressed) if clean.get(p) != regressed.get(p))
        facts = json.loads((event_dir / "event.json").read_text(encoding="utf-8"))
        events[event_id] = (clean, regressed, changed, facts)

    record = {}
    with FindingCache(args.cache) as cache:
        scanner = default_scanner(cache=cache)
        versions = scanner.versions()
        print(f"semgrep {versions['semgrep']}, bandit {versions['bandit']}, "
              f"rules {scanner.ruleset.commit[:12]} ({scanner.ruleset.sha256[:12]})")
        # Every file version of every event in one go: Semgrep's start-up
        # cost is then paid once, not once per event.
        scanner.scan((path, files[path]) for clean, regressed, changed, _ in events.values()
                     for files in (clean, regressed) for path in changed if path in files)

        for event_id, (clean, regressed, changed, facts) in events.items():
            scan = scanner.scan_change(clean, regressed, changed)
            introduced, resolved = scan.findings.introduced, scan.findings.resolved
            print(f"{event_id} [{facts['vulnerability_class']}, {facts['scope']}]: "
                  f"{len(scan.findings.before)} finding(s) before, {len(scan.findings.after)} after; "
                  f"{len(introduced)} introduced, {len(resolved)} removed")
            for sign, findings in (("+", introduced), ("-", resolved)):
                for f in findings:
                    print(f"    {sign} {f.path}:{f.start_line} {f.tool} {f.rule_id.split('.')[-1]} "
                          f"(CWE {', '.join(str(c) for c in f.cwes)}; {f.severity})")
            for message in scan.errors:
                print(f"    ! {message}")
            record[event_id] = {
                "vulnerability_class": facts["vulnerability_class"], "scope": facts["scope"],
                "changed_files": changed,
                "findings_before": len(scan.findings.before), "findings_after": len(scan.findings.after),
                "introduced": [{"tool": f.tool, "rule_id": f.rule_id, "path": f.path, "line": f.start_line,
                                "cwes": list(f.cwes), "severity": f.severity} for f in introduced],
                "removed": len(resolved), "errors": list(scan.errors)}
        print(f"\ntool runs: {scanner.runs}")
        config = scanner.config

    groups: dict[str, dict[str, int]] = {}
    for entry in record.values():
        group = groups.setdefault(f"{entry['vulnerability_class']}/{entry['scope']}", {"events": 0, "with_finding": 0})
        group["events"] += 1
        group["with_finding"] += bool(entry["introduced"])
    caught = sum(g["with_finding"] for g in groups.values())
    print(f"{caught} of {len(record)} regression(s) introduce at least one family finding:")
    for name in sorted(groups):
        cls, scope = name.split("/")
        print(f"    {cls:<15} {scope:<11} {groups[name]['with_finding']} of {groups[name]['events']}")

    if args.events:
        print("preview only: nothing written")
        return 0
    rules = load_json(args.rules_manifest, {})
    args.out.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "note": "Each validated event's regression taken as one change (clean slice to regressed "
                "slice) and scanned with Semgrep and Bandit. A first look at what the two tools can "
                "see, not a gate result: no model turn and no triage is involved.",
        "tools": versions,
        "rules": {"commit": rules.get("commit"), "sha256": rules.get("ruleset_sha256"),
                  "rule_files": rules.get("rule_files"), "rule_files_by_cwe": rules.get("rule_files_by_cwe")},
        "scanner_config": config,
        "summary": {"events": len(record), "with_introduced_finding": caught,
                    "by_class_and_scope": {name: groups[name] for name in sorted(groups)}},
        "events": {event_id: record[event_id] for event_id in sorted(record)},
    }, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.out.as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
