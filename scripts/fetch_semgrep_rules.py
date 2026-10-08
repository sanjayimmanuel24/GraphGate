"""Fetch the pinned Semgrep community rules and select the injection family (BUILD_PLAN 3.1).

    python scripts/fetch_semgrep_rules.py
    python scripts/fetch_semgrep_rules.py --check

Downloads github.com/semgrep/semgrep-rules at the commit pinned in
graphgate.gate.rules into data/raw (about 11 MB, once; ignored by git), copies
the Python rules for SQL, command and path injection into
data/raw/semgrep-rules-injection, and writes data/semgrep_rules.json with a
hash of every selected file. --check only verifies that the rules on disk are
the pinned set and touches nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from graphgate.gate.rules import COMMIT, RuleSetError, build, fetch, load_ruleset


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, default=Path("data/raw/semgrep-rules"),
                        help="where the upstream rules are checked out")
    parser.add_argument("--rules", type=Path, default=Path("data/raw/semgrep-rules-injection"),
                        help="where the selected rules go")
    parser.add_argument("--manifest", type=Path, default=Path("data/semgrep_rules.json"))
    parser.add_argument("--check", action="store_true", help="verify only; no download, no write")
    args = parser.parse_args(argv)

    if args.check:
        try:
            ruleset = load_ruleset(args.manifest, args.rules)
        except RuleSetError as exc:
            print(exc)
            return 1
        print(f"{args.rules.as_posix()} is the pinned rule set "
              f"(commit {ruleset.commit[:12]}, sha256 {ruleset.sha256[:12]})")
        return 0

    downloaded = fetch(args.source)
    manifest = build(args.source, args.rules)
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{'downloaded' if downloaded else 'already had'} semgrep-rules at {COMMIT[:12]}")
    print(f"selected {manifest['rule_files']} rule file(s) into {args.rules.as_posix()}: "
          + ", ".join(f"CWE-{c}: {n}" for c, n in manifest["rule_files_by_cwe"].items())
          + f"; {len(manifest['reclassified'])} counted under a CWE upstream does not give them")
    print(f"wrote {args.manifest.as_posix()} (rule set sha256 {manifest['ruleset_sha256'][:12]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
