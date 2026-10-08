"""Build the code graph of a directory, or check the builder on the seed repositories.

    python scripts/build_graph.py path/to/package
    python scripts/build_graph.py path/to/package --json runs/graph.json
    python scripts/build_graph.py --check

The first form prints what the graph holds: symbols, calls by how they were
resolved, the calls that could not be resolved, sources, sinks and sanitizers.

--check is the exit check of BUILD_PLAN M2.1: it builds the graph of every
selected seed repository from its local clone (data/interim/clones/, at the
commit checked out there) and writes data/graph_build_check.json with the
unknown-edge counts per repository, the transparency figure the paper reports.
It runs no rule and reads no regression.
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from graphgate.graph.index import GraphIndex
from graphgate.graph.link import GraphConfig, build_graph, is_test_path
from graphgate.graph.model import SANITIZE, TAINT, edges, to_json, with_role

SKIPPED_DIRS = {".git", ".venv", "venv", "node_modules", "build", "dist", "__pycache__", ".tox"}


def python_files(root: Path) -> dict[str, str]:
    """Repository path (POSIX, relative to ``root``) to text, for every Python file."""
    files = {}
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if SKIPPED_DIRS & set(relative.parts):
            continue
        files[relative.as_posix()] = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
    return files


def summary(graph) -> dict:
    stats = graph.graph["stats"]
    return {
        "files": stats["files"], "symbols": stats["symbols"], "nodes": graph.number_of_nodes(),
        "calls": stats["calls"], "calls_total": stats["calls_total"], "unknown_calls": stats["unknown_calls"],
        "unknown_share": round(stats["unknown_calls"] / stats["calls_total"], 3) if stats["calls_total"] else 0,
        "parse_errors": stats["parse_errors"],
        "taint_edges": sum(1 for _ in edges(graph, TAINT)),
        "sanitize_edges": sum(1 for _ in edges(graph, SANITIZE)),
        "sources": dict(sorted(Counter(graph.nodes[n]["source"] for n in with_role(graph, "source")).items())),
        "sinks": dict(sorted(Counter(graph.nodes[n]["sink"] for n in with_role(graph, "sink")).items())),
        "sanitizers": dict(sorted(Counter(graph.nodes[n]["sanitizer"]
                                          for n in with_role(graph, "sanitizer")).items())),
    }


def check(clones: Path, manifest: Path, out: Path, config: GraphConfig) -> int:
    repos = [r["repo"] for r in json.loads(manifest.read_text(encoding="utf-8"))["repos"] if r["role"] == "selected"]
    rows = []
    for repo in repos:
        clone = clones / repo.replace("/", "__")
        if not clone.is_dir():
            print(f"{repo}: no local clone at {clone.as_posix()}, skipped")
            continue
        files = {p: t for p, t in python_files(clone).items() if not is_test_path(p)}
        started = time.perf_counter()
        graph = build_graph(files, config=config)
        built = time.perf_counter() - started
        # One file touched: how long the stored graph takes to follow (BUILD_PLAN 4.4).
        with tempfile.TemporaryDirectory() as scratch, GraphIndex(Path(scratch) / "g.sqlite", config=config) as index:
            index.update(files)
            touched = max(files, key=lambda p: len(files[p]))
            started = time.perf_counter()
            update = index.apply({touched: files[touched] + "\nGRAPH_CHECK = 1\n"})
            followed = time.perf_counter() - started
            assert update.parsed == (touched,)
        commit = subprocess.run(["git", "-C", str(clone), "rev-parse", "HEAD"], capture_output=True,
                                text=True).stdout.strip()
        row = {"repo": repo, "commit": commit, **summary(graph), "seconds_full_build": round(built, 2),
               "seconds_after_one_file_changed": round(followed, 2)}
        rows.append(row)
        print(f"{repo:<34} {row['files']:>4} files {row['symbols']:>6} symbols {row['calls_total']:>6} calls "
              f"{row['unknown_share']:>6.1%} unknown  {built:5.1f}s full, {followed:4.1f}s after one file")
    total = sum(r["calls_total"] for r in rows)
    unknown = sum(r["unknown_calls"] for r in rows)
    report = {
        "schema_version": 1,
        "note": "Graph builder run on the selected seed repositories at the commit of the local clone, test "
                "files left out. Structural counts only: no rule was run and no regression was read.",
        "config": config.to_dict(),
        "repositories": rows,
        "totals": {"repositories": len(rows), "files": sum(r["files"] for r in rows),
                   "symbols": sum(r["symbols"] for r in rows), "calls": total, "unknown_calls": unknown,
                   "unknown_share": round(unknown / total, 3) if total else 0,
                   "files_with_parse_errors": sum(len(r["parse_errors"]) for r in rows)},
    }
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"\n{len(rows)} repositories, {total} calls, {unknown} unknown "
          f"({report['totals']['unknown_share']:.1%}); wrote {out.as_posix()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("directory", nargs="?", type=Path, help="directory whose Python files to read")
    parser.add_argument("--check", action="store_true", help="run the builder on every selected seed repository")
    parser.add_argument("--json", type=Path, default=None, help="also write the whole graph here")
    parser.add_argument("--public-api-sources", action="store_true",
                        help="treat the parameters of public functions as sources")
    parser.add_argument("--structural-guards", action="store_true",
                        help="count tests that raise or exit as guard edges")
    parser.add_argument("--clones", type=Path, default=Path("data/interim/clones"))
    parser.add_argument("--manifest", type=Path, default=Path("data/seed_repos.json"))
    parser.add_argument("--out", type=Path, default=Path("data/graph_build_check.json"))
    parser.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)-7s %(name)s: %(message)s")
    sys.stdout.reconfigure(encoding="utf-8")
    config = GraphConfig(public_api_sources=args.public_api_sources, structural_guards=args.structural_guards)

    if args.check:
        return check(args.clones, args.manifest, args.out, config)
    if args.directory is None or not args.directory.is_dir():
        parser.error("give a directory, or --check")
    graph = build_graph(python_files(args.directory), config=config)
    print(json.dumps(summary(graph), indent=2))
    worst = sorted(graph.graph["stats"]["unknown_by_file"].items(), key=lambda item: -item[1])[:10]
    for path, count in worst:
        print(f"  {count:>5} unknown call(s) in {path}")
    if args.json:
        args.json.write_text(json.dumps(to_json(graph), indent=1) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {args.json.as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
