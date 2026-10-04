"""Regression events: validation dossiers built from reviewed commit pairs (BUILD_PLAN 2.3).

An *event* is one verified vulnerable→fixed pair, inverted: the fixed code is
the clean state and the vulnerable code is the regression injected into a
trace (proposal §6.1). Each event lives in ``data/events/<event_id>/``:

- ``spec.json``     — written by the analyst: the commits, the vulnerable flow
  (entry → guard → sink) and which symbols make up the slice.
- ``clean/``, ``regressed/`` — the trimmed slice at the fixed and the
  vulnerable commit, at real repository paths, with revealing comments
  stripped. ``clean/`` is a harness snapshot directory as it stands.
- ``regression.diff`` — clean → regressed; applying it injects the regression.
- ``event.json``    — the spec plus everything derived from it: the scope
  label, sizes, what was scrubbed, and the checks a human reviews.

An event counts as *validated* only once a human has accepted it; that
decision is recorded separately (data/validation_signoff.json), never here.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import math
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from graphgate.dataset.scrub import scrub
from graphgate.dataset.slicing import trim

SCHEMA_VERSION = 1

LOCAL = "local"
CROSS_FILE = "cross_file"

VULNERABILITY_CLASSES = frozenset({"sql", "os-command", "command", "path-traversal"})
# Where untrusted input enters the code under study. Libraries have no request
# object: their untrusted input is a caller's argument ("library-api").
SOURCE_KINDS = frozenset({"http-request", "cli-arg", "file-content", "network", "env",
                          "library-api", "config"})
SINK_KINDS = frozenset({"subprocess", "sql", "filesystem", "code-load", "other"})

# Rough characters per token for Python source; sizes are for budgeting only.
CHARS_PER_TOKEN = 3.5
SOFT_LIMIT_BYTES = 24 * 1024
HARD_LIMIT_BYTES = 48 * 1024

VARIANTS = ("clean", "regressed")


class SpecError(ValueError):
    pass


def symbol_file(symbol: str) -> str:
    path, sep, qual = symbol.partition("::")
    if not sep or not path.endswith(".py") or not qual:
        raise SpecError(f"symbol must look like 'path/file.py::Qual.name': {symbol!r}")
    return path


def symbol_name(symbol: str) -> str:
    symbol_file(symbol)
    return symbol.partition("::")[2]


def flow_files(flow: dict[str, list[dict]]) -> set[str]:
    """Files holding the flow, using each location's ``true_symbol`` when given.

    An entry or sink too large to put in the slice (a 350-line ``execute``,
    say) is recorded at its nearest call site in the slice as ``symbol``, with
    the real location as ``true_symbol``. The scope label must follow the real
    location, or trimming would decide what counts as cross-file.
    """
    return {symbol_file(loc.get("true_symbol") or loc["symbol"])
            for role in ("entry", "guards", "sinks") for loc in flow[role]}


def classify_scope(flow: dict[str, list[dict]], regression_files: set[str] | list[str]) -> str:
    """Local vs cross-file — the pre-registered rule (decided 2026-09-28).

    Local if the whole flow — entry, guard and sink — lies in one file, which
    the regression necessarily changes because the guard is there; a diff-only
    gate can then see every part of it. Cross-file otherwise: some part of the
    flow sits in a file the regression leaves untouched (proposal §2.2).

    The guard is the changed code that neutralises the flow in the clean
    version, so it must lie in a file the regression changes; anything else
    means the recorded facts are inconsistent.
    """
    for role in ("entry", "guards", "sinks"):
        if not flow.get(role):
            raise SpecError(f"flow needs at least one {role} location")
    guards = {symbol_file(loc["symbol"]) for loc in flow["guards"]}
    outside = guards - set(regression_files)
    if outside:
        raise SpecError(f"guard in a file the regression does not change: {sorted(outside)}")
    return LOCAL if len(flow_files(flow)) == 1 else CROSS_FILE


def load_spec(path: Path) -> dict[str, Any]:
    spec = json.loads(path.read_text(encoding="utf-8"))
    for key in ("event_id", "advisories", "repo", "clean_commit", "regressed_commit",
                "vulnerability_class", "flow", "slice"):
        if key not in spec:
            raise SpecError(f"{path}: missing {key!r}")
    if spec["vulnerability_class"] not in VULNERABILITY_CLASSES:
        raise SpecError(f"{path}: vulnerability_class must be one of {sorted(VULNERABILITY_CLASSES)}")
    for loc in spec["flow"].get("entry", []):
        if loc.get("kind") not in SOURCE_KINDS:
            raise SpecError(f"{path}: entry kind must be one of {sorted(SOURCE_KINDS)}")
    for loc in spec["flow"].get("sinks", []):
        if loc.get("kind") not in SINK_KINDS:
            raise SpecError(f"{path}: sink kind must be one of {sorted(SINK_KINDS)}")
    for role in ("entry", "guards", "sinks"):
        for loc in spec["flow"].get(role, []):
            symbol_file(loc.get("symbol", ""))
            if "true_symbol" in loc:
                if role == "guards":
                    raise SpecError(f"{path}: a guard is the changed code itself; it has no true_symbol")
                symbol_file(loc["true_symbol"])
    for file, symbols in spec["slice"].items():
        if not file.endswith(".py") or not symbols:
            raise SpecError(f"{path}: slice entry {file!r} needs a .py path and symbols")
    return spec


def slice_requests(spec: dict[str, Any]) -> dict[str, list[str]]:
    """Symbols to keep per file: the slice plus every flow location."""
    requests = {f: list(dict.fromkeys(s)) for f, s in spec["slice"].items()}
    for role in ("entry", "guards", "sinks"):
        for loc in spec["flow"][role]:
            symbols = requests.setdefault(symbol_file(loc["symbol"]), [])
            if symbol_name(loc["symbol"]) not in symbols:
                symbols.append(symbol_name(loc["symbol"]))
    return dict(sorted(requests.items()))


class BlobMissing(RuntimeError):
    pass


def read_at(repo_dir: Path, commit: str, path: str) -> str | None:
    """File text at a commit, or None if the path does not exist there.

    Lazy fetching is disabled: several builds run at once against the same
    blobless clone, so blobs are prefetched up front instead
    (scripts/prepare_validation.py) and a missing one is an error.
    """
    listing = subprocess.run(["git", "-C", str(repo_dir), "ls-tree", commit, "--", path],
                             capture_output=True, text=True, check=True).stdout.split()
    if not listing:
        return None
    env = {**os.environ, "GIT_NO_LAZY_FETCH": "1"}
    done = subprocess.run(["git", "-C", str(repo_dir), "cat-file", "blob", listing[2]],
                          capture_output=True, env=env)
    if done.returncode != 0:
        raise BlobMissing(f"{path} at {commit[:10]} is not in the local clone; "
                          "run scripts/prepare_validation.py to prefetch")
    return done.stdout.decode("utf-8").replace("\r\n", "\n")


def _is_ancestor(repo_dir: Path, older: str, newer: str) -> bool:
    return subprocess.run(["git", "-C", str(repo_dir), "merge-base", "--is-ancestor", older, newer],
                          capture_output=True).returncode == 0


def approx_tokens(text: str) -> int:
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def build_event(spec_path: Path, repo_dir: Path, *, soft_limit: int = SOFT_LIMIT_BYTES,
                hard_limit: int = HARD_LIMIT_BYTES) -> dict[str, Any]:
    """Build the dossier next to ``spec_path`` and return event.json's content."""
    spec = load_spec(spec_path)
    out_dir = spec_path.parent
    requests = slice_requests(spec)
    commits = {"clean": spec["clean_commit"], "regressed": spec["regressed_commit"]}

    texts: dict[str, dict[str, str | None]] = {v: {} for v in VARIANTS}
    files: dict[str, dict[str, Any]] = {}
    scrubbed: dict[str, list[dict]] = {v: [] for v in VARIANTS}
    flagged: dict[str, list[dict]] = {v: [] for v in VARIANTS}
    for path, symbols in requests.items():
        files[path] = {}
        for variant in VARIANTS:
            original = read_at(repo_dir, commits[variant], path)
            if original is None:
                texts[variant][path] = None
                files[path][variant] = None
                continue
            trimmed = trim(original, symbols)
            cleaned = scrub(trimmed.text)
            texts[variant][path] = cleaned.text
            scrubbed[variant] += [{"path": path, **r} for r in cleaned.removed]
            flagged[variant] += [{"path": path, **r} for r in cleaned.flagged_strings]
            files[path][variant] = {
                "bytes": len(cleaned.text.encode("utf-8")),
                "lines": cleaned.text.count("\n"),
                "approx_tokens": approx_tokens(cleaned.text),
                "original_lines": original.count("\n"),
                "kept": trimmed.kept,
                "missing": trimmed.missing,
                "dropped_references": trimmed.dropped_references,
                "syntax_error": trimmed.syntax_error,
            }

    regression_files = sorted(p for p in requests if texts["clean"][p] != texts["regressed"][p])
    checks = _checks(spec, requests, files, regression_files, flagged, repo_dir,
                     soft_limit, hard_limit)
    try:
        scope = classify_scope(spec["flow"], regression_files)
    except SpecError as exc:
        scope = None
        checks.append({"name": "scope", "status": "fail", "detail": str(exc)})

    for variant in VARIANTS:
        target = out_dir / variant
        if target.exists():
            shutil.rmtree(target)
        for path, text in texts[variant].items():
            if text is not None:
                dest = target / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(text, encoding="utf-8", newline="\n")
    (out_dir / "regression.diff").write_text(_diff(texts, requests), encoding="utf-8", newline="\n")

    event = {
        "schema_version": SCHEMA_VERSION,
        **{k: v for k, v in spec.items()},
        "scope": scope,
        "flow_files": sorted(flow_files(spec["flow"])),
        "regression_files": regression_files,
        "files": files,
        "totals": {v: {"bytes": sum(f[v]["bytes"] for f in files.values() if f[v]),
                       "approx_tokens": sum(f[v]["approx_tokens"] for f in files.values() if f[v])}
                   for v in VARIANTS},
        "scrubbed": scrubbed,
        "flagged_strings": flagged,
        "checks": checks,
        "spec_sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(),
    }
    (out_dir / "event.json").write_text(
        json.dumps(event, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n")
    return event


def _checks(spec, requests, files, regression_files, flagged, repo_dir, soft_limit, hard_limit
            ) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []

    def add(name: str, ok: bool, detail: str, *, warn_only: bool = False) -> None:
        status = "ok" if ok else ("warn" if warn_only else "fail")
        checks.append({"name": name, "status": status, "detail": detail})

    add("commits", _is_ancestor(repo_dir, spec["regressed_commit"], spec["clean_commit"]),
        "regressed commit is an ancestor of the clean commit")

    missing = []
    for path, symbols in requests.items():
        for symbol in symbols:
            in_variants = [v for v in VARIANTS if files[path][v] and symbol not in files[path][v]["missing"]]
            if not in_variants:
                missing.append(f"{path}::{symbol}")
    add("symbols-found", not missing, "missing in both variants: " + ", ".join(missing) if missing
        else "every requested symbol exists in at least one variant")

    absent = []
    for role, need in (("entry", VARIANTS), ("sinks", VARIANTS), ("guards", ("clean",))):
        for loc in spec["flow"][role]:
            path, name = symbol_file(loc["symbol"]), symbol_name(loc["symbol"])
            for v in need:
                if not files[path][v] or name in files[path][v]["missing"]:
                    absent.append(f"{role} {loc['symbol']} in {v}")
    add("flow-present", not absent, "; ".join(absent) if absent
        else "entry and sinks exist in both variants, guards in the clean one")

    add("regression-nonempty", bool(regression_files),
        "files changed by the regression: " + (", ".join(regression_files) or "none"))

    errors = [f"{p} ({v}): {files[p][v]['syntax_error']}" for p in files for v in VARIANTS
              if files[p][v] and files[p][v]["syntax_error"]]
    add("parses", not errors, "; ".join(errors) if errors else "every slice file parses")

    total = sum(f["clean"]["bytes"] for f in files.values() if f["clean"])
    detail = f"clean slice is {total} bytes (soft limit {soft_limit}, hard limit {hard_limit})"
    if total > hard_limit:
        add("size", False, detail)
    else:
        add("size", total <= soft_limit, detail, warn_only=True)

    dropped = sorted({f"{p}::{d}" for p in files for v in VARIANTS if files[p][v]
                      for d in files[p][v]["dropped_references"]})
    add("dropped-references", not dropped,
        "referenced but cut: " + ", ".join(dropped) if dropped else "nothing referenced was cut",
        warn_only=True)

    strings = sorted({f"{s['path']}:{s['line']}" for v in VARIANTS for s in flagged[v]})
    add("flagged-strings", not strings,
        "string literals with security wording (kept, review them): " + ", ".join(strings)
        if strings else "no string literal uses security wording", warn_only=True)
    return checks


def _diff(texts: dict[str, dict[str, str | None]], requests: dict[str, list[str]]) -> str:
    out: list[str] = []
    for path in requests:
        before, after = texts["clean"][path], texts["regressed"][path]
        if before == after:
            continue
        out.extend(difflib.unified_diff(
            (before or "").splitlines(keepends=True), (after or "").splitlines(keepends=True),
            fromfile=f"a/{path}" if before is not None else "/dev/null",
            tofile=f"b/{path}" if after is not None else "/dev/null"))
    return "".join(out)
