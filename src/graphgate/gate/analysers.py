"""Running Semgrep and Bandit over file versions (BUILD_PLAN 3.1).

Both tools analyse one file at a time, so the unit of work here is a *file
version*: a path with one particular text. A change is scanned by scanning the
versions of its files before and after it and comparing the findings
(``graphgate.gate.findings``).

Three things shape the code:

- Semgrep takes around ten seconds to start, however little it scans, so many
  versions go into one run and results are remembered by content. A version
  that was scanned once is never scanned again, in this run or (with a cache
  file) in a later one.
- Nothing is skipped quietly. Semgrep's default ignore list leaves out
  ``tests/`` directories; that is switched off, and a file either tool did not
  analyse is an error. A file that does not parse is reported with the tool's
  message, since the model can write such a file.
- The tools run offline. Semgrep's metrics and version check are off, the
  rules are local, and its settings and log go to the scan's own temporary
  directory instead of the user's home.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping

from graphgate.gate.findings import (
    FAMILY_CWES,
    ChangeFindings,
    Finding,
    cwe_numbers,
    in_family,
    lines_of,
)
from graphgate.gate.rules import RuleSet

TOOLS_DIR = ".venv-tools"
RUN_TIMEOUT_SECONDS = 3600

_SEMGREP_SEVERITY = {"CRITICAL": "high", "ERROR": "high", "HIGH": "high", "WARNING": "medium",
                     "MEDIUM": "medium", "INFO": "low", "LOW": "low"}

# (arguments, working directory, environment) -> (exit code, stdout, stderr)
Run = Callable[[list[str], Path | None, dict[str, str]], tuple[int, str, str]]


class AnalyserError(RuntimeError):
    """A tool is missing, failed, or did not analyse what it was given."""


def _run(args: list[str], cwd: Path | None, env: dict[str, str]) -> tuple[int, str, str]:
    try:
        done = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=RUN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise AnalyserError(f"{Path(args[0]).name} did not finish in {RUN_TIMEOUT_SECONDS} s") from exc
    return done.returncode, done.stdout, done.stderr


@dataclass(frozen=True)
class Tools:
    semgrep: Path
    bandit: Path

    @classmethod
    def locate(cls, project_root: Path = Path(".")) -> Tools:
        """The analysers, from the project's tools environment or the PATH."""
        folders = [project_root / TOOLS_DIR / ("Scripts" if os.name == "nt" else "bin")]
        if os.environ.get("GRAPHGATE_TOOLS"):
            folders.insert(0, Path(os.environ["GRAPHGATE_TOOLS"]))
        found = {}
        for name in ("semgrep", "bandit"):
            path = next((p for folder in folders
                         for p in (folder / name, folder / f"{name}.exe") if p.is_file()), None)
            path = path or (Path(w) if (w := shutil.which(name)) else None)
            if path is None:
                raise AnalyserError(
                    f"{name} was not found in {folders[-1]} or on the PATH. Install the analysers with:\n"
                    f"  python -m venv {TOOLS_DIR}\n"
                    f"  {folders[-1] / 'python'} -m pip install -r requirements-analysers.txt")
            found[name] = path.resolve()
        return cls(**found)


@dataclass(frozen=True)
class FileScan:
    """What the tools say about one file version."""

    findings: tuple[Finding, ...]
    errors: tuple[str, ...]      # "tool: message" for a file a tool could not fully analyse

    def to_json(self) -> str:
        return json.dumps({"findings": [f.to_dict() for f in self.findings], "errors": list(self.errors)},
                          sort_keys=True, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> FileScan:
        data = json.loads(text)
        return cls(tuple(Finding.from_dict(f) for f in data["findings"]), tuple(data["errors"]))


@dataclass(frozen=True)
class ChangeScan:
    findings: ChangeFindings
    errors: tuple[str, ...]      # "before|after path: tool: message"


class FindingCache:
    """Scan results kept on disk by tool configuration and file content."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.execute("CREATE TABLE IF NOT EXISTS scans (config TEXT NOT NULL, path TEXT NOT NULL, "
                           "sha256 TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY (config, path, sha256))")
        self._conn.commit()

    def __enter__(self) -> FindingCache:
        return self

    def __exit__(self, *exc: object) -> None:
        self._conn.close()

    def get(self, config: str, path: str, sha256: str) -> FileScan | None:
        row = self._conn.execute("SELECT result FROM scans WHERE config = ? AND path = ? AND sha256 = ?",
                                 (config, path, sha256)).fetchone()
        return None if row is None else FileScan.from_json(row[0])

    def put(self, config: str, path: str, sha256: str, scan: FileScan) -> None:
        self._conn.execute("INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?)",
                           (config, path, sha256, scan.to_json()))
        self._conn.commit()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _relative(reported: str, root: Path) -> str:
    """A path a tool reported, relative to the directory it was asked to scan."""
    path = Path(reported)
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        # The tool spelled the directory differently (a short 8.3 name, mixed
        # separators); compare the resolved locations instead.
        return Path(os.path.realpath(path)).relative_to(os.path.realpath(root)).as_posix()


def parse_semgrep(output: dict[str, Any], root: Path, texts: Mapping[str, str],
                  reclassified: Mapping[str, int]) -> tuple[dict[str, list[Finding]], dict[str, list[str]]]:
    """Findings and per-file errors from ``semgrep scan --json``, keyed by path under ``root``."""
    scanned = {_relative(p, root) for p in output["paths"]["scanned"]}
    missing = sorted(set(texts) - scanned)
    if missing:
        raise AnalyserError(f"semgrep did not scan {len(missing)} file(s) it was given: {', '.join(missing[:5])}")
    findings: dict[str, list[Finding]] = {}
    for result in output["results"]:
        path = _relative(result["path"], root)
        extra = result["extra"]
        metadata = extra.get("metadata") or {}
        cwes = set(cwe_numbers(metadata.get("cwe")))
        if result["check_id"] in reclassified:
            cwes.add(reclassified[result["check_id"]])
        start, end = result["start"]["line"], result["end"]["line"]
        confidence = metadata.get("confidence")
        findings.setdefault(path, []).append(Finding(
            tool="semgrep", rule_id=result["check_id"], cwes=tuple(sorted(cwes)),
            severity=_SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), "medium"),
            confidence=confidence.lower() if isinstance(confidence, str) else None,
            path=path.split("/", 1)[1], start_line=start, end_line=end,
            message=" ".join(str(extra.get("message", "")).split()),
            # Semgrep's own copy of the lines needs a login; take them from the file.
            code=lines_of(texts[path], start, end)))
    errors: dict[str, list[str]] = {}
    for error in output.get("errors", []):
        if not error.get("path"):
            raise AnalyserError(f"semgrep: {str(error.get('message', error))[:300]}")
        kind = error.get("type")
        kind = kind[0] if isinstance(kind, list) else kind
        errors.setdefault(_relative(error["path"], root), []).append(f"semgrep: {kind}")
    return findings, errors


def parse_bandit(output: dict[str, Any], root: Path, texts: Mapping[str, str]
                 ) -> tuple[dict[str, list[Finding]], dict[str, list[str]]]:
    """Findings and per-file errors from ``bandit -f json``, keyed by path under ``root``."""
    analysed = {_relative(name, root) for name in output["metrics"] if name != "_totals"}
    missing = sorted(set(texts) - analysed)
    if missing:
        raise AnalyserError(f"bandit did not analyse {len(missing)} file(s) it was given: {', '.join(missing[:5])}")
    findings: dict[str, list[Finding]] = {}
    for result in output["results"]:
        path = _relative(result["filename"], root)
        lines = result.get("line_range") or [result["line_number"]]
        findings.setdefault(path, []).append(Finding(
            tool="bandit", rule_id=result["test_id"], cwes=cwe_numbers((result.get("issue_cwe") or {}).get("id")),
            severity=result["issue_severity"].lower(), confidence=result["issue_confidence"].lower(),
            path=path.split("/", 1)[1], start_line=min(lines), end_line=max(lines),
            message=f"{result['test_name']}: {' '.join(result['issue_text'].split())}",
            code=lines_of(texts[path], min(lines), max(lines))))
    errors: dict[str, list[str]] = {}
    for error in output.get("errors", []):
        errors.setdefault(_relative(error["filename"], root), []).append(f"bandit: {error['reason']}")
    return findings, errors


class StaticScanner:
    """Semgrep and Bandit findings for file versions, limited to one CWE family."""

    def __init__(self, tools: Tools, ruleset: RuleSet, *, cwes: Iterable[int] = FAMILY_CWES,
                 cache: FindingCache | None = None, run: Run = _run):
        self.tools = tools
        self.ruleset = ruleset
        self.cwes = frozenset(cwes)
        self._cache = cache
        self._run = run
        self._memo: dict[tuple[str, str], FileScan] = {}
        self._versions: dict[str, str] | None = None
        self.runs = 0  # tool invocations made, for reporting

    def versions(self) -> dict[str, str]:
        """The tools' versions, asked once: results are only comparable within one pair."""
        if self._versions is None:
            with tempfile.TemporaryDirectory(prefix="graphgate-scan-") as scratch:
                env = self._env(Path(scratch))
                semgrep = self._run([str(self.tools.semgrep), "--version"], None, env)[1].strip().splitlines()
                bandit = self._run([str(self.tools.bandit), "--version"], None, env)[1].strip().splitlines()
            if not semgrep or not bandit:
                raise AnalyserError("could not read the analysers' versions")
            self._versions = {"semgrep": semgrep[-1].strip(), "bandit": bandit[0].replace("bandit", "").strip()}
        return self._versions

    @property
    def config(self) -> str:
        """Everything a result depends on besides the file: the cache key and the provenance."""
        v = self.versions()
        return (f"semgrep={v['semgrep']};bandit={v['bandit']};rules={self.ruleset.sha256};"
                f"cwes={','.join(str(c) for c in sorted(self.cwes))}")

    def scan(self, versions: Iterable[tuple[str, str]]) -> dict[tuple[str, str], FileScan]:
        """Scan file versions, given as ``(path, text)``; one tool run covers all that are new."""
        wanted = list(dict.fromkeys(versions))
        todo = []
        for path, text in wanted:
            key = (path, _sha256(text))
            if key in self._memo:
                continue
            cached = self._cache.get(self.config, *key) if self._cache else None
            if cached is not None:
                self._memo[key] = cached
            elif ".." in PurePosixPath(path).parts or PurePosixPath(path).is_absolute():
                self._memo[key] = FileScan((), ("scanner: path leaves the snapshot; not analysed",))
            elif not text.strip():
                self._memo[key] = FileScan((), ())  # nothing to analyse in an empty file
            else:
                todo.append((path, text))
        if todo:
            for (path, text), scan in zip(todo, self._analyse(todo)):
                key = (path, _sha256(text))
                self._memo[key] = scan
                if self._cache:
                    self._cache.put(self.config, *key, scan)
        return {(path, text): self._memo[(path, _sha256(text))] for path, text in wanted}

    def scan_files(self, files: Mapping[str, str]) -> dict[str, FileScan]:
        return {path: scan for (path, _), scan in self.scan(files.items()).items()}

    def scan_change(self, before: Mapping[str, str], after: Mapping[str, str],
                    changed_paths: Iterable[str]) -> ChangeScan:
        """Findings on the files a change touched, before and after it.

        Only the changed files are scanned: both tools work within one file,
        so a finding in an untouched file cannot be the change's doing.
        """
        changed = sorted(set(changed_paths))
        sides = {"before": [(p, before[p]) for p in changed if p in before],
                 "after": [(p, after[p]) for p in changed if p in after]}
        scans = self.scan(sides["before"] + sides["after"])
        found = {side: tuple(f for version in versions for f in scans[version].findings)
                 for side, versions in sides.items()}
        errors = tuple(f"{side} {version[0]}: {message}" for side, versions in sides.items()
                       for version in versions for message in scans[version].errors)
        return ChangeScan(ChangeFindings(before=found["before"], after=found["after"]), errors)

    # -- running the tools ------------------------------------------------------

    def _env(self, scratch: Path) -> dict[str, str]:
        return {**os.environ,
                "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
                "SEMGREP_SETTINGS_FILE": str(scratch / "semgrep-settings.yml"),
                "SEMGREP_LOG_FILE": str(scratch / "semgrep.log"),
                "SEMGREP_VERSION_CACHE_PATH": str(scratch / "semgrep-version"),
                "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}

    def _analyse(self, versions: list[tuple[str, str]]) -> list[FileScan]:
        with tempfile.TemporaryDirectory(prefix="graphgate-scan-") as scratch:
            scratch_dir = Path(scratch)
            root = scratch_dir / "files"
            texts = {}
            for index, (path, text) in enumerate(versions):
                # Each version in its own numbered folder: two versions of one
                # path can then sit in the same run.
                target = root / str(index) / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8", newline="")
                texts[f"{index}/{path}"] = text
            # An ignore file of our own replaces Semgrep's default one, which
            # would leave out anything under a tests/ or build/ directory.
            (root / ".semgrepignore").write_text("# nothing is ignored\n", encoding="utf-8")
            env = self._env(scratch_dir)
            semgrep, semgrep_errors = parse_semgrep(self._semgrep(root, env), root, texts,
                                                    self.ruleset.reclassified)
            bandit, bandit_errors = parse_bandit(self._bandit(root, env), root, texts)
        scans = []
        for key in texts:
            found = [f for f in semgrep.get(key, []) + bandit.get(key, []) if in_family(f, self.cwes)]
            found.sort(key=lambda f: (f.start_line, f.end_line, f.tool, f.rule_id))
            scans.append(FileScan(tuple(found), tuple(semgrep_errors.get(key, []) + bandit_errors.get(key, []))))
        return scans

    def _json(self, tool: str, args: list[str], cwd: Path | None, env: dict[str, str],
              ok: tuple[int, ...]) -> dict[str, Any]:
        self.runs += 1
        code, out, err = self._run(args, cwd, env)
        try:
            if code not in ok:
                raise ValueError(f"exit code {code}")
            return json.loads(out)
        except ValueError as exc:
            raise AnalyserError(f"{tool} failed ({exc}): {(err or out).strip()[-400:]}") from exc

    def _semgrep(self, root: Path, env: dict[str, str]) -> dict[str, Any]:
        # Run from the rule directory with a relative --config, so rule ids
        # read "python.lang.security..." wherever the project lives.
        return self._json("semgrep", [str(self.tools.semgrep), "scan", "--config", self.ruleset.config,
                                      "--json", "--metrics=off", "--disable-version-check", "--quiet",
                                      "--no-git-ignore", str(root)], self.ruleset.root, env, ok=(0,))

    def _bandit(self, root: Path, env: dict[str, str]) -> dict[str, Any]:
        # Exit code 1 only means that issues were found.
        return self._json("bandit", [str(self.tools.bandit), "-r", str(root), "-f", "json", "-q"],
                          None, env, ok=(0, 1))


def default_scanner(project_root: Path = Path("."), *, cache: FindingCache | None = None,
                    cwes: Iterable[int] = FAMILY_CWES) -> StaticScanner:
    """The scanner as the project configures it: tools environment and pinned rules."""
    from graphgate.gate.rules import load_ruleset

    ruleset = load_ruleset(project_root / "data" / "semgrep_rules.json",
                           project_root / "data" / "raw" / "semgrep-rules-injection")
    return StaticScanner(Tools.locate(project_root), ruleset, cwes=cwes, cache=cache)

