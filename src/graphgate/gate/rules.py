"""The pinned Semgrep rule set for the injection family (BUILD_PLAN 3.1).

Condition B is meant to be a conventional, off-the-shelf check, so its rules
are not written here: they are the public community rules
(github.com/semgrep/semgrep-rules) at one fixed commit, cut down to the Python
rules that declare an injection-family CWE. Pinning the commit and hashing the
selection makes every scan repeatable and lets a run prove which rules it used.

The rules themselves are not kept in this repository (their licence restricts
redistribution). ``scripts/fetch_semgrep_rules.py`` downloads them into the
ignored ``data/raw`` directory; ``data/semgrep_rules.json`` records what was
selected, with a hash of every file.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from graphgate.gate.findings import FAMILY_CWES

REPO = "https://github.com/semgrep/semgrep-rules"
COMMIT = "a84ff9cc2453ca91d581380de4b8b3f272f6f4be"  # 2026-09-22
LANGUAGE_DIR = "python"

# Rules whose upstream metadata names another CWE although the rule is about
# this family. Both flag user input concatenated into an SQL string; upstream
# files them under CWE-704 and CWE-915. Leaving them out would weaken the
# conventional check, so they are counted as CWE-89 and listed in the manifest.
RECLASSIFIED = {
    "python/flask/security/injection/tainted-sql-string.yaml": 89,
    "python/django/security/injection/tainted-sql-string.yaml": 89,
}

MANIFEST_SCHEMA_VERSION = 1


class RuleSetError(RuntimeError):
    """The rule set is missing or is not the one the manifest describes."""


def declared_cwes(rule_text: str) -> tuple[int, ...]:
    """CWE ids a rule file declares in its ``metadata: cwe:`` entries.

    Read line by line instead of with a YAML parser, which this project does
    not otherwise need: the entry is either ``cwe: "CWE-78: ..."`` or a list
    of such strings on the lines below it. Mentions of a CWE anywhere else
    (messages, references) do not count.
    """
    found: set[int] = set()
    lines = rule_text.splitlines()
    for i, line in enumerate(lines):
        match = re.match(r"^(\s*)cwe:\s*(.*)$", line)
        if not match:
            continue
        values = [match.group(2)]
        for following in lines[i + 1:]:
            if not re.match(r"^\s*-\s", following):
                break
            values.append(following)
        for value in values:
            found.update(int(n) for n in re.findall(r"CWE-(\d+)", value))
    return tuple(sorted(found))


def _is_rule_file(path: Path) -> bool:
    return path.suffix in (".yaml", ".yml") and not path.name.endswith((".test.yaml", ".test.yml"))


def _normalised(path: Path) -> bytes:
    # Git may check the files out with CRLF on Windows; hash and copy them
    # with LF so the selection is the same on every machine.
    return path.read_bytes().replace(b"\r\n", b"\n")


def select(source_root: Path, cwes: Iterable[int] = FAMILY_CWES) -> list[dict[str, Any]]:
    """Rule files under ``source_root/python`` that belong to the family."""
    family = set(cwes)
    selected = []
    for path in sorted((source_root / LANGUAGE_DIR).rglob("*")):
        if not path.is_file() or not _is_rule_file(path):
            continue
        rel = path.relative_to(source_root).as_posix()
        data = _normalised(path)
        declared = declared_cwes(data.decode("utf-8"))
        counted = sorted(family & (set(declared) | ({RECLASSIFIED[rel]} if rel in RECLASSIFIED else set())))
        if counted:
            selected.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest(),
                             "declared_cwes": list(declared), "family_cwes": counted})
    return selected


def ruleset_sha256(files: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(files, key=lambda e: e["path"]):
        digest.update(f"{entry['path']}\0{entry['sha256']}\n".encode())
    return digest.hexdigest()


def build(source_root: Path, dest_root: Path, cwes: Iterable[int] = FAMILY_CWES) -> dict[str, Any]:
    """Copy the family's rules into ``dest_root`` and describe them."""
    family = sorted(set(cwes))
    selected = select(source_root, family)
    if not selected:
        raise RuleSetError(f"no rule under {source_root / LANGUAGE_DIR} declares CWE {family}")
    for stale in sorted(dest_root.rglob("*"), reverse=True) if dest_root.exists() else []:
        if stale.is_file() and _is_rule_file(stale):
            stale.unlink()  # a rule dropped from the selection must not linger
    for entry in selected:
        target = dest_root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_normalised(source_root / entry["path"]))
    by_cwe = {str(c): sum(c in e["family_cwes"] for e in selected) for c in family}
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "source": REPO,
        "commit": COMMIT,
        "licence": "Semgrep Rules License v1.0 (https://semgrep.dev/legal/rules-license); "
                   "the rule files are not redistributed in this repository",
        "language_dir": LANGUAGE_DIR,
        "family_cwes": family,
        "rule_files": len(selected),
        "rule_files_by_cwe": by_cwe,
        "reclassified": {path: {"counted_as": cwe,
                                "reason": "flags user input concatenated into an SQL string; "
                                          "upstream metadata names another CWE"}
                         for path, cwe in sorted(RECLASSIFIED.items())},
        "ruleset_sha256": ruleset_sha256(selected),
        "rules": selected,
    }


@dataclass(frozen=True)
class RuleSet:
    """A verified rule directory, ready to hand to Semgrep."""

    root: Path                         # Semgrep runs here with --config python
    sha256: str
    commit: str
    reclassified: dict[str, int]       # Semgrep check id -> CWE it is counted as

    @property
    def config(self) -> str:
        return LANGUAGE_DIR


def check_id(rule_path: str) -> str:
    """The id Semgrep reports for the rule in ``rule_path`` (id = file name)."""
    return rule_path.rsplit(".", 1)[0].replace("/", ".")


def load_ruleset(manifest_path: Path, rules_root: Path) -> RuleSet:
    """The rule set on disk, after checking it is the one the manifest pins."""
    if not manifest_path.exists():
        raise RuleSetError(f"{manifest_path} is missing; run scripts/fetch_semgrep_rules.py")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    on_disk = []
    for path in sorted(rules_root.rglob("*")) if rules_root.exists() else []:
        if path.is_file() and _is_rule_file(path):
            on_disk.append({"path": path.relative_to(rules_root).as_posix(),
                            "sha256": hashlib.sha256(_normalised(path)).hexdigest()})
    if ruleset_sha256(on_disk) != manifest["ruleset_sha256"]:
        raise RuleSetError(
            f"the rules in {rules_root} are not the set pinned in {manifest_path.name} "
            f"({len(on_disk)} file(s) found, {manifest['rule_files']} expected); "
            "run scripts/fetch_semgrep_rules.py")
    return RuleSet(root=rules_root, sha256=manifest["ruleset_sha256"], commit=manifest["commit"],
                   reclassified={check_id(path): entry["counted_as"]
                                 for path, entry in manifest["reclassified"].items()})


def fetch(source_root: Path, commit: str = COMMIT) -> bool:
    """Make ``source_root`` a checkout of the rules at ``commit``.

    Returns True if anything was downloaded. A checkout already at the commit
    is left alone, so a second run needs no network.
    """
    def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(source_root), *args], capture_output=True,
                              text=True, check=check)

    if (source_root / ".git").exists():
        if git("rev-parse", "HEAD", check=False).stdout.strip() == commit:
            return False
        git("fetch", "--quiet", "--filter=blob:none", "origin", commit)
    else:
        source_root.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout",
                        REPO, str(source_root)], check=True, capture_output=True, text=True)
        git("sparse-checkout", "set", LANGUAGE_DIR)
    git("-c", "advice.detachedHead=false", "checkout", "--quiet", commit)
    return True
