"""Pack what a cloud notebook needs to record traces and run the gate conditions.

    python scripts/build_repo_snapshots.py
    python scripts/make_notebook_bundle.py

Writes runs/graphgate_bundle.zip: the package, the scripts, the dataset files
the tools read, and the repository snapshots Condition C's registered view
needs (data/interim/repo_snapshots, the seed repositories' Python files at
each event's fix commit; all of them under MIT, Apache-2.0 or BSD licences).
Upload it to the notebook (notebooks/record_traces_open_model.ipynb says
where), as a private input. Nothing secret goes in: no caches, no clones, no
tools environment. The Semgrep rule files stay out as well, because their
licence does not allow passing them on; the notebook fetches them itself.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCLUDE = ("pyproject.toml", "README.md", "src", "scripts", "data/events", "data/refinement_prompts.txt",
           "data/validation_signoff.json", "data/validation_ai_review.json",
           "requirements-analysers.txt", "data/semgrep_rules.json", "data/leakage_exclusions.json",
           "data/interim/repo_snapshots")
SKIP_PARTS = {"__pycache__"}


def files() -> list[Path]:
    found = []
    for entry in INCLUDE:
        path = ROOT / entry
        if not path.exists():
            raise SystemExit(f"missing {entry}" + (": run scripts/build_repo_snapshots.py first"
                                                   if entry.endswith("repo_snapshots") else ""))
        found.extend([path] if path.is_file() else
                     sorted(p for p in path.rglob("*") if p.is_file() and not SKIP_PARTS & set(p.parts)))
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "runs" / "graphgate_bundle.zip")
    args = parser.parse_args(argv)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in files():
            bundle.write(path, path.relative_to(ROOT).as_posix())
            count = len(bundle.namelist())
    print(f"wrote {args.out} ({count} files, {args.out.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
