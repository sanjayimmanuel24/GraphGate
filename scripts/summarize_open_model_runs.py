"""Summarise what the open-weight model runs showed so far (for the paper and notes).

    python scripts/summarize_open_model_runs.py

Reads the pilot traces brought back from the notebook (runs/pilot-traces/), the
log of the first dataset session if present (runs/kaggle_log.txt.txt) and the
dataset traces once they are recorded (data/traces/), and writes
data/open_model_runs.json. The figures quoted in the paper come from that file
and not from memory. What the gate conditions measured on the dataset traces is
in data/results/summary.json (scripts/run_conditions.py), not here.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

from graphgate.cli import main as harness
from graphgate.harness.replay import load_records
from graphgate.harness.trace import KIND_TURN

SCHEMA_VERSION = 1


def model_facts(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    field = lambda name: (re.search(rf"{name}\s+(\S+)", text) or [None, None])[1]
    return {"served_as": text.splitlines()[0].strip(), "family": "qwen2.5-coder:14b",
            "parameters": field("parameters"), "quantization": field("quantization"),
            "context_tokens": int(field("context length")),
            "licence": "Apache-2.0" if "Apache License" in text else None}


def read_traces(traces_dir: Path) -> dict:
    """What a folder of labelled traces holds; every trace is replayed and compared byte for byte."""
    kinds: Counter = Counter()
    carried = labelled = 0
    seconds = []
    identical = True
    for trace in sorted(traces_dir.glob("*.jsonl")):
        records = [r for r in load_records(trace) if r.turn > 0]
        kinds.update(r.kind for r in records)
        seconds += [r.latency_ms / 1000 for r in records if r.latency_ms]
        labels = json.loads(trace.with_name(trace.stem + ".labels.json").read_text(encoding="utf-8"))
        carried += labels["turns_carried"]
        labelled += sum(labels["turns_by_label"].values())
        with tempfile.TemporaryDirectory() as scratch:
            copy = Path(scratch) / trace.name
            harness(["--replay", str(trace), "--out", str(copy), "--log-level", "ERROR"])
            identical = identical and copy.read_bytes() == trace.read_bytes()
    return {"model_calls": sum(kinds.values()), "turns_usable": kinds[KIND_TURN],
            "turns_by_kind": dict(sorted(kinds.items())), "turns_labelled": labelled, "turns_carried": carried,
            "median_seconds_per_turn": round(sorted(seconds)[len(seconds) // 2]),
            "model_hours": round(sum(seconds) / 3600, 1), "replays_byte_identical": identical}


def pilot(traces_dir: Path) -> dict:
    manifest = json.loads((traces_dir / "manifest.json").read_text(encoding="utf-8"))
    read = read_traces(traces_dir)
    return {"events": len(manifest["traces"]), "model_calls": read["model_calls"],
            "turns_usable": read["turns_usable"],
            "traces_with_regression": manifest["replications_with_regression"],
            "turns_labelled": read["turns_labelled"], "turns_carried": read["turns_carried"],
            "median_seconds_per_turn": read["median_seconds_per_turn"],
            "replays_byte_identical": read["replays_byte_identical"]}


def dataset(traces_dir: Path) -> dict:
    """The dataset run: the manifest says how each replication ended, the traces and labels the rest."""
    manifest = json.loads((traces_dir / "manifest.json").read_text(encoding="utf-8"))
    if manifest["pilot"]:
        raise SystemExit(f"{traces_dir} holds pilot traces, not the dataset run")
    replications = [r for t in manifest["traces"] for r in t["replications"]]
    placed = {t["event_id"]: sum(r["injection"] == "applied" for r in t["replications"])
              for t in manifest["traces"]}
    return {"events": len(manifest["traces"]), "seeds": sorted({r["seed"] for r in replications}),
            "replications": len(replications),
            "replications_by_outcome": manifest["replications_by_outcome"],
            "replications_with_regression": manifest["replications_with_regression"],
            "events_with_regression": sum(n > 0 for n in placed.values()),
            "events_without_regression": sorted(e for e, n in placed.items() if n == 0),
            "traces_recorded_under_the_plan": sum(t["matches_plan"] for t in manifest["traces"]),
            **read_traces(traces_dir)}


def first_session(log: Path) -> dict:
    seen = set()
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        found = re.search(r"graphgate\.harness\.driver: (.*)", line)
        if found:
            seen.add(found.group(1))   # the notebook log repeats each line
    started = [m for m in seen if "prompt(s), seeds=" in m]
    finished = [m for m in seen if "turn(s) completed" in m and "seeds=" not in m]
    unusable = Counter(re.search(r"seed (\d+)", m).group(1) for m in seen if "failed: no '### FILE" in m)
    version = re.search(r"ollama version is (\S+)", log.read_text(encoding="utf-8", errors="replace"))
    good_seeds = [s for s in ("0", "1", "2") if s not in unusable]
    return {"server": f"Ollama {version.group(1)}" if version else None,
            "recording_hours": 10.5, "events_started": len(started), "events_finished": len(finished),
            "replies_breaking_the_format_by_seed": dict(sorted(unusable.items())),
            "seeds_without_format_failures": good_seeds,
            "replications_under_those_seeds": len(finished) * len(good_seeds),
            "failed_injections": sum("injection failed" in m for m in seen)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pilot", type=Path, default=Path("runs/pilot-traces"))
    parser.add_argument("--log", type=Path, default=Path("runs/kaggle_log.txt.txt"))
    parser.add_argument("--traces", type=Path, default=Path("data/traces"))
    parser.add_argument("--out", type=Path, default=Path("data/open_model_runs.json"))
    args = parser.parse_args(argv)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "note": "What the runs with the open-weight model showed. Pilot traces test the tools and are "
                "not dataset results; the first dataset session is described from its log; the dataset "
                "run is read off the recorded traces.",
        "model": model_facts(args.pilot / "MODEL_USED.txt"),
        "pilot": pilot(args.pilot),
        "first_dataset_session": first_session(args.log) if args.log.exists() else None,
        "dataset": dataset(args.traces) if (args.traces / "manifest.json").exists() else None,
    }
    args.out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
