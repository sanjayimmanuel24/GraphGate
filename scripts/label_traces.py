"""Label every turn of the recorded traces (BUILD_PLAN 2.5).

    python scripts/label_traces.py
    python scripts/label_traces.py --traces-dir runs/pilot-traces

Writes <event_id>.labels.json next to each <event_id>.jsonl. The labels are
read off the recorded code, so this makes no API call and can be rerun freely;
rerun it whenever a trace is recorded again.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from graphgate.dataset.labels import write_labels


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--traces-dir", type=Path, default=Path("data/traces"))
    parser.add_argument("--events-dir", type=Path, default=Path("data/events"))
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    traces = sorted(args.traces_dir.glob("*.jsonl"))
    if not traces:
        print(f"no trace in {args.traces_dir.as_posix()}; record some with scripts/synthesize_traces.py")
        return 1

    totals: dict[str, int] = {}
    carried = introduced = replications = 0
    for trace in traces:
        event = json.loads((args.events_dir / trace.stem / "event.json").read_text(encoding="utf-8"))
        labels = write_labels(trace, event["scope"])
        for label, count in labels["turns_by_label"].items():
            totals[label] = totals.get(label, 0) + count
        carried += labels["turns_carried"]
        replications += len(labels["replications"])
        introduced += sum(rep["introduced_at"] is not None for rep in labels["replications"])
        print(f"{trace.stem}: {labels['turns_by_label']}"
              + (f"; {labels['turns_carried']} carried" if labels["turns_carried"] else ""))

    print(f"\n{len(traces)} trace(s), {replications} replication(s), {introduced} with the regression; "
          f"turns by label: {dict(sorted(totals.items()))}")
    if carried:
        print(f"{carried} turn(s) carry the previous turn's label: the model rewrote the regression's "
              "code there, so the label was not read off the code (basis 'carried')")
    return 0


if __name__ == "__main__":
    sys.exit(main())
