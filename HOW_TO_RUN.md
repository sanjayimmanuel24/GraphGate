# Showing GraphGate's output (VS Code, Windows)

Open the project folder in VS Code, then open a terminal with **Terminal > New Terminal**. It is
PowerShell. Run the commands below one at a time from the project root.

## 1. Go to the project and check Python

```powershell
cd C:\Users\Jeskookies\Downloads\GraphGate
```

```powershell
python --version
```

It should print Python 3.12.x.

## 2. (First time on a new machine only) install the project

```powershell
python -m pip install -e ".[dev]"
```

## 3. Run the test suite

```powershell
python -m pytest -q
```

Expected: every test passes (`400 passed` as of 2026-10-06).

## 4. Replay a recorded LLM refinement run (no API key, no cost)

First remove the output of any earlier replay. The harness refuses to replay into a file that already
exists, because appending to it would give a file that cannot match the original:

```powershell
Remove-Item runs/replay-demo.jsonl -ErrorAction SilentlyContinue
```

```powershell
graphgate-harness --replay docs/evidence/2026-09-27-smoke/smoke-05-opus48.jsonl --out runs/replay-demo.jsonl
```

This re-runs a three-turn, three-replication refinement session recorded against `claude-opus-4-8`,
without calling the model. To show it reproduces the original byte for byte, compare the hashes:

```powershell
Get-FileHash docs/evidence/2026-09-27-smoke/smoke-05-opus48.jsonl, runs/replay-demo.jsonl | Format-List Hash, Path
```

Both entries show the same hash.

## 5. Show a regression event from the dataset

```powershell
python scripts/build_event.py data/events/gitpython-2f96/spec.json
```

```powershell
Get-Content data/events/gitpython-2f96/regression.diff
```

The diff is the regression: the lines of a real security fix (GitPython, GHSA-2f96) being removed.

To rebuild every event dossier:

```powershell
python scripts/build_event.py --all
```

## 6. Open the project dashboard

```powershell
python scripts/build_dashboard.py --run-tests
```

```powershell
start dashboard\index.html
```

## 7. Rebuild and open the paper

```powershell
python paper/build.py
```

```powershell
start paper\output\GraphGate_paper.pdf
```

## 8. Optional: a live run against the model (paid)

This makes real, billed API calls. Set your API key in your own terminal first. Never paste it into a file
or a chat.

```powershell
graphgate-harness --snapshot examples/smoke --prompts examples/smoke_prompts.txt --out runs/live-demo.jsonl --trace-id live-demo --seeds 0 --model claude-opus-4-8 --cache runs/cache.sqlite
```

## 9. Refinement traces for the regression events (step 2.4)

See the plan and a rough cost. This sends nothing and needs no key:

```powershell
python scripts/synthesize_traces.py --dry-run --pilot
```

A small paid pilot on three events, one replication each: 21 calls, roughly $2–3 on Opus 4.8. Set your
API key in your own terminal first. Never paste it into a file or a chat.

```powershell
python scripts/synthesize_traces.py --pilot --seeds 0 --max-calls 25 lollms-m45c nicegui-hxp3 mako-2h4p
```

What was recorded, per replication, is in `runs/pilot-traces/manifest.json`.

Check that a recorded trace replays byte-for-byte:

```powershell
Remove-Item runs/pilot-replay.jsonl -ErrorAction SilentlyContinue
```

```powershell
graphgate-harness --replay runs/pilot-traces/lollms-m45c.jsonl --out runs/pilot-replay.jsonl
```

```powershell
fc.exe /b runs\pilot-traces\lollms-m45c.jsonl runs\pilot-replay.jsonl
```

Label every turn of the recorded traces (step 2.5). This reads the traces and makes no API call:

```powershell
python scripts/label_traces.py --traces-dir runs/pilot-traces
```

It writes `<event>.labels.json` next to each trace and prints how many turns are clean, how many hold the
regression, and how many were `carried` because the model rewrote the regression's code.

The dataset run (no `--pilot`) records only the 30 events accepted at sign-off and writes to
`data/traces/`. It is the large paid step: about 603 calls, roughly $74-126 on Opus 4.8 at three
replications. Check the plan first, then run it, then label it:

```powershell
python scripts/synthesize_traces.py --dry-run
```

```powershell
python scripts/synthesize_traces.py
```

```powershell
python scripts/label_traces.py
```

Responses are cached in `runs/cache.sqlite`, so the pilot's calls are not paid for again and an
interrupted run continues where it stopped.

## 9a. The same run with an open-weight model, in a free cloud notebook

The guide asked for no commercial model. This laptop cannot run an open model of useful size, so
the run happens in a Kaggle (or Colab) GPU notebook. Pack what the notebook needs:

```powershell
python scripts/make_notebook_bundle.py
```

Then, in Kaggle: create a notebook from `notebooks/record_traces_open_model.ipynb` (File > Import
notebook), set Accelerator to GPU T4 x2 and Internet to On, add `runs/graphgate_bundle.zip` with
Add input > Upload, and run the cells from the top. It installs the model server, downloads the
model, runs the three-event pilot and saves `graphgate_results.zip` for you to download. No API
key is involved and nothing is billed.

## 10. Sign-off and leakage control (steps 2.3 and 2.6)

Both read local files only and cost nothing. The first rewrites `data/validation_signoff.json`
from the decisions exported from the sign-off page and prints the tally; the second rebuilds the
list of repository code that the graph's retrieval must not see:

```powershell
python scripts/save_signoff.py data/interim/signoff_export/decisions
```

```powershell
python scripts/check_leakage.py
```

## 11. Semgrep and Bandit on the regression events (step 3.1)

The two analysers live in their own environment so that their packages do not mix with the
project's. On this machine it is already set up; on a new one, create it and fetch the pinned rule
set once (about 70 MB and 11 MB of downloads):

```powershell
python -m venv .venv-tools
```

```powershell
.venv-tools\Scripts\python -m pip install -r requirements-analysers.txt
```

```powershell
python scripts/fetch_semgrep_rules.py
```

Then scan every validated event's regression. It needs no network or API key, and takes about 20
seconds the first time and almost none afterwards, because results are kept in
`runs/analysis-cache.sqlite`:

```powershell
python scripts/scan_events.py
```

For each event it prints the injection findings the regression introduces (`+`) and removes
(`-`). Only one of the 30 introduces any: the pattern scanners report the same lines before and
after, which is the gap the graph-based gate is meant to close.

## 12. The diff-only gates on the regression events (step 3.2)

Two gates read each change from its diff: B, where the LLM triages what the scanners flag, and
B+, where it also judges the change as a whole. See what would be sent, and the exact request for
one event, without sending anything:

```powershell
python scripts/triage_events.py --dry-run
```

```powershell
python scripts/triage_events.py --show-prompt lollms-m45c
```

The paid pilot judges every event's regression and, as a control, its fix: 62 calls, roughly $1-3
on Opus 4.8. Set your API key in your own terminal first. Never paste it into a file or a chat.

```powershell
python scripts/triage_events.py --max-calls 70
```

It prints how many regressions and how many fixes each gate blocked, and writes every decision
with its rationale to `runs/triage-pilot/decisions.jsonl`. A good gate blocks the regressions and
lets the fixes through. This is a pilot of the triage step, not the study's result.

Steps 5 and 7 use the repository clones in `data/interim/repos` and Microsoft Word respectively. Both are
already on this machine. On another machine, steps 3, 4 and 6 work straight from the project files.

## 13. The conditions over recorded traces (step 3.4)

Traces must be labelled first (`python scripts/label_traces.py`, see section 9).

Without a model, on the pilot traces (about four minutes: each turn's scan is timed on its own):

```powershell
python scripts/run_conditions.py --traces runs/pilot-traces --no-triage
```

This runs A, B and C with triage switched off, so whatever is flagged blocks. It writes
`turns.csv`, `decisions.jsonl`, `summary.json` and `degradation.png` to `runs/conditions-pilot/`.
Add `--time-scans 0` to skip the timing and finish in seconds.

With triage, where the model server runs (the notebook):

```bash
python scripts/run_conditions.py --provider openai-compatible --base-url http://localhost:11434/v1 --model qwen2.5-coder-14b-ctx32768
```

Dataset traces (`data/traces/`) give `data/results/`. Pilot figures are a test of the tools and
are never quoted as results.
