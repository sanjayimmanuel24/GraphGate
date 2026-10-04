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

Expected: `242 passed`.

## 4. Replay a recorded LLM refinement run (no API key, no cost)

```powershell
graphgate-harness --replay docs/evidence/2026-09-27-smoke/smoke-05-opus48.jsonl --out runs/replay-demo.jsonl
```

This re-runs a three-turn, three-replication refinement session recorded against `claude-opus-4-8`,
without calling the model. To show it reproduces the original byte for byte, compare the hashes:

```powershell
Get-FileHash docs/evidence/2026-09-27-smoke/smoke-05-opus48.jsonl, runs/replay-demo.jsonl
```

Both lines show the same hash. Delete `runs/replay-demo.jsonl` before running step 4 again, because
the harness appends to an existing file.

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

Steps 5 and 7 use the repository clones in `data/interim/repos` and Microsoft Word respectively. Both are
already on this machine. On another machine, steps 3, 4 and 6 work straight from the project files.
