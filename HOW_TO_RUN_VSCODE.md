# Running GraphGate from VS Code

A walk-through for showing the project's outputs from Visual Studio Code on Windows. Every step
runs on this machine as it is: no model is called and no network is needed. All nine steps take
about six minutes. Each command was run on 2026-10-09 and the output shown is what it printed.

For everything else (recording traces, the notebook, paid runs) see `HOW_TO_RUN.md`.

## Before you start

1. **Open the project.** In VS Code: **File > Open Folder** and choose
   `C:\Users\Jeskookies\Downloads\GraphGate`.
2. **Pick the Python the project is installed in.** Press `Ctrl+Shift+P`, type
   **Python: Select Interpreter**, and choose **Python 3.12** (the one under
   `AppData\Local\Programs\Python\Python312`). This needs Microsoft's Python extension.
3. **Open a terminal.** Press `` Ctrl+` `` (or **Terminal > New Terminal**). It is PowerShell and
   starts in the project folder.
4. **Check the setup.** Both lines must work before anything else will:

```powershell
python --version
```

```powershell
python -c "import graphgate; print('graphgate is installed')"
```

The first prints `Python 3.12.10`. If the second fails, see "If something goes wrong" below.

### What has to be on this computer

These folders are not in git, so they exist only where they were built. Each is already here.

| Folder | What it holds | Steps that need it |
|---|---|---|
| `runs\pilot-traces\` | Three recorded runs of the open-weight model | 2, 3, 8 |
| `.venv-tools\` | Semgrep and Bandit | 4, 7, 8 |
| `data\raw\semgrep-rules-injection\` | The pinned Semgrep rules | 4, 7, 8 |
| `data\interim\clones\` | Checkouts of the seed repositories | 5 |
| `data\interim\repo_snapshots\` | Each event's repository at its fix commit | 6, 7, 8 |

## Two ways to run a step

- **Terminal:** copy the command into the terminal and press Enter.
- **Task menu:** **Terminal > Run Task...** and pick the step by name (`GraphGate 1: ...` to
  `GraphGate 9: ...`). The tasks are in `.vscode\tasks.json` and run the same commands.

## The demonstration

### 1. The code is tested (about a minute)

```powershell
python -m pytest -q
```

Ends with:

```
627 passed in 49.68s
```

To show the tests as a tree with green ticks instead, open the **Testing** panel (the flask icon
in the left bar) and press **Run Tests**.

### 2. A recorded run of the model replays byte for byte (a second)

`runs\pilot-traces\nicegui-hxp3.jsonl` is a real seven-turn session with the open-weight model.
Replaying it feeds the recorded replies back through the same code and must give the same file.

```powershell
Remove-Item runs/replay-demo.jsonl -ErrorAction SilentlyContinue
```

```powershell
python -m graphgate.cli --replay runs/pilot-traces/nicegui-hxp3.jsonl --out runs/replay-demo.jsonl
```

```powershell
Get-FileHash runs/pilot-traces/nicegui-hxp3.jsonl, runs/replay-demo.jsonl | Format-List Hash, Path
```

The last command prints the same hash twice:

```
Hash : 9EB6DA679066360C9FAC5162A9B2DEDA1DB8DDA99CD4161780ED3DECBF72973E
Path : ...\runs\pilot-traces\nicegui-hxp3.jsonl

Hash : 9EB6DA679066360C9FAC5162A9B2DEDA1DB8DDA99CD4161780ED3DECBF72973E
Path : ...\runs\replay-demo.jsonl
```

Which model produced the trace:

```powershell
Get-Content runs/pilot-traces/MODEL_USED.txt -TotalCount 8
```

### 3. Every turn of those runs is labelled (a second)

```powershell
python scripts/label_traces.py --traces-dir runs/pilot-traces
```

Ends with:

```
3 trace(s), 3 replication(s), 3 with the regression; turns by label: {'clean': 6, 'cross_file_regression': 10, 'local_regression': 5}
14 turn(s) carry the previous turn's label: the model rewrote the regression's code there, so the label was not read off the code (basis 'carried')
```

### 4. What the pattern scanners see of the 30 regressions (a few seconds)

Semgrep and Bandit on each validated regression, taken as one change.

```powershell
python scripts/scan_events.py
```

Ends with:

```
1 of 30 regression(s) introduce at least one family finding:
    command         cross_file  0 of 1
    os-command      cross_file  0 of 6
    path-traversal  cross_file  0 of 13
    path-traversal  local       0 of 5
    sql             cross_file  0 of 4
    sql             local       1 of 1
```

### 5. The graph builder on the 12 seed repositories (about a minute)

```powershell
python scripts/build_graph.py --check
```

Prints one line per repository and ends with:

```
12 repositories, 69722 calls, 24464 unknown (35.1%); wrote data/graph_build_check.json
```

"Unknown" are calls the builder could not resolve. They are kept in the graph and counted, never
dropped. This step rewrites `data\graph_build_check.json`; only its timing fields change.

### 6. What the graph rules see of the 30 regressions (two minutes)

Rules R1 to R4 on the same 30 changes: on the slice alone, and with the rest of the repository
around it.

```powershell
python scripts/delta_events.py
```

Prints one line per event and ends with:

```
graphgate                  flags  8 of 30 regressions (cross-file 5 of 24, local 3 of 6); flags 4 of the fixes
as-proposed                flags  7 of 30 regressions (cross-file 4 of 24, local 3 of 6); flags 0 of the fixes
repository view (graphgate): flags 11 of 30 regressions (cross-file 8 of 24, local 3 of 6); flags 5 of the fixes; ...
```

The figure to quote is the repository view, the registered one: **11 of 30, against 1 of 30 for
the scanners.** "Flags N of the fixes" is the control: the same rules on the reverse change.

### 7. One regression through the gate, stage by stage (a few seconds)

```powershell
python scripts/demo_gate.py nicegui-hxp3
```

It prints four parts:

1. the change as a diff (a path check is removed);
2. the scanners' verdict: `findings the change introduces: 0`, so Condition B allows it;
3. the graph rules: `flags: 1  rules: R3`, so Condition C blocks it without triage;
4. the item the triage model would be asked to judge, with the code of the function that opens
   the file, which is in another file than the change.

No model is called: part 4 is the question, not an answer. The same on the fix, as a control:

```powershell
python scripts/demo_gate.py nicegui-hxp3 --fix
```

Other events worth showing: `gitpython-2f96` (flagged only with the repository around it) and
`mako-2h4p` (not flagged: a check weakened inside one expression).

### 8. The conditions over the pilot traces (about 20 seconds)

A, B and both views of C over the three recorded runs, with triage switched off, so whatever is
flagged blocks. **This tests the tooling. Its figures are not results.**

```powershell
python scripts/run_conditions.py --traces runs/pilot-traces --no-triage --time-scans 0
```

Ends with:

```
A              blocks 0 of 3 regression(s) on arrival; 0 of 6 clean turn(s) blocked
B-untriaged    blocks 1 of 3 regression(s) on arrival; 0 of 6 clean turn(s) blocked
C-slice-untriaged blocks 2 of 3 regression(s) on arrival; 1 of 6 clean turn(s) blocked
C-untriaged    blocks 2 of 3 regression(s) on arrival; 1 of 6 clean turn(s) blocked
wrote runs/conditions-pilot/turns.csv, decisions.jsonl, summary.json, degradation.png
```

Open what it wrote inside VS Code:

```powershell
code runs/conditions-pilot/degradation.png
```

```powershell
code runs/conditions-pilot/turns.csv
```

### 9. The dashboard and the paper (a few seconds)

```powershell
python scripts/build_dashboard.py
```

```powershell
start dashboard\index.html
```

```powershell
start paper\output\GraphGate_paper.pdf
```

`start` opens the file in the browser and the PDF viewer. The paper is not rebuilt here, because
that needs Microsoft Word.

## Opening result files in VS Code

`code <path>` opens a file in the editor. The ones behind the figures above:

| File | What it is |
|---|---|
| `data\static_first_look.json` | Step 4, per event |
| `data\graph_build_check.json` | Step 5, per repository |
| `data\delta_first_look.json` | Step 6, per event, every setting |
| `runs\conditions-pilot\summary.json` | Step 8, every measure per condition |
| `runs\conditions-pilot\decisions.jsonl` | Step 8, each decision in full, one per line |
| `data\events\nicegui-hxp3\regression.diff` | The regression shown in step 7 |

## If something goes wrong

| What you see | What to do |
|---|---|
| `python` is not recognised, or the version is not 3.12 | Select the interpreter again (`Ctrl+Shift+P`, **Python: Select Interpreter**), then open a new terminal. |
| `No module named 'graphgate'` | Run `python -m pip install -e ".[dev]"` once in the project folder. |
| Step 2 says the output file already exists | Run the `Remove-Item` line first. A replay never writes into an existing file. |
| `semgrep was not found` in step 4, 7 or 8 | Run `python -m venv .venv-tools`, then `.venv-tools\Scripts\python -m pip install -r requirements-analysers.txt`. |
| The rule directory is missing or does not match | Run `python scripts/fetch_semgrep_rules.py`. It downloads about 11 MB once. |
| `no repository snapshot for ...` in step 6, 7 or 8 | Run `python scripts/build_repo_snapshots.py`. It reads `data\interim\repos\` and takes a few seconds. |
| No traces in `runs\pilot-traces\` | Unpack `graphgate_results.zip` from the notebook into the project folder. |
| A task from the menu fails but the command works in the terminal | The task used another Python. Select the interpreter, close all terminals and run the task again. |

## What these steps do not show

- A gate decision made with the model's triage. Steps 7 and 8 stop at the question.
- The full recording of the 30 events. It is in progress in the notebook; 13 of 30 are recorded.
- A live call to the model. It runs in the notebook, not on this laptop.
- The Pysa baseline, which needs Linux.
