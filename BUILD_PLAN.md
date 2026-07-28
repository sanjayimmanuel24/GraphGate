# GraphGate — Build Plan for Claude Code

Work through this **one numbered step at a time**. Do not ask Claude Code to "build M1" in one
shot — hand it one step, review the diff/output, run the tests, then move to the next. This is
what keeps a solo capstone from turning into an unreviewable pile of generated code.

Each step below is written the way you'd paste it (or paraphrase it) as a prompt to Claude Code
in this repo, once `CLAUDE.md` is in place.

---

## Phase M1.1 — Refinement harness + trace replay (Weeks 1–3)

**1.1** Scaffold the repo: `pyproject.toml`, `src/graphgate/`, `tests/`, `docs/` (drop the
proposal docx/pdf in here), `.gitignore`, pinned Python version. Set up pytest.
> Prompt: *"Scaffold a Python 3.12 project called graphgate with src/graphgate, tests/, docs/,
> a pyproject.toml, and pytest configured. No logic yet — just the skeleton and CI-friendly
> structure."*

**1.2** Build the refinement-loop driver: given a starting code file/repo snapshot and a list of
refinement prompts, call a code-generation LLM turn-by-turn, capture each candidate diff, and log
everything (prompt, response, diff, timestamp) to a structured trace file (e.g. JSON Lines).
> Prompt: *"Implement the refinement harness described in CLAUDE.md: a driver that takes a repo
> snapshot + an ordered list of prompts, calls the code-gen LLM once per turn, saves the diff and
> full I/O to a JSONL trace file. No gate logic yet — this just produces raw traces."*

**1.3** Add deterministic replay: given a saved trace file, replay it turn-by-turn feeding
pre-recorded diffs instead of calling the LLM live, so all future gate conditions (A/B/C) see
identical inputs.
> Prompt: *"Add a replay mode to the harness that consumes a saved JSONL trace and yields the same
> sequence of diffs deterministically, without calling the LLM again."*

**1.4** Add response caching keyed by `(prompt_hash, model, params)`.

**Exit check:** you can run the harness twice on the same prompt set and get byte-identical
trace files (in replay mode).

---

## Phase M1.2 — Dataset v1 (Weeks 3–6)

**2.1** Select and record the seed repository set: 8–12 mid-sized open-source Python projects
(5k–50k LOC) under permissive licenses (MIT / Apache-2.0 / BSD). Record the license of each and
verify compliance **before** any trace is redistributed (proposal §6.1). Output a manifest file
(repo URL, commit pinned, LOC, license, verification date) — this is the input to 2.2.

**2.2** Write a script to pull candidate CVE fix commits for injection-class vulnerabilities in
Python projects from CVEfixes (or equivalent public source).
> Prompt: *"Write a script that queries [CVEfixes/public source] for Python CVE fix commits
> tagged with injection-class CWEs (CWE-89, CWE-78, CWE-22), and outputs candidate
> vulnerable-commit / fixed-commit pairs with repo URL and file paths."*

**2.3** Manual validation pass: for each candidate, confirm the fix is genuinely injection-class,
extract the minimal vulnerable/fixed function pair, and record whether it's local (single-file)
or cross-file (fix touches a caller/callee in another file). Target 25–30 validated events for M1.

**2.4** Build the trace-synthesis tool: given a validated vulnerable/fixed pair, generate a 5–8
turn refinement trace (using the ISTAS-2025-style prompts: "improve readability", "add feature
X", "optimize") with the regression injected at a randomized turn.
> Prompt: *"Build a trace synthesizer: given a code snippet and its known-vulnerable variant,
> generate a 5-8 turn refinement trace using these prompt templates [...], injecting the
> vulnerable variant at a randomized turn between 2 and 6."*

**2.5** Label every turn `{clean, local_regression, cross_file_regression}` and store alongside
the trace.

**2.6** Leakage control (proposal §6.3): verify that each injected vulnerable pattern does not
already appear elsewhere in its repository; where duplicates exist, exclude them from the graph's
retrieval scope during evaluation. Log every exclusion — this has to be reportable.
> Prompt: *"Write a leakage check that, for each injected vulnerable pattern, scans the rest of
> the seed repository for near-duplicate occurrences and emits an exclusion list consumed by the
> retrieval layer."*

**Exit check:** 25–30 labeled traces on disk, each replayable via the M1.1 harness, with a seed-repo
license manifest and a leakage-exclusion list alongside them.

---

## Phase M1.3 — Local gate (B) + Pysa baseline (S1) (Weeks 6–9)

**3.1** Wrap Semgrep and Bandit to run on a diff and return structured findings.

**3.2** Build the LLM triage step for the local-only gate: given a diff + static-analysis
findings (no graph context), classify ALLOW / BLOCK and produce a rationale.
> Prompt: *"Implement Condition B: the local-only gate. Input is a diff + Semgrep/Bandit
> findings. Output is a structured decision {ALLOW, BLOCK} with a short rationale. Use temperature
> 0 and cache responses per CLAUDE.md conventions."*

**3.3** Wrap Pysa as a standalone baseline (S1) that runs independently of the LLM gate, on the
same diffs.

**3.4** Run Conditions A (no gate) / B (local gate) / S1 (Pysa-only) over the M1 dataset and
produce the full metric set from proposal §7.2 — not just the degradation curve:
- **Degradation curve** — cumulative ground-truth-verified critical/high regressions surviving
  per iteration, per condition.
- **Iterations-to-detection** — mean turns between a regression's introduction and first
  detection. A gate that flags three turns late is materially less useful than one that flags
  immediately, and the curve alone hides this.
- **Precision / false-positive burden** — fraction of BLOCK decisions on clean turns.
- **Overhead** — median added latency, LLM tokens, and estimated API cost per iteration.

Emit one tidy CSV keyed by `(trace_id, seed, condition, iteration)` so every metric above and the
§7.2 paired statistics can be derived from a single artifact.
> Prompt: *"Write the experiment runner that replays all M1 traces under conditions A, B, and S1,
> emitting a per-(trace, seed, condition, iteration) CSV covering surviving regressions,
> detection turn, BLOCK/ALLOW decision vs. ground-truth label, latency, and token count — plus the
> plotting script for the degradation curve."*

**Exit check (M1 complete):** you have a real A-vs-B-vs-S1 degradation-curve result, plus
iterations-to-detection and false-positive numbers for each condition. This is your fallback
publishable project if nothing else gets built — treat this exit check seriously.

---

## Phase M2.1 — Graph layer + ΔG engine (Weeks 9–12)

**4.1** Build the tree-sitter-based AST parser and symbol extractor (V).

**4.2** Build call-graph resolution (`E_call`) per the three resolution rules in CLAUDE.md,
explicitly logging `unknown` edges rather than dropping them.

**4.3** Build taint-edge extraction (`E_taint`) and the sanitizer allowlist (`E_sanitize`),
seeded from Semgrep/Pysa rule patterns.

**4.4** Build the incremental re-indexer: after an accepted revision, re-parse only changed
files and update the stored graph rather than rebuilding from scratch.

**4.5** Implement R1–R4 as pure functions over two graph snapshots, **each with unit tests on
hand-crafted minimal graphs before touching any real repo.**
> Prompt: *"Implement rules R1-R4 from CLAUDE.md as pure functions taking G(t-1) and G(t) and
> returning flagged deltas. Write unit tests first using small hand-constructed NetworkX graphs
> for each rule, covering both the case where the rule should fire and where it should not."*

**Exit check:** R1–R4 pass unit tests on synthetic graphs, and the graph builder runs end-to-end
on at least one real repo without crashing, with unknown-edge counts logged.

---

## Phase M2.2 — Dataset v2, Condition C, holdout (Weeks 12–15)

**5.1** Extend dataset construction to add 15–25 cross-file regression variants (sanitizer
weakened in one file, vulnerable call site in another).

**5.2** Build Condition C: the graph-augmented gate. Wire the ΔG engine's flagged deltas + their
supporting subgraphs into the LLM triage step.

**5.3** Collect the real-session holdout set: 10–20 genuine multi-turn refinement sessions with
manual two-pass review of naturally occurring regressions (disagreements adjudicated). Keep this
data untouched by any tuning — it's validation-only.

**5.4** Set up the **repository-level** holdout (proposal §7.4) — distinct from 5.3. Withhold
entire seed repositories from *any* rule tuning or sanitizer-allowlist curation, so generalization
is measured across repos and not just across traces. Record the split in the seed manifest from
2.1 and make the tuning scripts refuse to read held-out repos rather than relying on discipline.

**Exit check:** Condition C runs end-to-end on the full dataset; both holdouts in place — the
real-session set collected and reviewed, and the repository-level split enforced in code — sitting
untouched in their own directories.

---

## Phase M2.3 — Full study, ablations, writing (Weeks 15–18)

**6.1** Run the full three-condition + S1/S2 experiment across the whole dataset and the holdout
set separately.

**6.2** Run the ablation suite (call-only / taint-only / full / hop-depth 1-2-3 / rules-without-
LLM-triage), plus the **small-model ablation** — re-run Condition C on the secondary, cheaper code
LLM (proposal §9) to show how much of the benefit depends on model capability.

**6.3** Statistical analysis: paired Wilcoxon tests, effect sizes, confidence intervals.

**6.4** Manual error analysis on false negatives, categorized by cause (aliasing, dynamic
imports, reflection, framework flows, rule-coverage gaps).

**6.5** Write up results into the paper draft; prepare the artifact release (traces, rules,
harness) under a permissive license.

---

## How to actually work with Claude Code on this, day to day

- Keep `CLAUDE.md` and this file at the repo root — Claude Code reads `CLAUDE.md` automatically
  each session.
- Feed **one numbered step at a time**. After each step: run the tests, skim the diff yourself,
  commit, *then* move on. Don't queue up "do 3.1 through 3.4."
- When a step feels ambiguous, ask Claude Code to restate its plan before writing code — cheaper
  to correct a plan than a finished implementation.
- If you change a scope constraint (e.g., decide to support a second vulnerability class), update
  `CLAUDE.md` first, in writing, before asking Claude Code to build it. That file is your
  guardrail against scope creep as much as it is Claude Code's instructions.
- At the start of each new session, a quick "what's the current phase, and what did we finish
  last session?" grounds Claude Code against `CLAUDE.md`'s "Current phase" line — update that
  line yourself as you progress.
