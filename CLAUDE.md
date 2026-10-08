# GraphGate — Project Context for Claude Code

> This file is read automatically by Claude Code at the start of every session in this repo.
> Keep it updated as decisions change — it is the single source of truth for scope, architecture,
> and conventions. Do not let implementation details drift from this file without updating it.

## What this project is

GraphGate is a final-year capstone research project: a security gate that sits inside an
**iterative LLM code-refinement loop** and blocks/flags security regressions that a diff-only
check would miss, by reasoning over a **temporal code-graph delta (ΔG)** between successive
revisions rather than the raw diff.

Full academic proposal (problem statement, related work, evaluation design) lives at
`docs/GraphGate_Capstone_Proposal_v2.docx` — treat it as the spec. If code and proposal ever
disagree, flag the conflict instead of silently picking one.

## Core research question (do not lose sight of this)

Does grounding an in-loop security gate in cross-file code-graph context reduce security
degradation across refinement iterations, compared to (a) no gate and (b) a gate restricted to
local diff context? Everything we build exists to answer this, cleanly and measurably.

## Architecture (see Figure 1 in the proposal)

```
Refinement prompt (turn t)
        │
        ▼
Code-generation LLM → candidate diff
        │
        ▼
┌─────────────────────────── SECURITY GATE ───────────────────────────┐
│ 1. Static analysis on diff (Semgrep, Bandit)                        │
│ 2. ΔG DIFFERENCING ENGINE: G(t) − G(t−1), apply rules R1–R4          │
│ 3. LLM triage: classify each flagged delta as                       │
│    exploitable-regression / benign-refactor / uncertain + rationale │
└───────────────────────────────────────────────────────────────────────┘
        │
        ▼
Decision: ALLOW / BLOCK + rationale / AUTO-REPAIR (stretch goal)
        │
        ├─ BLOCK  → rationale fed back into next refinement prompt
        └─ ALLOW  → commit; re-index changed files into the graph
```

### Graph definition
`G(t) = (V, E_call, E_taint, E_sanitize)`
- **V**: function/method/module-level symbols from tree-sitter ASTs.
- **E_call**: resolved via (i) direct same-module calls, (ii) import-resolved cross-module
  calls (static imports only), (iii) attribute calls when the receiver's class is statically
  inferable. Anything else → an explicit `unknown` edge. **Never silently drop unresolved calls.**
- **E_taint**: sources (request params, env reads, file/network input, CLI args) → sinks, via
  assignment and call-argument propagation. Flow-insensitive, path-insensitive interprocedurally
  — this is a deliberate simplification, not a bug.
- **E_sanitize**: nodes matching a curated allowlist (parameterized query constructors,
  escaping/encoding functions, validation wrappers), seeded from Semgrep/Pysa rule sets.

### ΔG rules (the primary detector — deterministic, must be unit-testable)
- **R1 — Sanitizer removal**: an `E_sanitize` node present in G(t−1) is absent/bypassed in G(t)
  while its callers remain.
- **R2 — New source→sink path**: a source→sink path exists in G(t) that did not exist in G(t−1).
- **R3 — Guard elimination**: a validation/guard edge on an existing source→sink path disappears.
- **R4 — Path shortening**: the minimum sanitizer-free hop distance from source to sink decreases.

The LLM's job is to **triage flagged deltas**, not to discover vulnerabilities from open-ended
context. Do not let the LLM's role expand back into "look at this code and find issues" —
that reintroduces the hallucination surface the design specifically avoids.

## Hard scope constraints — do not silently expand these

- **Language: Python only.** No Java/JS/Go support in the implementation. (A short portability
  *discussion* exists in the proposal; there is no cross-language code.)
- **Vulnerability family: injection-class only** (SQL/command/path injection, missing
  sanitization). Do not add XSS, deserialization, crypto-misuse, etc. detection rules.
  Operationally: CWE-89 (SQL), CWE-78 (OS command), CWE-77 (command injection, the general
  weakness — many advisories file command injection under it instead of 78), CWE-22 (path
  traversal). CWE-77 was added 2026-09-27 as a reading of "command injection", not an expansion.
- **Seed repositories** (decided 2026-09-27): the projects whose real injection CVE fixes supply
  the ground truth, recorded in `data/seed_repos.json` (built by `scripts/build_seed_manifest.py`
  from the OSV PyPI export). "5k–50k LOC" means non-blank `.py` lines outside test/doc/example
  directories, measured at each advisory's vulnerable commit (2.2). The set is heavy on path
  traversal (22 of the 35 candidate pairs after 2.2) because that is what the permissive,
  mid-sized pool contains; report results per class rather than pooled.
- **Commit pairs** (2.2): commits not taken from an advisory itself live in their own files so
  each is auditable: `data/recovered_fix_commits.json` (fixes for advisories linking none) and
  `data/fix_pair_corrections.json` (hand-curated, only where both independent reviewers agreed).
  Never edit a pair in `data/fix_pairs.json` directly — it is regenerated.
- **Regression events** (2.3, decided 2026-09-28): each event is a *trimmed slice* in
  `data/events/<event_id>/` — the files on the vulnerable flow at their real repository paths, cut
  to the functions between entry, guard and sink, as `clean/` (fix commit) and `regressed/`
  (vulnerable commit). The refinement model edits whole files, and 16 of 35 candidates had a flow
  file too large for one response, which is why whole files were rejected. Deviation from the
  proposal to keep in view: §6.3 implies the graph retrieves over the whole repository; slices
  keep real paths so the repository can still be overlaid for Condition C.
  - **Scope label, pre-registered:** *local* iff entry, guard and sink lie in one file, else
    *cross-file*. Computed by `graphgate.dataset.events.classify_scope` from recorded facts; an
    entry or sink too large for the slice is recorded at its call site with the real location in
    `true_symbol`, and the label follows the real location. Do not change this rule after seeing
    results.
  - **Validation:** AI agents prepare each dossier (analyst, then an adversarial checker); only
    the owner's accept on the sign-off page makes an event validated. Never describe AI-prepared
    events as validated or expert-confirmed.
  - **Sign-off (2026-10-05):** 30 of the 34 events accepted, 2 rejected, 2 sent back; recorded
    in `data/validation_signoff.json` by `scripts/save_signoff.py`. In the write-up call these
    events accepted by the authors on AI-prepared, adversarially checked dossiers; the sign-off
    reviewed those dossiers and is not an independent re-derivation.
  - Build with `scripts/build_event.py`; never edit `clean/`, `regressed/` or `event.json` by
    hand — change `spec.json` and rebuild.
- **Traces** (2.4, decided 2026-10-04): the regression is *bundled with a model turn* — at the
  planned turn the model makes its own change, then the regression is placed in the code it
  produced (`graphgate.harness.injection`). A trace's turn count, instructions and injection turn
  depend only on `(plan_seed, event_id)`, so every replication of an event follows the same plan.
  - Dataset traces (`data/traces/`) come only from events accepted in
    `data/validation_signoff.json` on the current dossier. `--pilot` traces
    (`runs/pilot-traces/`) test the tool and are never reported as dataset results.
  - The `injection` field of a trace (schema v5) is ground truth. Never show it to the
    code-generation model or to any gate condition.
  - An injection that cannot be placed is recorded as failed and ends the replication. Never
    fall back to overwriting the model's file with the regressed version.
  - Do not change `data/refinement_prompts.txt` or the plan seed once dataset traces exist: the
    manifest marks every trace recorded under another plan (`matches_plan: false`).
- **Turn labels** (2.5, 2026-10-04): `graphgate.dataset.labels` labels the code *after* each turn
  — `clean`, `local_regression` or `cross_file_regression` — and marks the turn that brings the
  regression in as `introduced`. Labels are read off the recorded code: the units that differ
  between the event's clean and regressed files are compared with both versions, ignoring
  comments, docstrings and layout.
  - Where the model has rewritten one of those units, the label is carried from the previous
    turn and the turn is marked `carried`. Never count a `carried` turn as verified ground
    truth; report how many there are and how they were handled.
  - Labels cover the event's regression only, not weaknesses the model introduces by itself.
  - Do not change the rule after seeing gate results. Labels are regenerated from the traces
    (`scripts/label_traces.py`); never edit a `.labels.json` by hand.
- **Leakage control** (2.6, 2026-10-06): `data/leakage_exclusions.json`, written by
  `scripts/check_leakage.py`, lists what retrieval must keep out of scope for each validated
  event: near-duplicates elsewhere in the repository of the code the regression touches
  (similarity 0.8 or more over code tokens, units of at least 30 tokens, clean and regressed
  versions both compared) and test files the fix changed. Read it with
  `graphgate.dataset.leakage.load_exclusions`.
  - The retrieval layer (M2.1) must apply this list; a Condition C run that ignores it is not
    comparable with Condition B.
  - The threshold and minimum size were fixed before any gate existed. Do not tune them against
    gate results. Rerun the scan whenever the set of validated events or a dossier changes.
  - Source files a fix changed outside its slice are listed but stay in scope; whether sibling
    files given the same fix stay visible is open for M2.1 (BUILD_PLAN 2.6).
- **Bounded retrieval**: default 2-hop neighborhood around changed symbols. Hop depth is an
  ablation variable (1/2/3), not something to "improve" beyond the plan.
- **Deployment targets**: CI pre-merge gate and agent-framework middleware (e.g., a LangGraph
  node). Explicitly NOT an IDE plugin — no need to optimize for sub-second interactive latency.
- If you (Claude Code) think a scope constraint should change, say so explicitly and ask —
  do not just implement the larger version because it seemed natural.

## Success criteria (pre-registered — proposal §7.5)

These are operating points the project is judged against, not aspirations. They were fixed in
advance; do not quietly relax them because a run came in over budget.

- **False-positive rate < ~15%** — fraction of BLOCK decisions on clean turns, in Condition C.
- **Median added latency < ~10 s per iteration** in the CI setting.
- Condition A must reproduce a degradation trend consistent with the ISTAS 2025 base paper.
- Condition C must show a **statistically significant** improvement in cross-file recall over
  Condition B, and be at least competitive with S1 (Pysa).

A null result on the cross-file comparison is still reportable as a rigorous negative finding —
the controlled design is the contribution. Do not tune toward a positive result.

## Tech stack (decided — don't relitigate without discussion)

- Python 3.12
- Parsing: `tree-sitter` + `tree-sitter-python`
- Static analysis: Semgrep, Bandit (baseline B); Pysa (baseline S1, required); CodeQL (baseline
  S2, optional — license-permitting). Decided 2026-10-06: Semgrep 1.179.0 and Bandit 1.9.4 live
  in their own environment, `.venv-tools` (`requirements-analysers.txt`), never in the project's;
  Semgrep's rules are the public community rules pinned at one commit and cut to the injection
  family (`data/semgrep_rules.json`, fetched by `scripts/fetch_semgrep_rules.py`). The rule files
  are not committed: their licence restricts redistribution.
- Graph storage: NetworkX in-process, persisted to SQLite between iterations
- Orchestration: LangGraph (reuse patterns from the UTA trading project if helpful)
- **Models, changed 2026-10-07 on the guide's instruction: no commercial model in the
  experiment.** The code-generation model and the triage model are to be an open-weight model
  (candidate: `qwen2.5-coder:14b`, Apache-2.0), run by the owner in a free cloud GPU notebook
  because this laptop (8 GB RAM, 4 GB GPU) cannot run one
  (`notebooks/record_traces_open_model.ipynb`, `--provider openai-compatible --base-url ...`,
  client in `graphgate.llm.openai_compat`). The exact model is fixed after the notebook pilot;
  record its name and build with every run. Do not run dataset traces or gate conditions
  against a Claude model. The Claude entries below are history: they explain the archived smoke
  evidence, which still replays. Open-weight servers accept a seed, and the client sends the
  replication number as one; cache and replay remain what reproducibility rests on. What cannot
  change: Claude agents prepared the event dossiers and Claude Code assisted with code and
  draft, which stays disclosed in the paper.
- Earlier decision (superseded for new runs): `claude-opus-4-8` as the primary code LLM, `claude-haiku-4-5` as the smaller ablation
  model (proposal §9). Both are CLI flags, never constants — record the exact identifiers used
  in every run. Decided 2026-09-27 after `claude-opus-5` and `claude-opus-5-5` refused ordinary
  refinement turns on harmless code (Opus 4.8: 0 of 9); evidence and write-up guidance in
  `docs/MODEL_CHOICE.md`. Haiku 4.5 has the nearest retirement floor (2026-10-15);
  `claude-sonnet-5` is the fallback ablation model if it is deprecated mid-study.
- LLM calls: cache every response keyed by `(prompt_hash, replication)` — this is required for
  deterministic replay across the A/B/C conditions, not optional. `prompt_hash` already covers
  model and params. **The replication (seed) must be in the key**: the API takes no seed, so every
  seed sends an identical request, and without it one seed's cached answer is served to all the
  others — N replications collapse into one trajectory copied N times, and the §7.2 statistics
  silently run over duplicates. This happened in the 2026-09-27 smoke run and is now fixed and
  regression-tested.
- Testing: pytest; every ΔG rule (R1–R4) needs unit tests on hand-crafted minimal graphs before
  it's ever run on real repos

## Coding conventions

- Prefer small, reviewable modules over one large script. Each ΔG rule is its own function with
  its own unit tests.
- No silent fallbacks: if call resolution fails, taint propagation is ambiguous, or a sanitizer
  pattern doesn't match, log it explicitly (we report "unknown-edge counts" as a transparency
  metric in the paper — this data has to come from somewhere).
- Every experiment/script must be re-runnable deterministically. For everything we control, that
  means pinned dependency versions in `pyproject.toml` and no unseeded randomness.

  **For LLM calls, determinism comes from response caching and trace replay — not from sampling
  settings.** Do not add `temperature`, `top_p`, or `top_k` to a request: current models
  (`claude-opus-4-8` and every model from Opus 4.7 on) removed those parameters and return 400.
  The Messages API has no seed parameter either, on any model. An earlier draft of this file
  specified "temperature 0"; that is not achievable on the chosen models, and `temperature=0`
  never guaranteed identical outputs even where it was accepted. The mechanisms that actually
  deliver reproducibility are the cache (BUILD_PLAN 1.4) and replay (BUILD_PLAN 1.3), and
  conditions A/B/C are compared over replayed traces, so they see identical inputs by
  construction. Full reasoning and the rejected alternative: `docs/DETERMINISM.md`.

- `seeds` labels **independent replications**, not provider determinism. Proposal §7.2 runs
  several per trace for confidence intervals and the paired Wilcoxon tests, so anything taking a
  seed takes `seeds: list[int]`, from the harness outward. Never describe this in the write-up as
  a reproducibility mechanism — it isn't one.
- Config over hardcoding: hop depth, vulnerability family, model choice, etc. should be CLI/config
  flags, not constants buried in code — we need this for the ablation study (Section 7.3).

- **Static analysers** (3.1): go through `graphgate.gate.analysers.StaticScanner`, never call
  Semgrep or Bandit directly.
  - Scan many file versions in one call. Semgrep takes about ten seconds to start, so a loop of
    single-file scans turns minutes into hours; results are kept by content.
  - A finding is the change's doing only if it is *introduced* (`ChangeFindings.introduced`):
    pattern scanners flag most risky lines before and after an edit alike.
  - Never loosen the checks that every file was analysed, and keep the tools offline (metrics
    and version check off, local rules only).
  - Do not edit, add or drop Semgrep rules to change what Condition B catches. The selection
    rule (declared family CWE, plus the two marked exceptions) was fixed before B was ever run.

- **Diff-only gates and triage** (3.2, decided 2026-10-06): two conditions, reported separately.
  **B** is the planned one: the LLM triages what Semgrep and Bandit flag. **B+** was added
  because the scanners flag so little: the LLM also judges every change as a whole.
  - B+ is a baseline, not part of GraphGate. In Condition C the LLM still triages flags only;
    the rule above about not letting its role expand stands.
  - The registered comparison is C against B. Report C against B+ next to it, never instead.
  - `graphgate.gate.triage.SYSTEM_PROMPT` is part of the experiment. Change it only together
    with `PROMPT_VERSION`, never after a condition has been run with it, and use the same
    system prompt for every condition: conditions differ in the user message alone.
  - A gate is shown the diff and the items to judge. Never the refinement instruction, a trace
    or event id, a label, or the trace's `injection` field.
  - "uncertain" does not block; a refusal, a failed call or an unusable reply does not block
    either and is recorded as its own outcome. Do not turn those into verdicts.

- **Graph layer** (M2.1, 2026-10-08): `graphgate.graph`. `extract` reads one file into facts,
  `link` builds the graph from all facts, `index` stores facts per file and re-parses only what
  changed, `delta` holds R1 to R4.
  - Each rule stays one pure function of two graphs with its own tests on hand-built graphs
    (`tests/test_delta.py`). How each rule's wording is read is fixed in the docstring of
    `graphgate.graph.delta`; do not change a reading after the rules have been run on events.
  - `graphgate.graph.catalog` (sources, sinks, the sanitizer allowlist, the words that mark a
    validation function) is part of the experiment, like the Semgrep rule selection. Never add,
    drop or reword an entry to change what Condition C catches, and never fill the per-repository
    extension from the events (repository-level holdout, BUILD_PLAN 5.4).
  - Taint edges join ports (a symbol's parameters, return value, attributes, module names), not
    whole functions. Say so in the write-up; the proposal's V lists symbols only.
  - A call that cannot be resolved is an `unknown::` edge and is counted
    (`graph.graph["stats"]`); a file that does not parse is listed there too. Keep both.
  - `GraphConfig.public_api_sources` and `GraphConfig.structural_guards` widen the proposal's
    source list and its E_sanitize. **Decided by the owner on 2026-10-08, before the rules were
    run on any event: Condition C uses both** (`graphgate.graph.link.GRAPHGATE`). The other
    three combinations (`SETTINGS`), the proposal's literal reading among them, are reported
    beside it as an ablation, never in its place. Do not change which one is Condition C after
    seeing results, and disclose both departures from the proposal in the write-up. A graph
    records the settings it was built with; results under different settings are never mixed.
  - Build a graph for an event's repository with `link(..., exclude=...)` and the event's
    leakage exclusions (see "Leakage control").

- **Refusals** — decided 2026-09-27: *record and report*. The code-generation model's safety
  classifiers can decline a request (HTTP 200, `stop_reason: "refusal"`); the first live smoke
  run hit one. Refusals concentrate on exactly the security-relevant turns this study measures,
  so if they silently drop out, the degradation curve is biased downward, not just noisier.
  - A refusal is recorded as its own trace kind, `refusal`, with the API's category and
    explanation. It is a model outcome, never lumped in with `error`.
  - A refused turn ends that replication — the snapshot never received the change. Revisit at
    BUILD_PLAN 2.4 if this cuts short too many traces.
  - Report the refusal rate, with its category breakdown, alongside the degradation curve
    (BUILD_PLAN 3.4).
  - No automatic fallback to another model: that would mix two models within one condition.
  - Refusals are never cached — that would lock a possibly-false-positive refusal into every
    future live run. Replay reproduces recorded refusals exactly.

- **No research framing in model-visible code.** The harness sends every snapshot file to the
  code-generation model verbatim, so docstrings, comments, and names are part of the prompt.
  Anything the model sees — snapshots, seed code, fixtures — must read as ordinary code, with no
  mention of security testing, regressions, vulnerabilities, CVEs, or this study. Framing biases
  the output toward unrequested defensive code and can trigger refusals; the first smoke fixture
  did both. Explanations go in files the harness never sends (a README, prompt-file comments).

## Current phase

See `BUILD_PLAN.md` for the milestone breakdown. Update the "Current phase" line here as you
move between phases so a new session knows where things stand.

**Current phase: M1.1 complete** — scaffold (1.1), refinement-loop driver (1.2), deterministic
replay (1.3), and response caching (1.4) are all in. Live smoke runs on 2026-09-27 confirmed the
response protocol and byte-identical replay on real output, and surfaced problems now fixed:
research framing in the fixture, seeds collapsing under the cache, Opus-only request settings
breaking Haiku 4.5, requested-vs-reported model IDs breaking replay, and replay rejecting traces
whose first seed stopped early. The code-generation model is decided (`claude-opus-4-8`, see
`docs/MODEL_CHOICE.md`). **M1.2 in progress:** step 2.1 done provisionally — 12 seed repos plus 4
reserves in `data/seed_repos.json`. Step 2.2 done — 35 candidate vulnerable/fixed pairs in the
selected repos (`data/fix_pairs.json`), each reviewed by two independent reviewers
(`data/fix_review.json`). **Step 2.3 done:** the 35 pairs form 34 events; after AI preparation
(`data/validation_ai_review.json`) the owner signed off on 2026-10-05 — 30 validated events (24
cross-file, 6 local) in `data/validation_signoff.json`. **Step 2.6 done:** the leakage scan gives
35 exclusions in 20 events (`data/leakage_exclusions.json`). **Steps 2.4 and 2.5: tools built**
(`scripts/synthesize_traces.py`, trace schema v5; `scripts/label_traces.py`) **but no trace has
been recorded.** What closes M1.2 is the owner's paid run: a 3-event pilot (`--pilot`), then the
dataset run over the 30 validated events (about 603 calls, roughly $74–126 at 3 seeds), each
followed by labelling; the pilot also shows how many turns come out `carried`. **Next to
build: M1.3.** Step 3.1 is done (Semgrep and Bandit wrapper; only 1 of the 30 raw regressions
introduces a static finding). Step 3.2 is built (triage step, Condition B and the added baseline
B+) and tested against a stand-in model; the owner's paid pilot (`scripts/triage_events.py`, 62
calls) has not been run. **Next: 3.3** (Pysa), which needs Linux; this machine has neither WSL
nor Docker (BUILD_PLAN 3.1, "Open"). A
progress paper (`paper/`) and a dashboard
(`scripts/build_dashboard.py`) exist for the guide's review; both read their numbers from the
data files.

**M2.1 built (2026-10-08), ahead of M1.3's runs, because it needs no GPU:** the graph layer and
rules R1 to R4 (`graphgate.graph`, BUILD_PLAN 4.1 to 4.5) with 73 tests; the builder ran on all
12 seed repositories (`data/graph_build_check.json`, 35.1% of calls are unknown edges). The owner fixed Condition C's graph settings (both widened) before the rules were run on any
event. A first look then took each validated event's regression as one change
(`scripts/delta_events.py`, `data/delta_first_look.json`), as `scripts/scan_events.py` did for
the scanners: the rules flag 8 of 30 (5 of 24 cross-file), the scanners 1 of 30; on the reverse
change, the fix, the rules fire on 4 of 30. It is not a gate result, and the rules, the catalog
and the settings were not changed after it. Never change them to raise that number; report the
22 misses by cause (BUILD_PLAN M2.1). Next for the graph: how Condition C sees code cut from a
slice (5.2).

**Model switch, in progress (2026-10-08).** The experiment model is `qwen2.5-coder:14b`
(Q4_K_M, Apache-2.0, 32,768-token context, Ollama 0.40.0), run by the owner in a Kaggle GPU
notebook. The three-event pilot passed. The dataset run is under way and spans several
10.5-hour sessions (about 50 minutes per event); results come back as `graphgate_results.zip`.
- **Replications are 0, 2 and 3, not 0, 1, 2.** The client sends the replication number as the
  sampler seed, which fixes one random stream per replication. Under seed 1 the model's reply
  broke the output format in all 14 events the first run started (never under 0 or 2), so seed
  1 is dropped. The criterion is format validity alone; do not pick seeds on any other outcome.
- A reply the model gave but that cannot be used (prose, a cut-off file) is the model's outcome:
  it is recorded as an `error` turn, ends the replication and stays in the trace. Only a call
  that failed outright holds a trace back for a retry.
- With this model the injection fails more often than expected (4 of 26 replications in the
  first run), because it removes or renames the functions the regression lives in. Report the
  rate; never work around it.
- `docs/MODEL_CHOICE.md`, the paper and the dashboard describe the open model (2026-10-08); their
  figures come from `data/open_model_runs.json` (`scripts/summarize_open_model_runs.py`).
- Still to do after the run: the triage pilot in the notebook, and Pysa (3.3) there as well.

**Paper tables for unfinished work (2026-10-08):** "Results obtained so far" holds measured
values only, read from the data files. "Remaining steps" lists every open BUILD_PLAN step with
an *expected* outcome, marked as not yet measured. Never move a figure from the second table
into the first, or write an expected outcome as a result, until the run behind it exists; when
a step is measured, replace its expectation with the measurement and say if it differed.

**Paper headings (fixed by the guide, 2026-10-06):** Abstract, Introduction, Literature Survey,
Methodology, Dataset Description, Implementation and Results, Conclusion and Future Work,
References, and no others. No subsection headings and no separate Acknowledgment, Threats or
Related Work sections: topics inside a section start with an italic lead-in. The paper stays
within 6 pages. The AI-use disclosure is the closing paragraph of the conclusion; do not drop it.
