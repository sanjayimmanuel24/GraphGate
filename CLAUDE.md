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
  S2, optional — license-permitting)
- Graph storage: NetworkX in-process, persisted to SQLite between iterations
- Orchestration: LangGraph (reuse patterns from the UTA trading project if helpful)
- Models: `claude-opus-4-8` as the primary code LLM, `claude-haiku-4-5` as the smaller ablation
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
(`data/fix_review.json`). **Step 2.3 in progress:** the 35 pairs form 34 events; AI preparation
is finished (31 passed the adversarial check, 2 excluded, 1 rebuilt and awaiting a re-check —
`data/validation_ai_review.json`). **Next: the owner's sign-off** on the sign-off page (0 of 34
decided as of 2026-10-04), then record the decisions in `data/validation_signoff.json` and close
2.3. **Steps 2.4 and 2.5 tools built** (`scripts/synthesize_traces.py`, trace schema v5;
`scripts/label_traces.py`) but nothing has been recorded live: the owner runs a pilot
(`--pilot`, 3 events) and, after the sign-off, the dataset run; labelling follows each. The
pilot also shows how many turns come out `carried`. **Next to build: 2.6 (leakage control).** A
progress paper (`paper/`) and a
dashboard (`scripts/build_dashboard.py`) exist for the guide's review; both read their numbers
from the data files.
