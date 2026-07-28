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
- LLM calls: cache every response keyed by `(prompt_hash, model, params)` — this is required for
  deterministic replay across the A/B/C conditions, not optional
- Testing: pytest; every ΔG rule (R1–R4) needs unit tests on hand-crafted minimal graphs before
  it's ever run on real repos

## Coding conventions

- Prefer small, reviewable modules over one large script. Each ΔG rule is its own function with
  its own unit tests.
- No silent fallbacks: if call resolution fails, taint propagation is ambiguous, or a sanitizer
  pattern doesn't match, log it explicitly (we report "unknown-edge counts" as a transparency
  metric in the paper — this data has to come from somewhere).
- Every experiment/script must be re-runnable deterministically: fixed seeds, temperature 0 for
  gate/triage LLM calls, pinned dependency versions recorded in `requirements.txt` or `pyproject.toml`.
  "Fixed seeds" means a **fixed list of several** seeds, not one — proposal §7.2 runs multiple
  seeds per trace to get confidence intervals and the paired Wilcoxon tests. Anything that takes a
  seed should take `seeds: list[int]`, from the harness outward.
- Config over hardcoding: hop depth, vulnerability family, model choice, etc. should be CLI/config
  flags, not constants buried in code — we need this for the ablation study (Section 7.3).

## Current phase

See `BUILD_PLAN.md` for the milestone breakdown. Update the "Current phase" line here as you
move between phases so a new session knows where things stand.

**Current phase: M1.1 — step 1.1 (scaffold) complete. Next: 1.2 (refinement-loop driver).**
