# GraphGate

A security gate that sits inside an **iterative LLM code-refinement loop** and blocks or flags
security regressions a diff-only check would miss — by reasoning over a **temporal code-graph
delta (ΔG)** between successive revisions rather than the raw diff.

Final-year capstone research project.

## Research question

Does grounding an in-loop security gate in cross-file code-graph context reduce security
degradation across refinement iterations, compared to (a) no gate and (b) a gate restricted to
local diff context?

## Scope

- **Language:** Python only
- **Vulnerability family:** injection-class only (SQL / command / path injection, missing sanitization)
- **Targets:** CI pre-merge gate and agent-framework middleware — not an IDE plugin

See [CLAUDE.md](CLAUDE.md) for the full architecture, graph definition, ΔG rules R1–R4, and scope
constraints. See [BUILD_PLAN.md](BUILD_PLAN.md) for the milestone breakdown.

## Setup

Requires **Python 3.12+**.

```bash
python -m venv .venv && .venv/Scripts/activate && pip install -e ".[dev]"
```

Run the tests:

```bash
pytest
```

## Layout

```
src/graphgate/   package source
tests/           pytest suite
docs/            proposal (the spec), figures, paper draft
```

## Status

**Current phase:** M1.1 — refinement harness. Step 1.1 (scaffold) complete.
