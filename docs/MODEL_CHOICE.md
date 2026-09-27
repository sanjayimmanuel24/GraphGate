# Choice of code-generation model

> **Decided 2026-09-27: `claude-opus-4-8`** writes the code in the refinement loop.
> `claude-haiku-4-5` remains the smaller model for the proposal §9 ablation.
> This page is the rationale to draw on for the paper's methods section.

## Why this needed deciding

CLAUDE.md originally named `claude-opus-5`. In live smoke runs its safety classifier
declined ordinary refinement requests (`stop_reason: "refusal"`, category `cyber`) on a
harmless, parameterised-query fixture. A declined turn ends its replication (CLAUDE.md,
"Refusals"), so a model that declines this workload leaves traces too short to show a
degradation curve — and the declines concentrate on exactly the security-relevant turns
the study measures.

## Evidence

Same fixture (`examples/smoke/`), same three ISTAS-style prompts
(`examples/smoke_prompts.txt`), `effort: medium`, adaptive thinking where supported.

| Model | Turns completed | Refused | Replications reaching the last turn | Traces |
|---|---|---|---|---|
| `claude-opus-5` | — | in every run | 0 | `smoke-02`, `smoke-03-opus` |
| `claude-opus-5-5` | 5 of 7 | 2 (both turn 2) | 1 of 3 | `smoke-04-opus55` |
| `claude-opus-4-8` | 18 of 18 | 0 | 6 of 6 | `smoke-04-opus48`, `smoke-05-opus48` |
| `claude-haiku-4-5` | 18 of 18 | 0 | 6 of 6 | `smoke-04-haiku`, `smoke-05-haiku` |

Notes on reading this:

- **`smoke-03-opus` is weaker evidence than it looks.** It was recorded while the cache
  bug collapsed seeds, so its ten turn-2 refusals are ten samples of *one* request. They
  show the classifier declines that request reliably, not the refusal rate across
  independent trajectories.
- The same turn-1 request to Opus 5 was declined in one run and accepted in another, so
  the classifier is not deterministic on a given request.
- **The samples are small and the fixture is harmless.** M1.2 traces contain genuinely
  vulnerable code, so refusals are likely to rise for every model, Opus 4.8 included.
  Whatever it declines is recorded and reported as refusal rate (BUILD_PLAN 3.4).
- `smoke-05-*` were recorded on the final M1.1 code (trace schema v4) and replay
  byte-identically. The earlier traces use schemas v2–v3 and cannot be replayed by the
  current build; their figures were read from them before the format changed.

## Why Opus 4.8 over the alternatives

- **Opus 5.5** is newer and cheaper ($4 / $20 per MTok, against $5 / $25), but two of
  three replications were cut short at turn 2 on harmless code. On vulnerable code that
  would likely leave too few complete traces.
- **Automatic fallback** (re-running a declined request on another model) was rejected
  earlier: it would mix two models within one condition.
- **Opus 4.8** completed every turn, is the model Anthropic's refusal message and fallback
  guidance point integrators to for this refusal category, and is supported until at least
  2027-05-28 — past the end of this project.

## What the write-up should say

- State that the newest models (Opus 5, Opus 5.5) were evaluated and declined a large share
  of refinement turns on benign code, and that this is why an earlier model was used. It is
  a finding in its own right about deploying frontier models inside refinement loops.
- Report the exact identifiers: the requested ID (`model` on each trace record) and the
  snapshot the API served (`resolved_model`).
- Report the refusal rate per model alongside the degradation curve.

## Open risk: the ablation model's retirement

`claude-haiku-4-5` is the oldest model still offered, with a retirement floor of
2026-10-15. It is not yet deprecated, and Anthropic gives at least 60 days' notice, so it
cannot disappear abruptly. Recorded traces stay replayable after retirement — replay never
calls the model — but new ablation runs would stop. `claude-sonnet-5` ($2 / $10, supported
until at least 2027-06-30) is the natural replacement if that becomes necessary.
