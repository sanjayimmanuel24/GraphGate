# Choice of code-generation model

> **Changed 2026-10-07, on the guide's instruction: no commercial model in the experiment.**
> Code generation and triage run on the open-weight `qwen2.5-coder:14b` (see the next
> section). Everything below "Earlier decision" is history: it explains the archived
> smoke evidence and is not the experiment's setup.

## Current choice: an open-weight model

| | |
|---|---|
| Model | `qwen2.5-coder:14b`, 14.8B parameters, Q4_K_M quantisation, Apache-2.0 (Hui et al., arXiv:2409.12186) |
| Served by | Ollama 0.40.0 in a Kaggle notebook (GPU T4 x2), as `qwen2.5-coder-14b-ctx32768` |
| Context | 32,768 tokens, set in a Modelfile and checked by measurement before recording |
| Used for | code generation and the triage step, the same model in every condition |
| Client | `graphgate.llm.openai_compat`, `--provider openai-compatible --base-url http://localhost:11434/v1` |

What the runs showed so far is in `data/open_model_runs.json`
(`scripts/summarize_open_model_runs.py`):

- **Pilot, 3 events:** 21 of 21 turns returned usable files, the regression was placed in
  all 3 traces, and the traces replay byte for byte. Median 48 s per turn.
- **Carried labels:** 14 of the 21 pilot turns had to carry their label from the previous
  turn, because the model rewrote the functions the regression lives in. Report this
  count; the turn that brings the regression in is the measurement least affected.
- **Seeds:** the client sends the replication number as the server's sampling seed. Under
  seed 1 the reply broke the output format in all 14 events of the first dataset session;
  seeds 0 and 2 never did. Replications are therefore **0, 2, 3**. The choice was made on
  format validity alone, before any gate was run; say so in the write-up. The cause is
  not established (a fixed seed reuses one random stream for every request).
- **Failed injections:** 4 of 26 replications in that session, where the model had removed
  or renamed the function the regression goes into. Recorded as failed, not worked around.
- **Unusable replies** (prose instead of files) are the model's outcome for the turn and
  stay in the trace; only a call that failed outright holds a trace back for a retry.

Still to fix after the dataset recording: whether a smaller open model serves as the
proposal §9 ablation model, which depends on the GPU hours left.

## Earlier decision (superseded for new runs)

> Decided 2026-09-27: `claude-opus-4-8` wrote the code in the refinement loop, with
> `claude-haiku-4-5` as the smaller ablation model. Kept because the archived smoke
> traces were recorded with these models and still replay.

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
The traces named below are archived, checksummed, in `docs/evidence/2026-09-27-smoke/`.

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
