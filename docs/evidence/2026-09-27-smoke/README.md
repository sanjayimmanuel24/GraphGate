# Smoke-run traces, 2026-09-27

Raw traces from the first runs against the live Anthropic API. They are the evidence
behind `docs/MODEL_CHOICE.md` (why `claude-opus-4-8` writes the code) and behind several
rules and fixes recorded in `CLAUDE.md`. Model output is not reproducible on demand, so
these files are kept rather than regenerated.

**These are smoke tests, not study data.** Every run used the toy fixture in
`examples/smoke/` and the three prompts in `examples/smoke_prompts.txt`.

## Files

| File | Model requested | Schema | Seeds | Outcome | What it shows |
|---|---|---|---|---|---|
| `smoke.jsonl` | `claude-opus-5` | v2 | 1 | 2 turns; turn 3 declined, recorded as `error` (predates the `refusal` kind) | The fixture's docstring described it as a regression test; the model answered with unrequested security commentary. Basis for "No research framing in model-visible code". |
| `smoke-02.jsonl` | `claude-opus-5` | v3 | 1 | turn 1 refused (`cyber`), before any output | The cleaned fixture was still refused, so the framing was not what triggered the classifier. |
| `smoke-03-opus.jsonl` | `claude-opus-5` | v3 | 10 | 10 turns, 10 refusals at turn 2 | Recorded under the cache bug: seeds 1–9 were served seed 0's turn 1, so the ten refusals are ten samples of **one** request. Evidence for the bug, and that the classifier declines that request reliably. |
| `smoke-03-haiku.jsonl` | `claude-haiku-4-5` | v3 | 3 | 3 errors: HTTP 400, adaptive thinking not supported | Opus-only request settings broke the ablation model. Led to per-model presets. |
| `smoke-04-opus55.jsonl` | `claude-opus-5-5` | v3 | 3 | 5 turns, 2 refusals (both turn 2) | Opus 5.5 evaluation for `MODEL_CHOICE.md`. |
| `smoke-04-opus48.jsonl` | `claude-opus-4-8` | v3 | 3 | 9 of 9 turns | Opus 4.8 evaluation. Seed 2, turn 3 ("Optimize the database access") interpolates a column name into SQL with an f-string — the first regression-like pattern observed. |
| `smoke-04-haiku.jsonl` | `claude-haiku-4-5` | v3 | 3 | 9 of 9 turns | Its `model` field holds the served snapshot (`claude-haiku-4-5-20251001`), not the requested ID — the bug that broke replay's hash check. |
| `smoke-05-opus48.jsonl` | `claude-opus-4-8` | v4 | 3 | 9 of 9 turns | Final M1.1 code. Replays byte-identically. |
| `smoke-05-haiku.jsonl` | `claude-haiku-4-5` | v4 | 3 | 9 of 9 turns | Final M1.1 code; `model` and `resolved_model` recorded separately. Replays byte-identically. |

## Replaying and verifying

Only the **v4** files replay with the current build; the rest are rejected by the schema
check but remain readable JSON Lines.

```powershell
graphgate-harness --replay docs/evidence/2026-09-27-smoke/smoke-05-opus48.jsonl --out runs/check.jsonl
```

`SHA256SUMS` records each file's hash at the time it was archived. These files must stay
byte-exact: `.gitattributes` marks them `-text` so git never rewrites their line endings.
