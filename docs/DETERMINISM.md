# Determinism in GraphGate

> **Status: decided — Option A**, 2026-07-28. `CLAUDE.md` has been amended to match.
> This page is the rationale to draw on when writing the methods section; Option B is
> kept below as the recorded alternative, not as a live choice.

## The conflict

`CLAUDE.md` and proposal §9 both specify:

> temperature 0 for gate/triage calls; fixed seeds where the API supports them

Neither mechanism is available on the models this project would otherwise use.

| Mechanism | Status on current Anthropic models |
|---|---|
| `temperature` / `top_p` / `top_k` | **Removed.** Opus 4.7+, Sonnet 5, and Fable 5 reject any value with HTTP 400. |
| Seed parameter | **Never existed** on the Messages API, on any model. |

The proposal's "where the API supports them" hedge is correct and anticipates this.
`CLAUDE.md`'s flat "fixed seeds" does not, which is why this file exists.

Models that still accept `temperature`: Sonnet 4.6, Opus 4.6, Sonnet 4.5, Haiku 4.5,
and older. Choosing one of those is the only way to keep the literal wording.

## Why this is less damaging than it looks

**`temperature=0` never guaranteed identical outputs**, even on models that accepted
it. It narrows the sampling distribution; it does not make inference reproducible.
Any experimental design that relied on it for byte-identical replay was relying on
something that did not hold.

The design already carries the mechanisms that *do* deliver reproducibility, and it
carries them as requirements rather than conveniences:

1. **Response caching** keyed by `(prompt_hash, replication)` — BUILD_PLAN 1.4. The hash
   covers model and params; the replication keeps seeds independent, since the API takes no
   seed and every seed otherwise sends an identical request.
   `CLAUDE.md` calls this "required for deterministic replay across the A/B/C
   conditions, not optional."
2. **Trace replay** — BUILD_PLAN 1.3. Conditions A / B / C consume pre-recorded
   diffs, never live model calls, so all three see byte-identical inputs by
   construction.

Condition comparison — the thing RQ1 actually rests on — is guaranteed by (2)
regardless of sampling settings. Determinism was always going to come from replay.

## Options

### Option A — current models, no sampling parameters ✅ **chosen**

- `claude-opus-5` primary, `claude-haiku-4-5` for the §9 small-model ablation.
  *(The primary model was later changed to `claude-opus-4-8` — see `docs/MODEL_CHOICE.md`.
  That change leaves this decision intact: Opus 4.8 also rejects sampling parameters.)*
- `temperature` omitted entirely. `ModelConfig.temperature` stays `None`.
- Determinism from caching + replay, stated plainly in the methods section.
- Amend `CLAUDE.md` to describe the real mechanism.

**Cost:** the paper cannot claim "temperature 0". It must instead claim cached,
replayed traces — which is a stronger and more accurate claim.

### Option B — pin older models to keep the literal wording *(rejected)*

- `claude-sonnet-4-6` primary, `claude-haiku-4-5` ablation. Both accept `temperature`.
- Set `--temperature 0`; `ModelConfig` passes it through.
- Wording in `CLAUDE.md` and the proposal stands unchanged.

**Cost:** the study is run on a previous-generation code model, which weakens
external validity — the degradation phenomenon under study is a property of how
current models behave in refinement loops. It also buys reproducibility that,
as above, `temperature=0` does not actually provide.

## What "seed" means in this codebase

`RunConfig.seeds` labels **independent replications** of a prompt sequence. It is
not passed to any provider and does not make generation reproducible. Proposal §7.2
needs several replications per trace for confidence intervals and the paired
Wilcoxon tests, and that is exactly what the field provides.

This is recorded in the trace so the statistics can group by it. It is *not* a
reproducibility mechanism, and no part of the write-up should describe it as one.

## Decision

**Option A**, chosen 2026-07-28: take the accurate reproducibility story over the
familiar-sounding one, and run on the model generation the research question is
actually about.

### Consequences for the write-up

- The methods section claims **cached, replayed traces**, not "temperature 0". Say
  plainly that sampling parameters are unavailable on the models used and that
  condition comparison is guaranteed by replay instead.
- Threats to validity (§8, *internal validity*) currently lists "fixed decoding
  temperature" among the mitigations for LLM nondeterminism. That item needs
  replacing with the cache-and-replay mechanism when the proposal is next revised —
  the remaining mitigations there (deterministic replay, multiple seeds, response
  caching, paired tests) are unaffected and already carry the argument.
- Report the exact model identifiers (`claude-opus-4-8`, `claude-haiku-4-5`) and the
  effort level per run, since those now stand in for the sampling settings a reader
  would otherwise expect.
