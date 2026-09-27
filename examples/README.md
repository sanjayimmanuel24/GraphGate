# examples/

Fixtures for exercising the harness end to end against the live API. **Not** part of the
dataset — the real seed repositories come from BUILD_PLAN step 2.1.

| Path | What it is |
|---|---|
| `smoke/` | A one-file starting snapshot: a small user-lookup module using a parameterised query |
| `smoke_prompts.txt` | Three ISTAS-2025-style refinement instructions |

## Why this note lives here and not in the code

The harness sends the **entire snapshot verbatim** to the code-generation model on every turn.
Anything written in these files — docstrings, comments, names — becomes part of the prompt.

The first smoke fixture had a docstring describing it as a test for whether refinement
"introduces regressions". The model responded to that framing: its rewrites filled up with
unrequested security commentary, and the third turn was declined by the safety classifier.
The fixture was measuring its own description rather than the model's refinement behaviour.

So the files the model sees must read as ordinary code. Explanations like this one belong
in files the harness never sends — this README, or comment lines in `smoke_prompts.txt`,
which are stripped before the instructions are used. See CLAUDE.md, "No research framing
in model-visible code".

## Running it

```powershell
graphgate-harness --snapshot examples/smoke --prompts examples/smoke_prompts.txt --out runs/smoke-02.jsonl --trace-id smoke-02 --seeds 0 --cache .graphgate_cache/responses.sqlite
```

Requires `ANTHROPIC_API_KEY` in the environment. Costs a few cents.
