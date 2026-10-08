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

**1.4** Add response caching keyed by `(prompt_hash, model, params)`. *As built: keyed by
`(prompt_hash, replication)` — the hash already covers model and params, and the replication must
be in the key or every seed is served the first seed's answer (see CLAUDE.md, tech stack).*

**Exit check:** you can run the harness twice on the same prompt set and get byte-identical
trace files (in replay mode).

---

## Phase M1.2 — Dataset v1 (Weeks 3–6)

**2.1** Select and record the seed repository set: 8–12 mid-sized open-source Python projects
(5k–50k LOC) under permissive licenses (MIT / Apache-2.0 / BSD). Record the license of each and
verify compliance **before** any trace is redistributed (proposal §6.1). Output a manifest file
(repo URL, commit pinned, LOC, license, verification date) — this is the input to 2.2.

*As built (2026-09-27): seed repos are the projects whose real injection-class CVE fixes supply the
ground truth (reading (A) of §6.1), so selection draws on advisory data rather than preceding it.
`scripts/build_seed_manifest.py` extracts injection advisories from the OSV PyPI export, screens
their repos by licence and size, and writes `data/seed_repos.json`: 12 selected repos holding 34
advisories (22 path traversal, 6 command, 6 SQL) plus 4 in reserve. LOC means non-blank `.py`
lines outside test/doc/example directories. Provisional until 2.3 validation.*

**2.2** Write a script to pull candidate CVE fix commits for injection-class vulnerabilities in
Python projects from CVEfixes (or equivalent public source). *As built: the advisory extraction is
done in 2.1 (`graphgate.dataset.advisories`, OSV source); 2.2 starts from the advisories and fix
commits listed in `data/seed_repos.json` and resolves each to a vulnerable/fixed commit pair with
the changed file paths.*

*As built (2026-09-28): `scripts/resolve_fix_pairs.py` (`graphgate.dataset.fix_pairs`) works in
blobless clones. Canonical fix = earliest linked commit on the default branch; vulnerable = its
first parent. It records changed files by kind and re-checks source LOC and licence **at the
vulnerable commit**, writing `data/fix_pairs.json` with every uncertainty as a flag. Two amendments
to the 2.1 manifest: parisneo/lollms was recreated in 2025, so its advisories resolve against
ParisNeo/lollms_legacy; and advisories linking no fix commit are kept for recovery (40 in the
selected repos, 34 linked).*

*Every pair then went through an independent review workflow: one reviewer establishing the link,
one instructed to refute it, plus a history search for unlinked advisories
(`scripts/prepare_fix_review.py` stages the inputs; `scripts/apply_fix_review.py` writes
`data/fix_review.json` with every verdict and a source/sink/scope pre-screen for 2.3). Of 40
items: 30 confirmed, 4 contested, 4 needs-human, 1 rejected, 1 not recovered. Each non-confirmed
case was read by hand:*
- *The earliest-commit rule was wrong 4 times, and both reviewers named the same alternative.
  These are corrected in `data/fix_pair_corrections.json` after re-checking the git facts:
  - GHSA-8prr: the advisory also links the commit that introduced the bug.
  - GHSA-hg4c: only backports are linked.
  - GHSA-cwvm and GHSA-2f96: multi-part fixes.*
- *Recovered with both reviewers confirming: GHSA-7545, -rpm5, -v396 and -9ffm
  (`data/recovered_fix_commits.json`).*
- *Contested means the link is right but the fix was incomplete, with a later commit or advisory
  closing a bypass. These pairs are kept.*
- *Not paired:*
  - *GHSA-79h8: the only candidate adds a bypassable sanitizer.*
  - *GHSA-9chm: the vulnerable code is in xtts-api-server, not lollms.*

*Result: 35 candidate pairs in the selected repos. By reviewed class: 22 path traversal, 7 command
(6 CWE-78, 1 CWE-77) and 6 SQL. The reviewers' scope pre-screen: 25 cross-file, 7 local, 3 split.*
- *datadog/guarddog drops out: 1.2k–4.2k source LOC at its vulnerable commits.*
- *Usable reserve is 2 SQL pairs (geopandas, parsl). copier is under 5k LOC, and mocodo's fix is
  PHP. The resolver now flags a fix that changes more non-Python code than Python.*

*Open for 2.3:*
- *The contested fixes: confirm the fixed side is actually fixed. GHSA-9mv7's refuter thinks the
  fix never runs on the CLI `--pdf` path.*
- *GHSA-pwc9 is filed as CWE-77 but is path traversal to code loading.*
- *GHSA-p8h7 and GHSA-vqwr share one fix commit, so they are one pair.*
- *GHSA-2f96 and GHSA-v396 are consecutive, disjoint pairs from one PR.*
- *The lollms advisories appear in the public SM-100 benchmark (threat to validity).*
> Prompt: *"Write a script that queries [CVEfixes/public source] for Python CVE fix commits
> tagged with injection-class CWEs (CWE-89, CWE-78, CWE-22), and outputs candidate
> vulnerable-commit / fixed-commit pairs with repo URL and file paths."*

**2.3** Manual validation pass: for each candidate, confirm the fix is genuinely injection-class,
extract the minimal vulnerable/fixed function pair, and record whether it's local (single-file)
or cross-file (fix touches a caller/callee in another file). Target 25–30 validated events for M1.
Strip security-revealing comments from the extracted code — fix commits routinely carry lines
like `# fix CVE-2023-…: sanitize input`, and the model sees every file verbatim (CLAUDE.md, "No
research framing in model-visible code").

*As built (closed 2026-10-06 with the owner's sign-off). Three decisions were taken with the owner on
2026-09-28 and are recorded in CLAUDE.md: events are trimmed slices at real paths; AI agents
prepare dossiers but only the owner's sign-off validates; local/cross-file follows a
pre-registered rule.*
- *Tooling: `graphgate.dataset.slicing` (tree-sitter trimming that reports every referenced name
  it cut, with an opt-in `<wiring>` marker for module-level glue), `graphgate.dataset.scrub`
  (strips and logs comments that reveal the fix), `graphgate.dataset.events` (spec, scope rule,
  dossier builder with checks). `scripts/build_event.py` builds a dossier from `spec.json`.*
- *AI preparation over the 34 events (`scripts/prepare_validation.py`, then a workflow of one
  analyst and one adversarial checker per event, with one fix round on blocking defects;
  `scripts/save_ai_review.py` writes `data/validation_ai_review.json`): 31 passed the check, with
  the checker agreeing on class and scope in all 31 — 25 cross-file and 6 local; 19 path
  traversal, 7 command, 5 SQL.*
- *Excluded: xml2rfc-9mv7 (analyst and reviewer both found the published fix ineffective on the
  CLI `--pdf` path) and nicegui-9ffm (the slicer could not keep the module-level block wiring its
  sink; `<wiring>` now can, so it may be retried). alerta-8prr was rebuilt with `<wiring>` after
  the same limitation and still needs an independent re-check
  (`data/validation_followups.json`).*
- *Sign-off: `scripts/build_signoff_page.py` builds the review page; decisions are stored per
  event with the dossier version they were made on. The owner decided all 34 on 2026-10-05, every
  one on the current dossier: **30 accepted, 2 rejected, 2 sent back for revision**.
  `scripts/save_signoff.py` writes `data/validation_signoff.json` from the page's exported
  decisions.*
- *The 30 validated events (M1 target 25–30): 24 cross-file and 6 local. By class: 18 path
  traversal (13 cross-file), 7 command (all cross-file), 5 SQL (4 cross-file). They come from 10
  repositories; GitPython supplies 12 and lollms 6.*
- *Not accepted: nicegui-9ffm (rejected) and xml2rfc-9mv7 (revise) are the two excluded during
  preparation. xml2rfc-432c was rejected and alerta-8prr sent back; the notes saved with these two
  quote first-round check defects that the current dossiers no longer have (432c was re-modelled
  on the xi:include flow and passed its re-check; 8prr has its grammar wiring back in both
  variants). Both stay out unless the owner decides again on the page.*

*Open after the sign-off:*
- *Seven of the 30 validated events rest on known-incomplete fixes; each dossier extracts a flow
  the fix does close and says so.*
- *In GitPython every command runs through `Git.execute` in `git/cmd.py`, so 10 of its 12 events
  are cross-file by rule even when the visible change is in one method. Report per repository.*
- *Library events take a caller's argument as their source (`library-api`); the graph's source
  model in M2.1 must cover that or R2/R4 cannot fire on them.*
- *The checkers listed real-code wording the scrubber leaves in place (for example GitPython's
  "unsafe options"); the owner decides per event whether that is acceptable.*

**2.4** Build the trace-synthesis tool: given a validated vulnerable/fixed pair, generate a 5–8
turn refinement trace (using the ISTAS-2025-style prompts: "improve readability", "add feature
X", "optimize") with the regression injected at a randomized turn.
> Prompt: *"Build a trace synthesizer: given a code snippet and its known-vulnerable variant,
> generate a 5-8 turn refinement trace using these prompt templates [...], injecting the
> vulnerable variant at a randomized turn between 2 and 6."*

*As built (2026-10-04; tool finished, no dataset trace recorded yet). Decided with the owner: the
regression is **bundled with a model turn**. At the chosen turn the model makes its own change and
the regression is then placed in the code it produced, so that turn's diff holds both.*
- *Plan (`graphgate.dataset.traceplan`): turn count (5–8), the instructions and the injection turn
  (2–6) come from a generator seeded with `plan_seed:event_id`. Every replication of an event
  follows one plan; replications differ only in what the model writes. Instructions are drawn
  without repetition from `data/refinement_prompts.txt` (10 neutral, ISTAS-style requests).*
- *Injection (`graphgate.harness.injection`): a file the model has not touched is swapped for its
  regressed version; a file it has changed gets the regression merged unit by unit (functions,
  class attributes, imports, statements), keeping the model's other edits. If a changed function
  can no longer be found by name the injection **fails**: recorded as such, and the replication
  ends. Checked against every real dossier: of the 39 changed files the merge reproduces 35
  byte-for-byte and 4 up to blank lines.*
- *Trace schema v5 adds `injection`: the plan on each init record, the outcome on the injected
  turn. It is ground truth and is never shown to the model or to a gate. Replay re-applies it
  through the same driver, so injected traces replay byte-for-byte; v4 traces still replay as v4.*
- *`scripts/synthesize_traces.py` records the traces (one file per event, all replications) and a
  `manifest.json` with each replication's outcome. Dataset traces come only from events accepted
  in `data/validation_signoff.json` on the current dossier, and go to `data/traces/`. `--pilot`
  also takes AI-prepared events and writes to `runs/pilot-traces/`; those test the tool and are
  not dataset traces. `--dry-run` prints the plan and a rough cost and sends nothing.*
- *Found on the way and fixed: a reply cut off at `max_tokens` used to be half-applied (the
  unfinished file block dropped, the finished ones kept). It is now recorded as an error.*

*Open:*
- *Nothing has been run live. Dry-run estimate for the 31 AI-prepared events at 3 seeds: 621
  calls, roughly $75–127 on Opus 4.8. Run the three-event pilot in `HOW_TO_RUN.md` first (21
  calls, roughly $2–3).*
- *For 2.5: a later turn may undo the regression (the model can put a guard back), so a label
  cannot assume the regression persists after the injection turn — check each turn.*
- *xml2rfc-cfmv is large enough that a turn rewriting every file may pass 16k output tokens.*
- *The refusal rule (a refusal ends the replication) is to be revisited here once the pilot shows
  how often it happens.*

*Change of model (2026-10-07). The guide ruled out commercial models, so traces will be recorded
with an open-weight model in a free cloud GPU notebook, not with Claude:
`graphgate.llm.openai_compat` (any chat-completions server), `--provider`/`--base-url` on the run
scripts, `scripts/make_notebook_bundle.py` and `notebooks/record_traces_open_model.ipynb`. Built
and unit-tested; no open model has been run yet. Open: whether a 14-billion-parameter model
returns whole files reliably for the larger slices, and whether 603 calls fit the notebook's
weekly GPU hours; the pilot answers both, and fewer replications or a smaller model are the
fallbacks. The Opus cost estimates above no longer apply.*

*First notebook runs (2026-10-07/08). Pilot: 3 events, 21 calls, no failures; 14 of 21 turns
`carried`. First dataset session: 10.5 hours, 13 events finished and a 14th started, about 50
minutes per event. It kept nothing, for two reasons, both now fixed. (1) The client sent the
replication number as the sampler seed, and under seed 1 the model's reply broke the output
format in every event (14 of 14; never under seeds 0 and 2): a fixed seed reuses one random
stream for every request, and that stream's first draw lands in the tail. Replications are
therefore 0, 2 and 3. (2) The script discarded any trace containing an error, which was meant
for failed API calls; an unusable reply is the model's outcome and now stays in the trace. The
responses of that session are in the cache, so replications 0 and 2 of those events are not
recorded again. Also seen: 4 of 26 replications lost the regression to a failed injection.*

**2.5** Label every turn `{clean, local_regression, cross_file_regression}` and store alongside
the trace.

*As built (2026-10-04; tool finished, no real trace labelled yet). `graphgate.dataset.labels`,
run by `scripts/label_traces.py`, writes `<event_id>.labels.json` next to each trace.*
- *A label describes the code **after** the turn: is the event's regression in it. The turn that
  brings it in is marked `introduced`. Both are needed by §7.2: recall and false positives need
  to know which turns are clean, iterations-to-detection needs to know how long the regression
  survived. The regression's label comes from the event's scope (2.3).*
- *The label is read off the recorded code, not assumed from the plan. The regression is the set
  of units (functions, assignments, imports) that differ between the event's clean and regressed
  files. After each turn they are compared with both versions, ignoring comments, docstrings and
  layout: all match the regressed version → regression; all match the clean version → clean.*
- *If the model has rewritten one of those units, neither matches. The label is then carried from
  the previous turn and the turn is marked `carried`. Whether a rewritten regression still holds
  is a security judgement the tool does not make.*
- *The same check runs before the injection, so a turn where the model itself edits the guard is
  marked `carried` too instead of being counted as verified clean.*
- *Cross-checks: the turn the trace records as injected must hold the regressed code, or labelling
  stops; labels store the trace's hash and are refused for any other version of it. The rule
  tells clean from regressed on all 33 built events.*

*Open:*
- *How many turns come out `carried` is unknown until the pilot. If it is many, they need a
  review pass (same pattern as 2.3: AI-prepared, owner decides) or a rule for leaving them out.*
- *Scope of the claim: labels cover the event's regression only. A weakness the model introduces
  by itself elsewhere is not labelled (the §6.2 holdout covers natural regressions), and a match
  means the regressed code is unchanged, not that nothing else on the flow compensates.*
- *How a BLOCK on a later turn of a surviving regression is scored (late detection, not a false
  positive) is fixed in M1.3 when the gate conditions are scored; the labels support either.*

**2.6** Leakage control (proposal §6.3): verify that each injected vulnerable pattern does not
already appear elsewhere in its repository; where duplicates exist, exclude them from the graph's
retrieval scope during evaluation. Log every exclusion — this has to be reportable.
> Prompt: *"Write a leakage check that, for each injected vulnerable pattern, scans the rest of
> the seed repository for near-duplicate occurrences and emits an exclusion list consumed by the
> retrieval layer."*

*As built (2026-10-06). `graphgate.dataset.leakage`, run by `scripts/check_leakage.py`, scans each
validated event's repository at its clean commit, outside the slice's own files, and writes
`data/leakage_exclusions.json`. It reads the local clones only: a file a clone lacks is an error,
never a download.*
- *Near-duplicates (the proposal's rule). Every function or assignment the regression changes,
  adds or removes is compared, in its clean and its regressed version, with every function or
  assignment elsewhere. Similarity is the share of code tokens in common, in order, with
  comments, docstrings and layout removed; 0.8 or more is a near-duplicate. Both versions are
  compared because a guarded twin gives the regression away as surely as a vulnerable copy.*
- *Tests the fix changed (added here; not named in §6.3). They were written to pin down the guard
  the regression removes, so they describe the answer. Owner may veto this rule; it is one
  reason code (`test-changed-by-fix`) in the list.*
- *Result over the 30 validated events: 35 exclusions in 20 events. 3 are near-duplicates, all in
  piccolo-xq59, whose SQLite engine holds exact copies of the three fixed Postgres functions. 32
  are test files changed by a fix. Every other regression unit's closest match elsewhere scores
  0.58 or less, so the threshold separates cleanly.*
- *Units under 30 tokens are listed as not compared (9 of 74: option lists, a logger, two small
  helpers). 20 was tried first; a 25-token one-statement method then matched an unrelated one at
  exactly 0.80, so the minimum was set to 30 before anything was run against a gate.*

*Open:*
- *11 source files a fix changed outside its slice are listed but left in scope. Six are imported
  by their slice (in lollms-m45c one defines the sanitizer the slice calls), so hiding them would
  remove the cross-file context the study is about. The other five are siblings given the same
  fix (for example pycsw's `csw3.py`, 0.56 similar to the regression). Decide at M2.1 whether
  siblings stay visible.*
- *Whether the graph covers test directories at all is an M2.1 decision. If it does not, the
  test rule is moot and harmless.*
- *Identifiers are compared as written, so a copy with every name changed is not detected.*

**Exit check:** 25–30 labeled traces on disk, each replayable via the M1.1 harness, with a seed-repo
license manifest and a leakage-exclusion list alongside them.

---

## Phase M1.3 — Local gate (B) + Pysa baseline (S1) (Weeks 6–9)

**3.1** Wrap Semgrep and Bandit to run on a diff and return structured findings.

*As built (2026-10-06). `graphgate.gate` holds the first stage of every gate condition; two
choices were made with the owner (tools in their own environment; pinned community rules).*
- *Tools: Semgrep 1.179.0 and Bandit 1.9.4, installed in `.venv-tools` from
  `requirements-analysers.txt` and called as external programs. Semgrep brings about 70 packages;
  kept apart, they cannot change the versions the project pins. Both run natively on Windows.*
- *Rules: the public community rules (github.com/semgrep/semgrep-rules) at commit `a84ff9cc`
  (2026-09-22), cut down to the Python rules that declare CWE-22, 77, 78 or 89: 63 rule files (33
  command, 25 SQL, 5 path traversal, none for CWE-77). Two rules that flag user input in an SQL
  string are filed upstream under CWE-704 and CWE-915; they are counted as CWE-89 and marked.
  `scripts/fetch_semgrep_rules.py` downloads and selects; `data/semgrep_rules.json` pins every
  selected file by hash, and a scan refuses a rule directory that does not match. The rule files
  stay in the ignored `data/raw` because their licence restricts redistribution.*
- *Findings: both tools' reports become one record (tool, rule, CWEs, severity, file, lines,
  code), and only family CWEs are kept; the family is a parameter. Bandit's own CWE mapping
  decides what is in, which includes broad checks such as B404 (`import subprocess`).*
- *"On a diff": the files a turn changed are scanned before and after it. A finding is
  **introduced** when nothing with the same tool, rule, file and code (whitespace aside) was there
  before, so a finding that only moved is not new.*
- *Speed: Semgrep takes about ten seconds to start however little it scans, so every new file
  version goes into one run and results are kept by content, in memory and in
  `runs/analysis-cache.sqlite`. All file versions of the 30 events take one run of each tool,
  about 20 seconds.*
- *Nothing is skipped quietly: Semgrep's default ignore list, which drops `tests/` directories, is
  replaced; a file a tool did not analyse is an error; a file that does not parse is reported
  with each tool's message. The tools run offline: metrics and version check off, local rules,
  settings and log in the scan's own temporary directory.*

*First look, not a gate result (`scripts/scan_events.py`, saved in
`data/static_first_look.json`): taking each validated event's regression as one change, only **1 of 30** introduces a family finding (wsgidav-p6gw, the local
SQL event). Elsewhere the tools report the same findings before and after, or none at all. In
piccolo-xq59 the f-string SQL is flagged either way, because the fix validates the name
beforehand and leaves the flagged line alone. 18 of the 30 events are path traversal, for which
the rule set has five framework-specific rules and Bandit has no check.*

*Open:*
- *For 3.2: whether triage sees every turn's diff or only turns with an introduced finding. With
  the second, Condition B could catch about one regression in thirty before triage even starts,
  so this choice largely decides how strong B is. It must be fixed before B is run.*
- *For 3.3: Pysa has no Windows build, and this machine has neither WSL nor Docker. It needs
  WSL (the owner installs it; admin rights and a restart) or a Linux runner such as GitHub
  Actions on the project's repository.*

**3.2** Build the LLM triage step for the local-only gate: given a diff + static-analysis
findings (no graph context), classify ALLOW / BLOCK and produce a rationale.
> Prompt: *"Implement Condition B: the local-only gate. Input is a diff + Semgrep/Bandit
> findings. Output is a structured decision {ALLOW, BLOCK} with a short rationale. Use temperature
> 0 and cache responses per CLAUDE.md conventions."*

*As built (2026-10-06; tested against a stand-in model, not yet run against the real one).*
- *Decided with the owner: **two diff-only conditions, reported separately.** B is the planned
  one: the LLM triages what Semgrep and Bandit flag, and a change with nothing flagged is allowed
  without a call. **B+** is added: the LLM also judges every change as a whole. The scanners
  flagged 1 of the 30 regressions (3.1), so B alone would be an almost silent baseline; B+ is the
  strong diff-only check GraphGate also has to be measured against. B+ is a baseline only: in
  GraphGate the LLM still triages flags and nothing else. The registered criterion (C against B)
  is unchanged; C against B+ is reported next to it.*
- *`graphgate.gate.triage`: the model gets the diff and a numbered list of items, each either
  flagged code (findings on one piece of code are grouped into one item) or, in B+ only, the
  change as a whole. It labels each item exploitable-regression, benign-refactor or uncertain,
  with a rationale, as one JSON object. A reply that misses an item, adds one or uses another
  label is an error, never a guess.*
- *One system prompt for every condition, version 1, fixed before any live call and pinned by
  hash in a test. It says nothing about which context a condition has, so Condition C can use the
  same text and differ only in what the user message adds.*
- *`graphgate.gate.local.LocalGate`: BLOCK if any item is an exploitable regression. "uncertain"
  does not block; the label is recorded, so the stricter reading can be computed afterwards. A
  refusal, a failed call or an unusable reply never blocks either and is recorded as its own
  outcome (the gate fails open, visibly).*
- *What the gate is shown: the diff and the items. Not the refinement instruction: the injected
  regression has nothing to do with the instruction by construction, so showing it would make
  the regression stand out for a reason no real change shares. No trace id, event id or label.*
- *`scripts/triage_events.py` is a pilot on each event's regression and, as a control, its
  reverse (the fix): 62 calls, roughly $1-3 on Opus 4.8. `--dry-run` and `--show-prompt` send
  nothing. It is not the study's result; that needs the recorded traces (3.4).*

*Open for 3.4:*
- *Latency. Semgrep alone takes about ten seconds to start on this machine, which is already at
  the registered limit (median added latency under about 10 s per iteration), for B and C alike.
  The runner must time each turn's scan on its own, not read it off the batched run.*
- *What a BLOCK means when a trace is replayed: later turns were recorded as if the change had
  been accepted. The labels support either reading; the scoring rule must be fixed before the run.*
- *If the pilot shows many `error` outcomes from the reply format, fix the protocol and raise the
  prompt version before any condition is run on traces.*

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
- **Refusal rate** — share of turns the code-generation model declined, broken down by refusal
  category. A refused turn ends its replication, so traces that were cut short must be visible
  next to the degradation curve rather than silently missing from it (CLAUDE.md, "Refusals").

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

*As built (2026-10-08). `graphgate.graph`, steps 4.1 to 4.5 together; 73 tests. The exit check is
met: the rules pass on hand-built graphs, and the builder ran on all 12 selected seed
repositories (`scripts/build_graph.py --check`, saved in `data/graph_build_check.json`): 1,673
files, 16,625 symbols, 69,722 calls, of which 24,464 (35.1%) could not be resolved and are
unknown edges; no file failed to parse. A full build takes 0.3 to 2.4 seconds per repository and
under a second after one file changes.*
- *Two stages. `extract` turns one file into plain facts with tree-sitter and looks at no other
  file; `link` turns the facts of all files into the graph. Facts are stored per file by content
  hash (`index`, SQLite), so a turn re-parses only the files it changed (4.4). Linking is redone
  over all facts each time, because a change in one file can change how a call in another
  resolves; the stored graph therefore equals a build from scratch, and a test checks it.*
- *Nodes (4.1): modules, classes, functions and methods, named `path::qualname` as the events
  name them. Taint does not run between whole functions: each symbol has ports for its
  parameters, its return value, attributes set through `self` and module-level names, and taint
  edges join ports. This is finer than "symbols" in the proposal's definition of V and was needed
  for the rules to mean anything: with one node per function, every caller and callee are joined
  both ways and a source reaches a sink almost everywhere.*
- *Calls (4.2): the three rules of CLAUDE.md. "Statically inferable receiver" means `self`, a
  class name, `super()`, a variable or attribute assigned from one constructor, or an annotated
  parameter. Everything else is an explicit `unknown::` edge, counted per file.*
- *Taint (4.3): inside a symbol the origins of every name are solved to a fixed point, ignoring
  order and branches. A call into code the graph cannot see passes on what went into it. Not
  followed, as the proposal's limits say: closures, properties, computed attribute names,
  decorators that replace a function.*
- *Sources, sinks, sanitizers (4.3): `graphgate.graph.catalog`, seeded from the pinned Semgrep
  injection rules and the Pysa source and sink families, the injection family only. A project's
  own validation functions are recognised by a word of their name (sanitize, escape, quote,
  validate, verify, check, secure, safe, valid). The list was fixed before the rules were run on
  any event.*
- *Rules (4.5), `graphgate.graph.delta`, one function each, with the reading of each rule fixed in
  the module's docstring. R2 and R4 work on (source, sink) pairs and never fire on the same pair:
  R2 when a pair is newly joined by a sanitizer-free path, R4 when a joined pair's shortest such
  path loses an edge. R1 fires when a sanitizer node is gone, or when a caller routes a value
  around it. R3 fires when a sanitize edge is gone from a symbol that is on a source-to-sink path
  or guards one. The rules see the graphs within 2 symbols of what changed (`hops`, the ablation
  variable).*

*Two settings widen two definitions of the proposal. **Decided with the owner on 2026-10-08,
before the rules were run on any event: Condition C uses both** (`link.GRAPHGATE`); all four
combinations are run and reported side by side as an ablation (`link.SETTINGS`), and the
registered C-versus-B comparison uses the chosen one only.*
- *`public_api_sources`: the parameters of a library's public functions count as sources. The
  proposal lists request parameters, environment, file and network input and command-line
  arguments. Most seed repositories are libraries; the events accepted at sign-off name a
  "library-api" entry for them, which none of those source kinds covers.*
- *`structural_guards`: an `if` that raises or exits, or an `assert`, whose test looks at a value
  counts as a guard edge. The proposal's E_sanitize is an allowlist of named functions. A
  validation function that is weakened from inside keeps its name and its callers, so without
  this the graph before and after is the same.*

*First look, not a gate result (`scripts/delta_events.py`, saved in `data/delta_first_look.json`;
run on 2026-10-08 after the settings were fixed, and the rules were not changed afterwards):
taking each validated event's regression as one change on its slice, the rules flag **8 of 30**
under Condition C's settings (5 of 24 cross-file, 3 of 6 local), against 1 of 30 for the
scanners. R1 fires on 7 events, R3 on 5, R2 on 2, R4 on 1. The proposal's literal settings flag
7 (4 cross-file). Depth: 7 at one hop, 8 at two, 9 at three or with no bound.*
- *Control: on the reverse change, the fix, the rules fire on 4 of 30 (R2 on 2, R3 on 2), and on
  none under the literal settings. So the two widened settings bought one more regression and
  four flagged fixes; triage has to tell those apart.*
- *Why 22 are missed, read off the graphs: 27 of the 30 regressions change at least one edge, so
  the difference is rarely empty, but the change is usually a test or an expression weakened
  inside a function, which removes no sanitizer and opens no path. In 8 slice graphs there is no
  source-to-sink path at all, 5 of them with no sink: the slice cuts the sink function away, or
  the sink is reached through dynamic dispatch (GitPython's `repo.git.<command>` goes through
  `__getattr__`, an unknown edge). These are the rule-coverage and dynamic-feature gaps the
  proposal's error analysis names.*
- *What it does not say: how often the rules fire on a model's harmless turns. That needs the
  recorded traces.*

*Open:*
- *For 5.2: the first look ran on slices. Laying the repository around a slice does not bring
  back a function that was cut out of a slice file, and for several events that function is the
  sink. How Condition C sees cut code has to be decided before C is run, and not by looking at
  which events it would rescue.*
- *Pysa's stub files were not on this machine when the catalog was written. Check the entries
  against the pinned stubs when Pysa is set up (3.3).*
- *The per-repository sanitizer extension the proposal allows (`Catalog.extended`) is unused. It
  is bound by the repository-level holdout (5.4) and must not be filled from the events.*
- *35% of calls are unknown edges, mostly methods called on values whose class the code does not
  state (strings, lists, loggers). A breakdown by form belongs in the error analysis (6.4).*
- *The ablations "call graph only" and "taint edges only" (6.2) need the path rules to run over
  call edges; not built.*
- *For 5.2: the leakage exclusions go in through `link(..., exclude=...)`; nothing calls it for
  the events yet.*

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
