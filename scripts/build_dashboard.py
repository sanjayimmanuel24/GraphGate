"""Build the GraphGate project dashboard from the project's data files.

    python scripts/build_dashboard.py            # writes dashboard/index.html
    python scripts/build_dashboard.py --run-tests  # also runs the test suite for the tile

The page is a single self-contained HTML file (charts are inline SVG), so it
opens offline in any browser. Every number on it is read from the repository:
the seed manifest, the fix pairs and their review, the event dossiers and the
AI review of BUILD_PLAN 2.3, and the smoke-run evidence.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboard"

# Milestones from BUILD_PLAN.md; status is kept here because it is project
# management state, not something the data files record.
MILESTONES = [
    ("M1.1", "Refinement harness and trace replay", [
        ("1.1", "Project scaffold", "done"), ("1.2", "Refinement-loop driver", "done"),
        ("1.3", "Deterministic replay", "done"), ("1.4", "Response caching", "done")]),
    ("M1.2", "Dataset v1", [
        ("2.1", "Seed repository selection", "done"), ("2.2", "Fix commits to vulnerable/fixed pairs", "done"),
        ("2.3", "Validation of events", "active"), ("2.4", "Trace synthesis", "todo"),
        ("2.5", "Turn labels", "todo"), ("2.6", "Leakage control", "todo")]),
    ("M1.3", "Local gate (B) and Pysa baseline (S1)", [("3.1-3.4", "Gate B, Pysa, A/B/S1 run", "todo")]),
    ("M2.1", "Graph layer and difference engine", [("4.1-4.5", "Graph builder, rules R1-R4", "todo")]),
    ("M2.2", "Dataset v2, Condition C, holdout", [("5.1-5.4", "Cross-file variants, gate C, holdouts", "todo")]),
    ("M2.3", "Full study, ablations, writing", [("6.1-6.5", "Study, statistics, paper", "todo")]),
]

SMOKE = [  # docs/MODEL_CHOICE.md, from the archived traces in docs/evidence/2026-09-27-smoke/
    ("claude-opus-5", "none", "every run", "0", "declined"),
    ("claude-opus-5-5", "5 of 7", "2", "1 of 3", "declined"),
    ("claude-opus-4-8", "18 of 18", "0", "6 of 6", "chosen"),
    ("claude-haiku-4-5", "18 of 18", "0", "6 of 6", "ablation"),
]

LOC_MIN, LOC_MAX = 5_000, 50_000
EXCLUDED_BY_HAND = {"GHSA-j6cv-98jx-mrwr"}
CLASS_NAMES = {"path-traversal": "Path traversal", "os-command": "OS command", "command": "Command",
               "sql": "SQL"}


def load(rel: str):
    path = ROOT / rel
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def tests(run: bool) -> tuple[int, str]:
    args = [sys.executable, "-m", "pytest", "-q"] + ([] if run else ["--collect-only"])
    done = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if run:
        m = re.search(r"(\d+) passed", done.stdout)
        failed = re.search(r"(\d+) failed", done.stdout)
        return (int(m[1]) if m else 0), ("failing" if failed else "passing")
    m = re.search(r"(\d+) tests? collected", done.stdout)
    return (int(m[1]) if m else 0), "collected"


def gather(run_tests: bool) -> dict:
    manifest = load("data/seed_repos.json")
    funnel = manifest["source"]["funnel"]
    selected = [r for r in manifest["repos"] if r["role"] == "selected"]
    pairs = load("data/fix_pairs.json")["events"]
    review = load("data/fix_review.json")
    ai = {r["event_id"]: r for r in (load("data/validation_ai_review.json") or {"results": []})["results"]}
    signoff = (load("data/validation_signoff.json") or {"decisions": {}})["decisions"]

    candidates = [e for e in pairs
                  if e["role"] == "selected" and e["vulnerable_commit"]
                  and e["advisory"] not in EXCLUDED_BY_HAND
                  and LOC_MIN <= ((e.get("loc_at_vulnerable") or {}).get("source") or 0) <= LOC_MAX]
    groups: dict[tuple, list] = {}
    for e in candidates:
        groups.setdefault((e["repo"], e["fix_commit"], e["vulnerable_commit"]), []).append(e)

    events = []
    for (repo, fix, vuln), members in groups.items():
        members.sort(key=lambda m: m["advisory"])
        eid = f"{repo.split('/')[1].removesuffix('_legacy')}-{members[0]['advisory'].split('-')[1]}"
        r = ai.get(eid, {})
        a = r.get("fix") or r.get("analyst") or {}
        event_json = load(f"data/events/{eid}/event.json") or {}
        events.append({
            "id": eid, "repo": repo, "advisories": [m["advisory"] for m in members],
            "class": a.get("vulnerability_class") or members[0]["classes"][0],
            "scope": event_json.get("scope") if a.get("verdict") != "exclude" else None,
            "ai": r.get("status", "pending"),
            "signoff": (signoff.get(eid) or {}).get("decision"),
            "tokens": (event_json.get("totals") or {}).get("clean", {}).get("approx_tokens"),
            "note": (a.get("exclusion_reason") or "")[:220],
        })
    n_tests, test_state = tests(run_tests)
    return {
        "generated": dt.datetime.now().strftime("%d %B %Y, %H:%M"),
        "funnel": [
            ("Injection-class advisories (PyPI, GHSA)", funnel["injection_advisories"]),
            ("with a linked fix commit", funnel["usable_with_fix_commit"]),
            ("in the selected seed repositories", sum(len(r["advisories"]) for r in selected)),
            ("verified candidate pairs", len(candidates)),
            ("candidate events", len(events)),
            ("prepared and passed the AI check", sum(e["ai"] in ("sound", "sound-after-fix") for e in events)),
            ("signed off by the authors", sum(e["signoff"] == "accept" for e in events)),
        ],
        "repos": [(r["repo"], r["licence"], len(r["advisories"])) for r in
                  sorted(selected, key=lambda r: (-len(r["advisories"]), r["repo"]))],
        "reserve": sum(r["role"] == "reserve" for r in manifest["repos"]),
        "review": review["tally"],
        "events": sorted(events, key=lambda e: e["id"]),
        "tests": (n_tests, test_state),
    }


# --------------------------------------------------------------------------

def esc(s) -> str:
    return html.escape(str(s))


def bar_svg(rows: list[tuple[str, int]]) -> str:
    import math
    width, label_w, bar_h, gap = 560, 250, 22, 10
    top = max(v for _, v in rows) or 1
    height = len(rows) * (bar_h + gap)
    out = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Dataset funnel" class="chart">']
    for i, (label, v) in enumerate(rows):
        y = i * (bar_h + gap)
        w = 0 if v <= 0 else max(3, (math.log10(v + 1) / math.log10(top + 1)) * (width - label_w - 50))
        out.append(f'<text x="{label_w - 10}" y="{y + bar_h * 0.68}" text-anchor="end" class="lbl">{esc(label)}</text>')
        out.append(f'<rect x="{label_w}" y="{y}" width="{w:.1f}" height="{bar_h}" rx="3" class="bar{" last" if i == len(rows) - 1 else ""}"/>')
        out.append(f'<text x="{label_w + w + 8:.1f}" y="{y + bar_h * 0.68}" class="val">{v}</text>')
    out.append("</svg>")
    return "".join(out)


def stacked_svg(counts: dict[str, tuple[int, int, int]]) -> str:
    width, label_w, bar_h, gap = 560, 130, 22, 12
    total_max = max((sum(v) for v in counts.values()), default=1) or 1
    height = len(counts) * (bar_h + gap)
    scale = (width - label_w - 60) / total_max
    out = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Events by class and scope" class="chart">']
    for i, (cls, (cross, local, other)) in enumerate(counts.items()):
        y, x = i * (bar_h + gap), label_w
        out.append(f'<text x="{label_w - 10}" y="{y + bar_h * 0.68}" text-anchor="end" class="lbl">{esc(CLASS_NAMES.get(cls, cls))}</text>')
        for value, klass in ((cross, "seg-cross"), (local, "seg-local"), (other, "seg-other")):
            if value:
                out.append(f'<rect x="{x:.1f}" y="{y}" width="{value * scale:.1f}" height="{bar_h}" class="{klass}"/>')
                x += value * scale
        out.append(f'<text x="{x + 8:.1f}" y="{y + bar_h * 0.68}" class="val">{cross} / {local} / {other}</text>')
    out.append("</svg>")
    return "".join(out)


STATUS_PILL = {
    "sound": ("ok", "AI check passed"), "sound-after-fix": ("ok", "Passed after fix"),
    "excluded": ("bad", "Excluded"), "excluded-after-fix": ("bad", "Excluded"),
    "exclusion-disputed": ("warn", "Exclusion disputed"), "defects-remain": ("warn", "Defects remain"),
    "rebuilt-recheck-pending": ("warn", "Rebuilt, re-check pending"),
    "unchecked": ("wait", "Being checked"), "pending": ("wait", "Queued"),
}


def render(d: dict) -> str:
    events = d["events"]
    prepared = [e for e in events if e["ai"] in ("sound", "sound-after-fix")]
    scope = Counter(e["scope"] for e in prepared)
    by_class: dict[str, list[int]] = {c: [0, 0, 0] for c in CLASS_NAMES}
    for e in events:
        slot = 0 if e["scope"] == "cross_file" and e in prepared else 1 if e["scope"] == "local" and e in prepared else 2
        by_class.setdefault(e["class"], [0, 0, 0])[slot] += 1
    n_tests, test_state = d["tests"]
    signed = sum(e["signoff"] == "accept" for e in events)

    tiles = [
        (f"{n_tests}", f"automated tests {test_state}"),
        (f"{len(d['repos'])} + {d['reserve']}", "seed repositories (selected + reserve)"),
        (f"{d['funnel'][0][1]}", "injection advisories mined"),
        (f"{len(events)}", "candidate regression events"),
        (f"{len(prepared)}", f"prepared ({scope['cross_file']} cross-file, {scope['local']} local)"),
        (f"{signed}", "signed off (target 25-30)"),
    ]
    tiles_html = "".join(f'<div class="tile"><b>{esc(v)}</b><span>{esc(l)}</span></div>' for v, l in tiles)

    ms_html = []
    for code, name, steps in MILESTONES:
        states = {s for _, _, s in steps}
        state = "done" if states == {"done"} else "active" if "active" in states or "done" in states else "todo"
        items = "".join(f'<li class="{s}"><span class="step">{esc(c)}</span>{esc(t)}'
                        f'<span class="pill {s}">{ {"done": "Done", "active": "In progress", "todo": "Planned"}[s] }</span></li>'
                        for c, t, s in steps)
        ms_html.append(f'<details class="ms {state}"{" open" if state == "active" else ""}><summary>'
                       f'<span class="code">{esc(code)}</span>{esc(name)}</summary><ul>{items}</ul></details>')

    rows = []
    for e in events:
        cls, label = STATUS_PILL.get(e["ai"], ("wait", e["ai"]))
        sign = {"accept": ("ok", "Accepted"), "reject": ("bad", "Rejected"), "revise": ("warn", "Revise")}.get(
            e["signoff"], ("wait", "Not yet"))
        adv = ", ".join(f'<a href="https://github.com/advisories/{esc(a)}" target="_blank" rel="noopener">{esc(a)}</a>'
                        for a in e["advisories"])
        rows.append(
            f'<tr data-class="{esc(e["class"])}" data-scope="{esc(e["scope"] or "none")}" data-ai="{cls}">'
            f'<td class="mono">{esc(e["id"])}</td><td>{adv}</td><td>{esc(CLASS_NAMES.get(e["class"], e["class"]))}</td>'
            f'<td>{"Cross-file" if e["scope"] == "cross_file" else "Local" if e["scope"] == "local" else "&ndash;"}</td>'
            f'<td class="num">{e["tokens"] or "&ndash;"}</td>'
            f'<td><span class="pill {cls}" title="{esc(e["note"])}">{label}</span></td>'
            f'<td><span class="pill {sign[0]}">{sign[1]}</span></td></tr>')

    repo_rows = "".join(f'<tr><td class="mono">{esc(r)}</td><td>{esc(l)}</td><td class="num">{n}</td></tr>'
                        for r, l, n in d["repos"])
    smoke_rows = "".join(f'<tr><td class="mono">{esc(m)}</td><td>{esc(a)}</td><td>{esc(b)}</td><td>{esc(c)}</td>'
                         f'<td><span class="pill {"ok" if s == "chosen" else "bad" if s == "declined" else "wait"}">'
                         f'{ {"chosen": "Primary model", "declined": "Declined turns", "ablation": "Ablation model"}[s] }'
                         f'</span></td></tr>' for m, a, b, c, s in SMOKE)
    review = d["review"]
    review_html = "".join(f'<div class="kv"><span>{esc(k.replace("-", " "))}</span><b>{v}</b></div>'
                          for k, v in sorted(review.items(), key=lambda kv: -kv[1]))
    class_options = "".join(f'<option value="{k}">{v}</option>' for k, v in CLASS_NAMES.items())

    return TEMPLATE.format(
        generated=esc(d["generated"]), tiles=tiles_html, milestones="".join(ms_html),
        funnel=bar_svg(d["funnel"]),
        scope=stacked_svg({k: tuple(v) for k, v in by_class.items() if sum(v)}),
        rows="".join(rows), repo_rows=repo_rows, smoke_rows=smoke_rows, review=review_html,
        class_options=class_options, n_events=len(events))


TEMPLATE = """<title>GraphGate Project Dashboard</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>
:root {{
  --bg: #f3f5f3; --surface: #ffffff; --sunken: #eaeeeb; --ink: #18211e; --muted: #5a6762; --line: #d6ddd9;
  --accent: #1d5b86; --accent-soft: #e3edf5; --ok: #2b7a4b; --ok-soft: #e2f1e7; --bad: #b0281f; --bad-soft: #f9e5e3;
  --warn: #9a6200; --warn-soft: #f8eed9; --wait: #5a6762; --wait-soft: #eceff0;
  --bar: #4a6f96; --bar-last: #2b7a4b; --seg-cross: #2f4f73; --seg-local: #a9bfd8; --seg-other: #d6ddd9;
  --sans: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif; --mono: "IBM Plex Mono", Consolas, monospace;
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    color-scheme: dark; --bg: #111614; --surface: #19201d; --sunken: #141a18; --ink: #e2e8e5; --muted: #98a59f;
    --line: #2b3431; --accent: #82b9df; --accent-soft: #1b2a35; --ok: #79c795; --ok-soft: #173024; --bad: #f0928a;
    --bad-soft: #3a1c1a; --warn: #e3b25a; --warn-soft: #33280f; --wait: #98a59f; --wait-soft: #222a27;
    --bar: #6f97c2; --bar-last: #79c795; --seg-cross: #82b9df; --seg-local: #3d5a78; --seg-other: #2b3431;
  }}
}}
:root[data-theme="dark"] {{
  color-scheme: dark; --bg: #111614; --surface: #19201d; --sunken: #141a18; --ink: #e2e8e5; --muted: #98a59f;
  --line: #2b3431; --accent: #82b9df; --accent-soft: #1b2a35; --ok: #79c795; --ok-soft: #173024; --bad: #f0928a;
  --bad-soft: #3a1c1a; --warn: #e3b25a; --warn-soft: #33280f; --wait: #98a59f; --wait-soft: #222a27;
  --bar: #6f97c2; --bar-last: #79c795; --seg-cross: #82b9df; --seg-local: #3d5a78; --seg-other: #2b3431;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--ink); font-family: var(--sans); font-size: 14px; line-height: 1.5;
       padding-inline: 16px; padding-block: 20px 48px; }}
a {{ color: var(--accent); }}
:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
.wrap {{ max-width: 1180px; margin: 0 auto; display: grid; gap: 16px; }}
header {{ display: grid; gap: 6px; }}
h1 {{ margin: 0; font-size: 24px; font-weight: 600; letter-spacing: -0.01em; text-wrap: balance; }}
h2 {{ margin: 0 0 10px; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }}
.sub {{ color: var(--muted); max-width: 80ch; margin: 0; }}
.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; }}
.tile {{ background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; display: grid; gap: 2px; }}
.tile b {{ font-size: 24px; font-weight: 600; font-variant-numeric: tabular-nums; }}
.tile span {{ color: var(--muted); font-size: 12.5px; }}
.grid {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.4fr); gap: 16px; }}
@media (max-width: 900px) {{ .grid {{ grid-template-columns: minmax(0, 1fr); }} }}
.card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 16px; min-width: 0; }}
.ms {{ border-top: 1px solid var(--line); padding: 8px 0; }}
.ms:first-of-type {{ border-top: 0; }}
.ms summary {{ cursor: pointer; display: flex; gap: 10px; align-items: baseline; font-weight: 500; }}
.ms .code {{ font-family: var(--mono); font-size: 12px; color: var(--muted); min-width: 40px; }}
.ms.done summary::after {{ content: "Done"; margin-left: auto; color: var(--ok); font-size: 12px; }}
.ms.active summary::after {{ content: "In progress"; margin-left: auto; color: var(--warn); font-size: 12px; }}
.ms.todo summary::after {{ content: "Planned"; margin-left: auto; color: var(--muted); font-size: 12px; }}
.ms ul {{ list-style: none; margin: 8px 0 0; padding: 0 0 0 50px; display: grid; gap: 4px; }}
.ms li {{ display: flex; gap: 8px; align-items: center; }}
.ms li .step {{ font-family: var(--mono); font-size: 12px; color: var(--muted); min-width: 52px; }}
.ms li .pill {{ margin-left: auto; }}
.pill {{ display: inline-block; font-size: 11.5px; border-radius: 999px; padding: 1px 9px; white-space: nowrap; border: 1px solid transparent; }}
.pill.ok, .pill.done {{ color: var(--ok); background: var(--ok-soft); }}
.pill.bad {{ color: var(--bad); background: var(--bad-soft); }}
.pill.warn, .pill.active {{ color: var(--warn); background: var(--warn-soft); }}
.pill.wait, .pill.todo {{ color: var(--wait); background: var(--wait-soft); }}
svg.chart {{ width: 100%; height: auto; display: block; }}
svg .lbl {{ fill: var(--ink); font: 12px var(--sans); }}
svg .val {{ fill: var(--muted); font: 12px var(--mono); }}
svg .bar {{ fill: var(--bar); }} svg .bar.last {{ fill: var(--bar-last); }}
svg .seg-cross {{ fill: var(--seg-cross); }} svg .seg-local {{ fill: var(--seg-local); }} svg .seg-other {{ fill: var(--seg-other); }}
.legend {{ display: flex; gap: 14px; flex-wrap: wrap; color: var(--muted); font-size: 12px; margin-top: 8px; }}
.legend i {{ display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 5px; vertical-align: -1px; }}
.table-wrap {{ overflow-x: auto; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
th {{ text-align: left; font-weight: 600; color: var(--muted); font-size: 12px; border-bottom: 1px solid var(--line); padding: 6px 8px; white-space: nowrap; }}
td {{ border-bottom: 1px solid var(--line); padding: 6px 8px; vertical-align: top; }}
td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.mono {{ font-family: var(--mono); font-size: 12.5px; }}
.filters {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }}
.filters select {{ font: inherit; font-size: 13px; padding: 4px 8px; border-radius: 6px; border: 1px solid var(--line); background: var(--surface); color: var(--ink); }}
.kvs {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 8px; }}
.kv {{ background: var(--sunken); border-radius: 6px; padding: 8px 10px; display: grid; }}
.kv span {{ color: var(--muted); font-size: 12px; text-transform: capitalize; }}
.kv b {{ font-size: 18px; font-variant-numeric: tabular-nums; }}
footer {{ color: var(--muted); font-size: 12px; }}
</style>

<div class="wrap">
  <header>
    <h1>GraphGate Project Dashboard</h1>
    <p class="sub">In-loop security gate for iterative LLM code refinement. Every number below is read from the project's data files; snapshot generated {generated}.</p>
  </header>

  <section class="tiles" aria-label="Summary">{tiles}</section>

  <div class="grid">
    <section class="card"><h2>Milestones</h2>{milestones}</section>
    <section class="card">
      <h2>Dataset funnel</h2>
      {funnel}
      <p class="sub" style="margin-top:8px;font-size:12px">Log scale. The last bar counts events the authors have accepted on the sign-off page.</p>
    </section>
  </div>

  <div class="grid">
    <section class="card">
      <h2>Events by class and scope</h2>
      {scope}
      <div class="legend"><span><i style="background:var(--seg-cross)"></i>Cross-file (prepared)</span><span><i style="background:var(--seg-local)"></i>Local (prepared)</span><span><i style="background:var(--seg-other)"></i>Queued or excluded</span></div>
    </section>
    <section class="card">
      <h2>Fix-link verification (two independent reviewers)</h2>
      <div class="kvs">{review}</div>
      <p class="sub" style="margin-top:10px;font-size:12.5px">Four pairs were corrected and four missing fixes recovered after every non-confirmed case was read against the repository history.</p>
    </section>
  </div>

  <section class="card">
    <h2>Regression events ({n_events})</h2>
    <div class="filters">
      <select id="f-class" aria-label="Class"><option value="">All classes</option>{class_options}</select>
      <select id="f-scope" aria-label="Scope"><option value="">Any scope</option><option value="cross_file">Cross-file</option><option value="local">Local</option></select>
      <select id="f-ai" aria-label="AI status"><option value="">Any AI status</option><option value="ok">Passed</option><option value="bad">Excluded</option><option value="wait">Queued</option><option value="warn">Needs attention</option></select>
    </div>
    <div class="table-wrap"><table id="events">
      <thead><tr><th>Event</th><th>Advisories</th><th>Class</th><th>Scope</th><th>Slice tokens</th><th>AI preparation</th><th>Sign-off</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
  </section>

  <div class="grid">
    <section class="card">
      <h2>Models (smoke runs on a harmless fixture)</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>Model</th><th>Turns completed</th><th>Refused</th><th>Full runs</th><th>Role</th></tr></thead>
        <tbody>{smoke_rows}</tbody>
      </table></div>
    </section>
    <section class="card">
      <h2>Selected seed repositories</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>Repository</th><th>Licence</th><th>Advisories</th></tr></thead>
        <tbody>{repo_rows}</tbody>
      </table></div>
    </section>
  </div>

  <footer>Built by <span class="mono">python scripts/build_dashboard.py</span>. Sources: data/seed_repos.json, data/fix_pairs.json, data/fix_review.json, data/validation_ai_review.json, data/events/, docs/MODEL_CHOICE.md.</footer>
</div>

<script>
(function () {{
  var selects = ["f-class", "f-scope", "f-ai"].map(function (id) {{ return document.getElementById(id); }});
  function apply() {{
    var c = selects[0].value, s = selects[1].value, a = selects[2].value;
    document.querySelectorAll("#events tbody tr").forEach(function (tr) {{
      var show = (!c || tr.dataset.class === c) && (!s || tr.dataset.scope === s) && (!a || tr.dataset.ai === a);
      tr.hidden = !show;
    }});
  }}
  selects.forEach(function (el) {{ el.addEventListener("change", apply); }});
}})();
</script>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-tests", action="store_true", help="run pytest for the tests tile (about 40 s)")
    parser.add_argument("--out", type=Path, default=OUT / "index.html")
    args = parser.parse_args(argv)
    body = render(gather(args.run_tests))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text('<!DOCTYPE html>\n<meta charset="utf-8">\n'
                        '<meta name="viewport" content="width=device-width, initial-scale=1">\n' + body,
                        encoding="utf-8", newline="\n")
    (args.out.parent / "artifact.html").write_text(body, encoding="utf-8", newline="\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
