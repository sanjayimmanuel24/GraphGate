"""Build the GraphGate paper from the project's own data.

    python paper/build.py              # numbers, figures, Word (.docx) and PDF
    python paper/build.py --no-word    # numbers and figures only (for Overleaf)

Outputs:
- paper/generated/numbers.tex, meta.tex  dataset figures and title block, read by main.tex
- paper/figures/*.pdf, *.png             charts drawn from the data
- paper/output/GraphGate_paper.docx/.pdf a Word copy, rendered through Microsoft Word

main.tex is the canonical IEEE (IEEEtran) source: upload the paper folder to
Overleaf to compile it. The Word copy is converted from the same file by a small
converter that understands only the LaTeX this paper uses and stops with an
error on anything else, so the two versions cannot silently drift apart.
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
PAPER = ROOT / "paper"
GEN, FIG, OUT = PAPER / "generated", PAPER / "figures", PAPER / "output"

META = {
    "title": "GraphGate: Toward an In-Loop Security Gate for Iterative LLM Code Refinement "
             "Using Temporal Code-Graph Deltas",
    "authors": [
        {"name": "Janani R",
         "lines": ["Department of Artificial Intelligence and Data Science",
                   "Karunya Institute of Technology and Sciences", "Coimbatore, India", "email address"]},
        {"name": "Rajkumar",
         "lines": ["Project Guide, Department of Artificial Intelligence and Data Science",
                   "Karunya Institute of Technology and Sciences", "Coimbatore, India", "email address"]},
    ],
}

LOC_MIN, LOC_MAX = 5_000, 50_000
EXCLUDED_BY_HAND = {"GHSA-j6cv-98jx-mrwr"}  # fix is PHP (BUILD_PLAN 2.2)


# --------------------------------------------------------------------------
# Numbers
# --------------------------------------------------------------------------

def load(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def roman(n: int) -> str:
    out = ""
    for value, sym in ((10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")):
        while n >= value:
            out, n = out + sym, n - value
    return out


def count_tests() -> int:
    done = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q"], cwd=ROOT,
                          capture_output=True, text=True)
    m = re.search(r"(\d+) tests? collected", done.stdout)
    return int(m[1]) if m else 0


def compute_numbers() -> tuple[dict[str, str], dict]:
    manifest = load("data/seed_repos.json")
    funnel = manifest["source"]["funnel"]
    selected = [r for r in manifest["repos"] if r["role"] == "selected"]
    reserve = [r for r in manifest["repos"] if r["role"] == "reserve"]
    pairs = load("data/fix_pairs.json")["events"]
    review = load("data/fix_review.json")
    tally = Counter(review["tally"])
    corrections = load("data/fix_pair_corrections.json")["advisories"]
    recovered = load("data/recovered_fix_commits.json")["advisories"]

    candidates = [e for e in pairs
                  if e["role"] == "selected" and e["vulnerable_commit"]
                  and e["advisory"] not in EXCLUDED_BY_HAND
                  and LOC_MIN <= ((e.get("loc_at_vulnerable") or {}).get("source") or 0) <= LOC_MAX]
    events = {(e["repo"], e["fix_commit"], e["vulnerable_commit"]) for e in candidates}

    ai_path = ROOT / "data/validation_ai_review.json"
    ai = json.loads(ai_path.read_text(encoding="utf-8"))["results"] if ai_path.exists() else []
    sound = [r for r in ai if r["status"] in ("sound", "sound-after-fix")]
    excluded = [r for r in ai if r["status"] in ("excluded", "excluded-after-fix")]
    final = lambda r: r.get("fix") or r.get("analyst") or {}
    scope = Counter(final(r).get("scope") for r in sound)
    by_class = Counter((final(r).get("vulnerability_class"), final(r).get("scope")) for r in sound)
    signoff_path = ROOT / "data/validation_signoff.json"
    decisions = load("data/validation_signoff.json")["decisions"] if signoff_path.exists() else {}
    accepted = sorted(e for e, d in decisions.items() if d.get("decision") == "accept")
    signed = len(accepted)
    if accepted:
        # After the sign-off the paper reports the validated set, with the
        # scope label the pre-registered rule computed (event.json).
        facts = [load(f"data/events/{e}/event.json") for e in accepted]
        scope = Counter(f["scope"] for f in facts)
        by_class = Counter((f["vulnerability_class"], f["scope"]) for f in facts)
    leak_path = ROOT / "data/leakage_exclusions.json"
    leak = load("data/leakage_exclusions.json")["summary"] if leak_path.exists() else {}
    # Semgrep and Bandit over each validated regression (scripts/scan_events.py).
    static_path = ROOT / "data/static_first_look.json"
    static = load("data/static_first_look.json") if static_path.exists() else {}
    static_groups = static.get("summary", {}).get("by_class_and_scope", {})
    # Runs with the open-weight model (scripts/summarize_open_model_runs.py).
    open_path = ROOT / "data/open_model_runs.json"
    open_runs = load("data/open_model_runs.json") if open_path.exists() else {}
    pilot = open_runs.get("pilot") or {}
    # The graph layer: builder check and first look (scripts/build_graph.py, scripts/delta_events.py).
    delta = (load("data/delta_first_look.json") if (ROOT / "data/delta_first_look.json").exists() else {}
             ).get("summary", {})
    delta_c = delta.get("settings", {}).get("graphgate", {})
    delta_repo = delta.get("repository_view") or {}      # the registered view of Condition C
    graph_totals = (load("data/graph_build_check.json") if (ROOT / "data/graph_build_check.json").exists()
                    else {}).get("totals", {})
    session = open_runs.get("first_dataset_session") or {}

    rows = []
    for r in sorted(selected, key=lambda r: (-len(r["advisories"]), r["repo"])):
        note = ""
        if r["repo"] == "datadog/guarddog":
            note = " (excluded: size)"
        rows.append(f"{latex_escape(r['repo'])} & {r['licence']} & {len(r['advisories'])}{note} \\\\ \\hline")

    n = {
        "nInjAdv": funnel["injection_advisories"],
        "nInjAdvWithFix": funnel["usable_with_fix_commit"],
        "nReposUsable": funnel["repos_with_usable_advisories"],
        "nOsvDate": "27 September 2026",
        "nSeedSelected": len(selected),
        "nSeedReserve": len(reserve),
        "nAdvSelected": sum(len(r["advisories"]) for r in selected),
        "nAdvSelectedLinked": sum(1 for r in selected for a in r["advisories"] if a["fix_commits"]),
        "nReviewItems": len(review["advisories"]),
        "nReviewConfirmed": tally["confirmed"],
        "nReviewContested": tally["contested"],
        "nReviewNeedsHuman": tally["needs-human"],
        "nReviewRejected": tally["rejected"],
        "nReviewNotRecovered": tally["not-recovered"],
        "nCorrected": len(corrections),
        "nRecovered": len(recovered),
        "nCandidatePairs": len(candidates),
        "nEvents": len(events),
        "nEventsSound": len(sound),
        "nEventsExcluded": len(excluded),
        "nEventsPending": len(events) - len(sound) - len(excluded),
        "nEventsCross": scope["cross_file"],
        "nEventsLocal": scope["local"],
        "nEventsSignedOff": signed,
        "nEventsNotAccepted": len(decisions) - signed,
        "nLeakTwins": leak.get("near_duplicates", 0),
        "nLeakTests": leak.get("fix_tests_excluded", 0),
        "nStaticEvents": static.get("summary", {}).get("events", 0),
        "nStaticCaught": static.get("summary", {}).get("with_introduced_finding", 0),
        "nPathEvents": sum(g["events"] for name, g in static_groups.items() if name.startswith("path-traversal/")),
        "nSemgrepRules": static.get("rules", {}).get("rule_files", 0),
        "nPathRules": (static.get("rules", {}).get("rule_files_by_cwe") or {}).get("22", 0),
        "nSemgrepVersion": static.get("tools", {}).get("semgrep", "n/a"),
        "nDeltaCaught": delta_c.get("flagged", 0),
        "nDeltaCross": delta_c.get("by_scope", {}).get("cross_file", {}).get("flagged", 0),
        "nDeltaProposed": delta.get("settings", {}).get("as-proposed", {}).get("flagged", 0),
        "nDeltaRepo": delta_repo.get("flagged", 0),
        "nDeltaRepoCross": delta_repo.get("by_scope", {}).get("cross_file", {}).get("flagged", 0),
        "nDeltaRepoFixes": delta_repo.get("control_fix_flagged", 0),
        "nDepthOne": (delta_repo.get("by_depth") or {}).get("1", 0),
        "nEdgeChanged": delta.get("slice_graphs", {}).get("regression_changes_an_edge", 0),
        "nDeltaFixes": delta.get("control_fix_flagged", {}).get("graphgate", 0),
        "nNoPath": delta.get("slice_graphs", {}).get("without_a_source_to_sink_path", 0),
        "nGraphRepos": graph_totals.get("repositories", 0),
        "nGraphCalls": f"{graph_totals.get('calls', 0):,}",
        "nUnknownShare": f"{100 * graph_totals.get('unknown_share', 0):.0f}",
        "nGraphTests": sum(len(re.findall(r"^def test_", (ROOT / "tests" / name).read_text(encoding="utf-8"),
                                          flags=re.M))
                           for name in ("test_delta.py", "test_graph_extract.py", "test_graph_link.py",
                                        "test_graph_index.py")),
        "nPilotCalls": pilot.get("model_calls", 0),
        "nPilotUsable": pilot.get("turns_usable", 0),
        "nPilotSeconds": pilot.get("median_seconds_per_turn", 0),
        "nSessionEvents": session.get("events_finished", 0),
        "nPilotTurns": pilot.get("turns_labelled", 0),
        "nPilotCarried": pilot.get("turns_carried", 0),
        "nSeedEvents": session.get("events_started", 0),
        "nInjFailed": session.get("failed_injections", 0),
        "nInjReps": session.get("replications_under_those_seeds", 0),
        "nBanditVersion": static.get("tools", {}).get("bandit", "n/a"),
        "nSnapshotDate": f"{dt.date.today().day} {dt.date.today():%B %Y}",
        "nTests": count_tests(),
        "nRepoRows": "\n".join(rows),
    }
    extra = {"by_class": by_class, "funnel": funnel, "validated": bool(accepted)}
    return {k: str(v) for k, v in n.items()}, extra


def latex_escape(s: str) -> str:
    return s.replace("\\", r"\textbackslash{}").replace("_", r"\_").replace("&", r"\&").replace("%", r"\%")


def write_generated(numbers: dict[str, str]) -> None:
    GEN.mkdir(exist_ok=True)
    lines = ["% Generated by paper/build.py from the project's data files. Do not edit."]
    lines += [f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in numbers.items()]
    (GEN / "numbers.tex").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    blocks = []
    for a in META["authors"]:
        body = " \\\\\n".join(latex_escape(line) for line in a["lines"])
        blocks.append(f"\\IEEEauthorblockN{{{a['name']}}}\n\\IEEEauthorblockA{{{body}}}")
    meta = (f"% Generated by paper/build.py. Edit META in build.py, not this file.\n"
            f"\\title{{{META['title']}}}\n\n\\author{{" + "\n\\and\n".join(blocks) + "}\n")
    (GEN / "meta.tex").write_text(meta, encoding="utf-8", newline="\n")


# --------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------

def figures(numbers: dict[str, str], extra: dict) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch
    from matplotlib.ticker import MaxNLocator

    FIG.mkdir(exist_ok=True)
    plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"],
                         "font.size": 7, "axes.linewidth": 0.6})

    def save(fig, name):
        fig.savefig(FIG / f"{name}.pdf", bbox_inches="tight")
        fig.savefig(FIG / f"{name}.png", dpi=300, bbox_inches="tight")
        plt.close(fig)

    # Architecture
    fig, ax = plt.subplots(figsize=(3.5, 4.3))
    ax.set_xlim(0, 10), ax.set_ylim(1.0, 13.3), ax.axis("off")

    def box(x, y, w, h, text, fill="#ffffff", bold=False, dashed=False, size=7):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.15",
                                    linewidth=0.8, edgecolor="#222222", facecolor=fill,
                                    linestyle="--" if dashed else "-"))
        if text:
            ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size,
                    fontweight="bold" if bold else "normal", wrap=True)

    def arrow(x1, y1, x2, y2, text=None):
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="-|>", lw=0.8, color="#222222", mutation_scale=8))
        if text:
            ax.text((x1 + x2) / 2 + 0.15, (y1 + y2) / 2, text, ha="left", va="center", fontsize=6,
                    style="italic")

    box(1.6, 12.2, 6.8, 0.9, "Refinement prompt (turn t)")
    arrow(5, 12.2, 5, 11.55)
    box(1.6, 10.6, 6.8, 0.95, "Code-generation LLM\n(open-weight model)")
    arrow(5, 10.6, 5, 9.75, "candidate revision (full files)")
    box(0.35, 4.95, 6.95, 4.8, "", fill="#f4f4f4", dashed=True)
    ax.text(0.6, 9.45, "Security gate", fontsize=7, fontweight="bold", va="center")
    box(0.7, 7.95, 6.25, 1.05, "1. Static analysis of the diff\n(Semgrep, Bandit)", fill="#e8eef6")
    box(0.7, 6.6, 6.25, 1.05, "2. Graph-difference engine\n\u0394G = G(t) \u2212 G(t\u22121), rules R1\u2013R4",
        fill="#dbe5f1")
    box(0.7, 5.25, 6.25, 1.05, "3. LLM triage of flagged deltas\n(label and rationale)", fill="#e8eef6")
    arrow(3.8, 7.95, 3.8, 7.65)
    arrow(3.8, 6.6, 3.8, 6.3)
    box(7.6, 6.25, 2.3, 1.75, "Graph store\n(NetworkX,\nSQLite)", size=6.3)
    ax.annotate("", xy=(7.6, 7.12), xytext=(6.95, 7.12),
                arrowprops=dict(arrowstyle="<|-|>", lw=0.8, color="#222222", mutation_scale=7))
    arrow(3.8, 4.95, 3.8, 4.25)
    box(1.0, 3.35, 5.6, 0.9, "Decision: ALLOW or BLOCK", bold=True)
    box(0.35, 1.3, 3.9, 1.3, "BLOCK: rationale added\nto the next prompt", fill="#f7e3e1")
    box(5.1, 1.3, 4.7, 1.3, "ALLOW: commit and\nre-index changed files", fill="#e3f1e7")
    arrow(2.9, 3.35, 2.3, 2.6)
    arrow(4.7, 3.35, 7.2, 2.6)
    ax.plot([0.35, 0.1, 0.1, 1.6], [1.95, 1.95, 12.65, 12.65], color="#222222", lw=0.8)
    ax.annotate("", xy=(1.6, 12.65), xytext=(1.2, 12.65),
                arrowprops=dict(arrowstyle="-|>", lw=0.8, color="#222222", mutation_scale=8))
    ax.annotate("", xy=(8.75, 6.25), xytext=(8.75, 2.6),
                arrowprops=dict(arrowstyle="-|>", lw=0.8, color="#222222", linestyle=":", mutation_scale=8))
    ax.text(8.9, 4.3, "re-index", fontsize=6, style="italic", va="center")
    save(fig, "architecture")

    # Funnel
    stages = [
        ("Injection-class advisories\n(PyPI, GHSA)", int(numbers["nInjAdv"])),
        ("... with a linked fix commit", int(numbers["nInjAdvWithFix"])),
        ("In the selected seed repositories", int(numbers["nAdvSelected"])),
        ("Verified candidate pairs", int(numbers["nCandidatePairs"])),
        ("Candidate events", int(numbers["nEvents"])),
        ("Prepared, passed adversarial check", int(numbers["nEventsSound"])),
    ]
    if extra["validated"]:
        stages.append(("Validated at author sign-off", int(numbers["nEventsSignedOff"])))
    fig, ax = plt.subplots(figsize=(3.5, 2.0))
    labels = [s for s, _ in stages][::-1]
    values = [v for _, v in stages][::-1]
    bars = ax.barh(labels, values, color="#4a6f96", height=0.6)
    ax.set_xscale("log")
    ax.set_xlim(10, 2500)
    for b, v in zip(bars, values):
        ax.text(v * 1.12, b.get_y() + b.get_height() / 2, str(v), va="center", fontsize=7)
    ax.set_xlabel("Count (log scale)")
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(axis="y", length=0)
    save(fig, "funnel")

    # Class x scope
    classes = [("path-traversal", "Path traversal (CWE-22)"), ("os-command", "OS command (CWE-78)"),
               ("command", "Command (CWE-77)"), ("sql", "SQL (CWE-89)")]
    by = extra["by_class"]
    cross = [by.get((c, "cross_file"), 0) for c, _ in classes][::-1]
    local = [by.get((c, "local"), 0) for c, _ in classes][::-1]
    names = [n for _, n in classes][::-1]
    fig, ax = plt.subplots(figsize=(3.5, 1.55))
    ax.barh(names, cross, color="#2f4f73", height=0.55, label="Cross-file")
    ax.barh(names, local, left=cross, color="#a9bfd8", height=0.55, label="Local")
    for i, (c, l) in enumerate(zip(cross, local)):
        if c + l:
            ax.text(c + l + 0.2, i, f"{c} + {l}", va="center", fontsize=6.5)
    ax.set_xlabel("Validated events" if extra["validated"] else "Prepared events")
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_xlim(0, max(c + l for c, l in zip(cross, local)) + 3)
    ax.legend(frameon=False, fontsize=6.5, loc="lower right")
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(axis="y", length=0)
    save(fig, "scope")


# --------------------------------------------------------------------------
# LaTeX subset -> HTML (for the Word copy)
# --------------------------------------------------------------------------

MATH = {
    r"G(t) = (V, E_{\mathrm{call}}, E_{\mathrm{taint}}, E_{\mathrm{sanitize}})":
        "<i>G</i>(<i>t</i>) = (<i>V</i>, <i>E</i><sub>call</sub>, <i>E</i><sub>taint</sub>, "
        "<i>E</i><sub>sanitize</sub>)",
    r"\Delta G = G(t) - G(t-1)": "\u0394<i>G</i> = <i>G</i>(<i>t</i>) \u2212 <i>G</i>(<i>t</i>\u22121)",
    r"G(t-1)": "<i>G</i>(<i>t</i>\u22121)",
    r"G(t)": "<i>G</i>(<i>t</i>)",
    r"E_{\mathrm{call}}": "<i>E</i><sub>call</sub>",
    r"E_{\mathrm{taint}}": "<i>E</i><sub>taint</sub>",
    r"E_{\mathrm{sanitize}}": "<i>E</i><sub>sanitize</sub>",
    "V": "<i>V</i>",
    "t": "<i>t</i>",
}


class ConvertError(RuntimeError):
    pass


def read_group(text: str, i: int) -> tuple[str, int]:
    """Content of the {...} group starting at text[i]; returns (content, index after '}')."""
    if text[i] != "{":
        raise ConvertError(f"expected '{{' at: {text[i:i + 40]!r}")
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{" and text[j - 1] != "\\":
            depth += 1
        elif text[j] == "}" and text[j - 1] != "\\":
            depth -= 1
            if depth == 0:
                return text[i + 1:j], j + 1
    raise ConvertError(f"unbalanced braces at: {text[i:i + 40]!r}")


class Converter:
    def __init__(self, body: str, bib: dict[str, dict]):
        self.body = body
        self.bib = bib
        self.cite_order: list[str] = []
        self.labels = self._labels()

    def _labels(self) -> dict[str, str]:
        labels, sec, table, figure, last = {}, 0, 0, 0, None
        for m in re.finditer(r"\\section(\*?)\{|\\subsection\{|\\begin\{table\}|\\begin\{figure\}|\\label\{([^}]*)\}",
                             self.body):
            token = m.group(0)
            if token.startswith("\\section"):
                if not m.group(1):
                    sec += 1
                    last = roman(sec)
            elif token.startswith("\\begin{table"):
                table += 1
                last = roman(table)
            elif token.startswith("\\begin{figure"):
                figure += 1
                last = str(figure)
            elif token.startswith("\\label"):
                labels[m.group(2)] = last
        return labels

    # inline -------------------------------------------------------------
    def inline(self, s: str) -> str:
        s = " ".join(s.split())
        s = html.escape(s, quote=False)
        s = re.sub(r"\$([^$]+)\$", self._math, s)
        s = re.sub(r"\\cite\{([^}]*)\}", self._cite, s)
        s = re.sub(r"\\ref\{([^}]*)\}", lambda m: self._ref(m[1]), s)
        s = re.sub(r"\\label\{[^}]*\}", "", s)
        simple = {"textbf": "<b>{}</b>", "emph": "<i>{}</i>", "textit": "<i>{}</i>",
                  "texttt": '<span class="tt">{}</span>', "mbox": "{}", "url": "{}"}
        changed = True
        while changed:
            changed = False
            for cmd, tpl in simple.items():
                new = re.sub(r"\\" + cmd + r"\{([^{}]*)\}", lambda m, t=tpl: t.format(m[1]), s)
                if new != s:
                    s, changed = new, True
        for a, b in [(r"\&amp;", "&amp;"), (r"\%", "%"), (r"\_", "_"), (r"\#", "#"), (r"\$", "$"),
                     ("``", "\u201c"), ("''", "\u201d"), ("---", "\u2014"), ("--", "\u2013"),
                     (r"\ldots", "\u2026"), (r"\,", "\u2009"), ("~", "\u00a0")]:
            s = s.replace(a, b)
        s = s.replace("`", "\u2018").replace("'", "\u2019")
        if "\\" in s or "{" in s or "}" in s:
            raise ConvertError(f"unconverted LaTeX: {s[max(0, s.find(chr(92)) - 30):][:120]!r}")
        return s

    def _math(self, m: re.Match) -> str:
        expr = html.unescape(m[1]).strip()
        if expr not in MATH:
            raise ConvertError(f"no HTML form for math ${expr}$; add it to MATH")
        return MATH[expr]

    def _cite(self, m: re.Match) -> str:
        nums = []
        for key in m[1].split(","):
            key = key.strip()
            if key not in self.bib:
                raise ConvertError(f"unknown citation key {key}")
            if key not in self.cite_order:
                self.cite_order.append(key)
            nums.append(self.cite_order.index(key) + 1)
        nums.sort()
        parts, i = [], 0
        while i < len(nums):
            j = i
            while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
                j += 1
            parts.append(f"[{nums[i]}]" if j == i else
                         f"[{nums[i]}], [{nums[j]}]" if j == i + 1 else f"[{nums[i]}]\u2013[{nums[j]}]")
            i = j + 1
        return ", ".join(parts)

    def _ref(self, label: str) -> str:
        if label not in self.labels:
            raise ConvertError(f"unknown label {label}")
        return self.labels[label]

    # blocks ---------------------------------------------------------------
    def paragraphs(self, text: str) -> str:
        out = []
        for chunk in re.split(r"\n\s*\n", text):
            chunk = chunk.strip()
            chunk = re.sub(r"^\\label\{[^}]*\}\s*", "", chunk).strip()
            if chunk:
                out.append(f"<p>{self.inline(chunk)}</p>")
        return "\n".join(out)

    def convert(self) -> str:
        out: list[str] = []
        pos, sec, sub = 0, 0, 0
        pat = re.compile(r"\\begin\{(abstract|IEEEkeywords|itemize|table|figure)\}|\\(section|subsection)(\*?)\{"
                         r"|\\maketitle|\\bibliographystyle\{[^}]*\}|\\bibliography\{[^}]*\}|\\input\{[^}]*\}")
        while True:
            m = pat.search(self.body, pos)
            out.append(self.paragraphs(self.body[pos:m.start() if m else len(self.body)]))
            if not m:
                break
            token = m.group(0)
            if m.group(1):
                env = m.group(1)
                end = self.body.index(f"\\end{{{env}}}", m.end())
                out.append(getattr(self, "env_" + env)(self.body[m.end():end]))
                pos = end + len(f"\\end{{{env}}}")
            elif m.group(2):
                title, pos = read_group(self.body, m.end() - 1)
                if m.group(2) == "section":
                    if m.group(3):
                        out.append(f"<h1>{self.inline(title)}</h1>")
                    else:
                        sec, sub = sec + 1, 0
                        out.append(f"<h1>{roman(sec)}. {self.inline(title)}</h1>")
                else:
                    sub += 1
                    out.append(f"<h2>{chr(64 + sub)}. {self.inline(title)}</h2>")
            elif token == "\\maketitle":
                out.append(self.title_block())
                pos = m.end()
            elif token.startswith("\\bibliography{"):
                out.append(self.references())
                pos = m.end()
            else:
                pos = m.end()
        return "\n".join(o for o in out if o)

    def title_block(self) -> str:
        cells = []
        for a in META["authors"]:
            lines = "<br>".join(f"<i>{html.escape(l)}</i>" if i < 2 else html.escape(l)
                                for i, l in enumerate(a["lines"]))
            cells.append(f'<td class="author"><p class="aname">{html.escape(a["name"])}</p>'
                         f'<p class="aff">{lines}</p></td>')
        return (f'<p class="title">{html.escape(META["title"])}</p>\n'
                f'<table class="authors" align="center"><tr>{"".join(cells)}</tr></table>\n'
                f'<p class="marker">[[COLUMNS]]</p>')

    def env_abstract(self, inner: str) -> str:
        return f'<p class="abstract"><b><i>Abstract</i>\u2014{self.inline(inner)}</b></p>'

    def env_IEEEkeywords(self, inner: str) -> str:
        return f'<p class="abstract"><b><i>Index Terms</i>\u2014{self.inline(inner)}</b></p>'

    def env_itemize(self, inner: str) -> str:
        items = [i.strip() for i in inner.split("\\item") if i.strip()]
        return "<ul>" + "".join(f"<li>{self.inline(i)}</li>" for i in items) + "</ul>"

    def _caption(self, inner: str) -> str:
        i = inner.index("\\caption{")
        caption, _ = read_group(inner, i + len("\\caption"))
        return self.inline(caption)

    def env_table(self, inner: str) -> str:
        label = re.search(r"\\label\{([^}]*)\}", inner)[1]
        caption = self._caption(inner)
        start = inner.index("\\begin{tabular}")
        _, after_spec = read_group(inner, start + len("\\begin{tabular}"))
        body = inner[after_spec:inner.index("\\end{tabular}")]
        body = re.sub(r"\\(hline|toprule|midrule|bottomrule)", "", body)
        rows = [r.strip() for r in re.split(r"\\\\", body) if r.strip()]
        html_rows = []
        for n, row in enumerate(rows):
            cells = [self.inline(c) for c in re.split(r"(?<!\\)&", row)]
            tag = "th" if n == 0 else "td"
            html_rows.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
        return (f'<p class="tcap">TABLE {self.labels[label]}<br>{caption}</p>'
                f'<table class="ieee">{"".join(html_rows)}</table>')

    def env_figure(self, inner: str) -> str:
        label = re.search(r"\\label\{([^}]*)\}", inner)[1]
        path = re.search(r"\\includegraphics(?:\[[^\]]*\])?\{([^}]*)\}", inner)[1]
        return (f'<p class="fig"><img src="../{path}.png" width="330"></p>'
                f'<p class="fcap">Fig. {self.labels[label]}. {self._caption(inner)}</p>')

    def references(self) -> str:
        items = [f'<p class="ref">[{i}]\u00a0\u00a0{format_ref(self.bib[k])}</p>'
                 for i, k in enumerate(self.cite_order, 1)]
        return "<h1>References</h1>\n" + "\n".join(items)


# --------------------------------------------------------------------------
# Bibliography (IEEE style, for the Word copy; Overleaf uses IEEEtran.bst)
# --------------------------------------------------------------------------

def parse_bib(text: str) -> dict[str, dict]:
    entries = {}
    for m in re.finditer(r"@(\w+)\{([^,]+),", text):
        kind, key = m[1].lower(), m[2].strip()
        i, fields = m.end(), {"_type": kind}
        while True:
            fm = re.compile(r"\s*(\w+)\s*=\s*").match(text, i)
            if not fm:
                break
            name, j = fm[1].lower(), fm.end()
            if text[j] == "{":
                value, j = read_group(text, j)
                fields[name + "_raw"] = value
            else:
                vm = re.compile(r"[^,\n}]+").match(text, j)
                value, j = vm[0], vm.end()
            fields[name] = value.strip()
            i = j
            cm = re.compile(r"\s*,").match(text, i)
            if cm:
                i = cm.end()
            else:
                break
        entries[key] = fields
    return entries


def clean(value: str) -> str:
    value = value.replace('{\\"e}', "\u00eb")
    value = re.sub(r"\\url\{([^}]*)\}", r"\1", value)
    value = value.replace("--", "\u2013").replace("{", "").replace("}", "")
    return html.escape(value, quote=False)


def format_authors(raw: str) -> str:
    if raw.startswith("{") and raw.endswith("}"):
        return clean(raw)
    names, others = [], False
    for part in raw.split(" and "):
        part = part.strip()
        if part == "others":
            others = True
            continue
        words = clean(part).split()
        initials = " ".join(w[0] + "." if not w.endswith(".") else w for w in words[:-1])
        names.append(f"{initials} {words[-1]}".strip())
    if others:
        return ", ".join(names) + ", <i>et al.</i>"
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + ", and " + names[-1]


def format_ref(e: dict) -> str:
    authors = format_authors(e.get("author_raw", e.get("author", "")))
    title = clean(e["title"])
    sep = "" if title.endswith(("?", "!")) else ","  # IEEE: no comma after a question mark
    note = f" {clean(e['note'])}." if e.get("note") else ""
    if e["_type"] == "inproceedings":
        pages = f", pp. {clean(e['pages'])}" if e.get("pages") else ""
        return f"{authors}, \u201c{title}{sep}\u201d in <i>{clean(e['booktitle'])}</i>, {e['year']}{pages}.{note}"
    if e["_type"] == "article":
        parts = [f"<i>{clean(e['journal'])}</i>"]
        if e.get("volume"):
            parts.append(f"vol. {e['volume']}")
        if e.get("number"):
            parts.append(f"no. {e['number']}")
        if e.get("pages"):
            parts.append(f"pp. {clean(e['pages'])}")
        parts.append(e["year"])
        return f"{authors}, \u201c{title}{sep}\u201d {', '.join(parts)}.{note}"
    url = clean(e.get("howpublished", ""))
    return f"{authors}, \u201c{title}.\u201d{note} [Online]. Available: {url}"


# --------------------------------------------------------------------------
# HTML and Word export
# --------------------------------------------------------------------------

CSS = """
body { font-family: "Times New Roman", serif; font-size: 10pt; }
p { margin: 0; text-align: justify; text-indent: 0.14in; font-size: 10pt; }
h1 { font-family: "Times New Roman", serif; font-size: 10pt; font-weight: normal; font-variant: small-caps; text-align: center;
     margin: 9pt 0 4pt 0; }
h2 { font-family: "Times New Roman", serif; font-size: 10pt; font-weight: normal; font-style: italic; text-align: left; margin: 6pt 0 3pt 0; }
p.title { font-size: 24pt; text-align: center; text-indent: 0; margin: 0 0 12pt 0; line-height: 1.1; }
table.authors td { vertical-align: top; text-align: center; padding: 0 18pt; border: none; }
p.aname { font-size: 11pt; text-align: center; text-indent: 0; }
p.aff { font-size: 10pt; text-align: center; text-indent: 0; }
p.marker { text-indent: 0; }
p.abstract { font-size: 9pt; margin: 0 0 6pt 0; }
ul { margin-top: 2pt; margin-bottom: 2pt; }
li { font-size: 10pt; text-align: justify; margin-bottom: 1pt; }
p.tcap { font-size: 8pt; text-align: center; text-indent: 0; font-variant: small-caps; margin: 8pt 0 3pt 0; page-break-after: avoid; }
table.ieee { border-collapse: collapse; width: 100%; margin-bottom: 8pt; }
table.ieee th, table.ieee td { border: 0.5pt solid #000; font-size: 8pt; padding: 1pt 3pt;
     vertical-align: top; text-align: left; }
table.ieee th { font-weight: bold; }
p.fig { text-align: center; text-indent: 0; margin-top: 6pt; page-break-after: avoid; }
p.fcap { font-size: 8pt; text-indent: 0; margin: 3pt 0 8pt 0; }
p.ref { font-size: 8pt; margin-left: 0.3in; text-indent: -0.3in; margin-bottom: 1pt; }
span.tt { font-family: "Courier New", monospace; font-size: 9pt; }
"""


def build_html() -> Path:
    tex = (PAPER / "main.tex").read_text(encoding="utf-8")
    macros = dict(re.findall(r"\\newcommand\{\\(\w+)\}\{(.*?)\}\n",
                             (GEN / "numbers.tex").read_text(encoding="utf-8"), re.S))
    body = tex[tex.index("\\begin{document}") + len("\\begin{document}"):tex.index("\\end{document}")]
    body = re.sub(r"(?<!\\)%.*", "", body)
    for name in sorted(macros, key=len, reverse=True):
        body = re.sub(r"\\" + name + r"(\{\})?(?![A-Za-z])", lambda m, v=macros[name]: v, body)
    bib = parse_bib((PAPER / "references.bib").read_text(encoding="utf-8"))
    conv = Converter(body, bib)
    content = conv.convert()
    unused = sorted(set(bib) - set(conv.cite_order))
    if unused:
        print(f"note: bibliography entries never cited: {unused}")
    OUT.mkdir(exist_ok=True)
    page = (f'<!DOCTYPE html>\n<html><head><meta charset="utf-8"><title>{html.escape(META["title"])}</title>'
            f"<style>{CSS}</style></head><body>\n{content}\n</body></html>\n")
    path = OUT / "GraphGate_paper.html"
    path.write_text(page, encoding="utf-8", newline="\n")
    return path


def export_word(html_path: Path) -> None:
    script = PAPER / "word_export.ps1"
    docx, pdf = OUT / "GraphGate_paper.docx", OUT / "GraphGate_paper.pdf"
    done = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
                           str(html_path), str(docx), str(pdf)], capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"Word export failed:\n{done.stdout}\n{done.stderr}")
    print(done.stdout.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-word", action="store_true", help="skip the Word/PDF export")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    numbers, extra = compute_numbers()
    write_generated(numbers)
    figures(numbers, extra)
    html_path = build_html()
    print(f"numbers: events={numbers['nEvents']} prepared={numbers['nEventsSound']} "
          f"excluded={numbers['nEventsExcluded']} pending={numbers['nEventsPending']} tests={numbers['nTests']}")
    print(f"wrote {GEN}, {FIG}, {html_path}")
    if not args.no_word:
        export_word(html_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
