# GraphGate paper (IEEE conference format)

| File | What it is |
|---|---|
| `output/GraphGate_paper.pdf` | Ready-to-read PDF for review |
| `output/GraphGate_paper.docx` | Word version of the same paper, for comments and edits |
| `main.tex` | The IEEE LaTeX source (IEEEtran class) |
| `references.bib` | The 34 references |
| `figures/` | Figures, drawn from the project's data (PDF for LaTeX, PNG for Word) |
| `generated/` | Dataset numbers and the title/author block, written by `build.py` |
| `build.py` | Rebuilds the numbers, figures, Word file and PDF |

## Section headings

The guide fixed the paper's headings on 2026-10-06: Abstract, Introduction, Literature Survey,
Methodology, Dataset Description, Implementation and Results, Conclusion and Future Work,
References. No other heading is used. Topics inside a section start with an italic lead-in
("*Code graph.* The graph of revision...") instead of a subsection heading; keep it that way when
adding material.

## Compile the LaTeX version on Overleaf

1. Zip this `paper` folder, or use `GraphGate_Paper.zip`.
2. In Overleaf: **New Project > Upload Project**, then choose the zip.
3. Set the main document to `main.tex` and click **Recompile**. The IEEEtran class is built into Overleaf.

## Rebuild after the data changes

From the project root, in a terminal:

```powershell
python paper/build.py
```

This refreshes every number in the paper from the data files, redraws the figures and re-exports
the Word file and PDF through Microsoft Word. Use `--no-word` to skip the Word step.

## Before submitting, fill in

- **Email addresses** for both authors (currently the IEEE placeholder "email address").
  Edit `META` near the top of `build.py`, then rebuild.
- **The guide's designation and department.** They are currently written as "Project Guide,
  Department of Artificial Intelligence and Data Science"; correct them in `META` if different.
- **Other team members**, if any, in the same place.
- **Snapshot numbers.** Sections IV and V and Table IV report the project as of the build date.
  Rebuild whenever the data files change, so the counts are current.

## About the writing

The text was written for this project and does not reuse wording from the cited papers. Run it through
your institution's plagiarism checker before submission, as usual. IEEE policy requires disclosing
AI-generated content. With the guide's headings there is no Acknowledgment section, so the disclosure
is the last paragraph of "Conclusion and Future Work". IEEE asks for it in an acknowledgments section:
if the paper goes to an IEEE venue, check with the guide whether that heading may return. Keep the
disclosure unless your department
tells you otherwise.
