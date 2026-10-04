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
- **Snapshot numbers.** Section VI and Table V report the dataset as of the build date. Rebuild after the
  validation step (BUILD_PLAN 2.3) finishes and after your sign-off, so the counts are current.

## About the writing

The text was written for this project and does not reuse wording from the cited papers. Run it through
your institution's plagiarism checker before submission, as usual. IEEE policy requires disclosing
AI-generated content; the Acknowledgment section does this. Keep the disclosure unless your department
tells you otherwise.
