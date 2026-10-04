# Render the paper's HTML copy through Microsoft Word into IEEE conference layout
# (US Letter, two columns below the title block) and save .docx and .pdf.
# Called by paper/build.py; needs Microsoft Word installed.
param([string]$Html, [string]$Docx, [string]$Pdf)
$ErrorActionPreference = 'Stop'

$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0
try {
    $doc = $word.Documents.Open($Html, $false, $false, $false)
    $doc.ActiveWindow.View.Type = 3          # print layout

    # Pictures arrive as links to the PNG files; store them in the document.
    foreach ($field in @($doc.Fields)) { if ($field.Type -eq 67) { $field.Unlink() } }
    foreach ($shape in @($doc.InlineShapes)) {
        if ($shape.LinkFormat -ne $null) {
            $shape.LinkFormat.SavePictureWithDocument = $true
            $shape.LinkFormat.BreakLink()
        }
    }

    # Title and authors span the page; everything after the marker is two-column.
    $range = $doc.Content
    if ($range.Find.Execute('[[COLUMNS]]')) {
        $range.Text = ''
        $range.InsertBreak(3)                # continuous section break
    }
    foreach ($section in @($doc.Sections)) {
        $ps = $section.PageSetup
        $ps.PaperSize = 2                    # US Letter, as in the IEEE conference template
        $ps.TopMargin = 54                   # 0.75 in
        $ps.BottomMargin = 72                # 1 in
        $ps.LeftMargin = 45                  # 0.625 in
        $ps.RightMargin = 45
    }
    $last = $doc.Sections.Item($doc.Sections.Count)
    $last.PageSetup.TextColumns.SetCount(2)
    $last.PageSetup.TextColumns.EvenlySpaced = $true
    $last.PageSetup.TextColumns.Spacing = 18  # 0.25 in

    # Body tables fill their column; the author table (first) stays centred.
    $i = 0
    foreach ($table in @($doc.Tables)) {
        $i++
        if ($i -eq 1) { continue }
        $table.AutoFitBehavior(2)            # fit to window (column)
        $table.Rows.AllowBreakAcrossPages = 0
        $table.Range.ParagraphFormat.KeepWithNext = -1   # keep each table in one piece
        $table.Rows.Item($table.Rows.Count).Range.ParagraphFormat.KeepWithNext = 0
    }
    # Table captions stay with their table; figures stay with their caption.
    foreach ($para in @($doc.Paragraphs)) {
        if ($para.Range.Text -match '^TABLE [IVX]+') { $para.KeepWithNext = -1 }
    }
    foreach ($shape in @($doc.InlineShapes)) { $shape.Range.Paragraphs.Item(1).KeepWithNext = -1 }
    foreach ($name in @('Heading 1', 'Heading 2')) {
        $doc.Styles.Item($name).Font.Name = 'Times New Roman'
    }
    $doc.AutoHyphenation = $true

    $doc.SaveAs2($Docx, 16)                  # .docx
    $doc.ExportAsFixedFormat($Pdf, 17)       # .pdf
    $doc.Close($false)
    Write-Output "wrote $Docx and $Pdf"
}
finally {
    # Word sometimes drops the COM connection while closing; the files are saved by then.
    try { $word.Quit() } catch { }
}
