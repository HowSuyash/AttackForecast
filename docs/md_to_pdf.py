"""Render a Markdown document to a print-ready PDF.

Run:
    python docs/md_to_pdf.py docs/TUTORIAL.md
    python docs/md_to_pdf.py docs/TUTORIAL.md --out somewhere.pdf

Markdown -> styled HTML -> Chrome's `--print-to-pdf`. Chrome is used because it
is already installed on this machine and its print engine handles page breaks,
tables and images correctly; wkhtmltopdf and friends would be another install
for no gain.

Images are inlined as base64 data URIs rather than left as relative paths.
Chrome restricts what a `file://` page may load, so a relative `<img src>` can
silently render as a blank box in the PDF. Inlining removes the question.
"""

from __future__ import annotations

import argparse
import base64
import mimetypes
import re
import subprocess
import sys
import tempfile
from pathlib import Path

CHROME_CANDIDATES = [
    Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path("/usr/bin/google-chrome"),
    Path("/usr/bin/chromium"),
]

CSS = """
@page { size: A4; margin: 14mm 13mm 16mm 13mm; }

*, *::before, *::after { box-sizing: border-box; }

body {
  font-family: "Segoe UI", system-ui, -apple-system, Roboto, sans-serif;
  font-size: 10.5pt;
  line-height: 1.55;
  color: #1b2230;
  margin: 0;
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;
}

h1 {
  font-size: 21pt; color: #1F497D; margin: 0 0 6pt;
  padding-bottom: 5pt; border-bottom: 2.5pt solid #1F497D;
}
/* Each numbered section starts on a fresh page - the document is a reference,
   and hunting for a section that begins two thirds down a page is friction. */
h2 {
  font-size: 15pt; color: #1F497D; margin: 0 0 9pt;
  padding-bottom: 4pt; border-bottom: 1pt solid #cfd8e6;
  page-break-before: always; page-break-after: avoid;
}
h2:first-of-type { page-break-before: avoid; }
h3 { font-size: 12pt; color: #2b3d5c; margin: 13pt 0 5pt; page-break-after: avoid; }

p { margin: 0 0 7pt; orphans: 3; widows: 3; }
ul, ol { margin: 0 0 8pt; padding-left: 17pt; }
li { margin-bottom: 3pt; }

a { color: #1F497D; text-decoration: none; border-bottom: 0.5pt dotted #7d93b5; }

code {
  font-family: Consolas, "SF Mono", Menlo, monospace;
  font-size: 9pt; background: #eef1f6; padding: 1pt 3.5pt;
  border-radius: 2.5pt; color: #22304a;
}

pre {
  background: #f6f8fb; border: 0.75pt solid #d8dee8; border-left: 3pt solid #4F81BD;
  border-radius: 3pt; padding: 8pt 10pt; margin: 0 0 9pt;
  overflow-x: auto; page-break-inside: avoid;
}
pre code {
  background: none; padding: 0; font-size: 8.5pt; line-height: 1.45;
  white-space: pre-wrap; word-break: break-word;
}

table {
  border-collapse: collapse; width: 100%; margin: 0 0 10pt;
  font-size: 9.5pt; page-break-inside: avoid;
}
th, td { border: 0.75pt solid #d8dee8; padding: 4.5pt 7pt; text-align: left; vertical-align: top; }
th { background: #1F497D; color: #fff; font-weight: 600; }
tr:nth-child(even) td { background: #f6f8fb; }

blockquote {
  margin: 0 0 9pt; padding: 7pt 11pt;
  background: #f2f6fc; border-left: 3pt solid #4F81BD; border-radius: 0 3pt 3pt 0;
  page-break-inside: avoid;
}
blockquote p:last-child { margin-bottom: 0; }

img {
  max-width: 100%; height: auto; display: block;
  margin: 7pt auto 11pt; border: 0.75pt solid #d8dee8; border-radius: 3pt;
  page-break-inside: avoid;
}

hr { border: 0; border-top: 0.75pt solid #d8dee8; margin: 13pt 0; }

strong { color: #14203a; }
"""

# Overrides for documents with a hard page budget - the SIH architecture
# document is capped at two pages, and the per-section page breaks that make a
# long reference readable turn a six-section brief into six pages.
COMPACT_CSS = """
@page { size: A4; margin: 10mm 11mm 10mm 11mm; }
body { font-size: 8.6pt; line-height: 1.34; }
h1 { font-size: 15pt; margin: 0 0 4pt; padding-bottom: 3pt; border-bottom-width: 2pt; }
h2 { page-break-before: auto; font-size: 10.5pt; margin: 8pt 0 4pt;
     padding-bottom: 2pt; }
h3 { font-size: 9pt; margin: 6pt 0 3pt; }
p  { margin: 0 0 4pt; }
ul, ol { margin: 0 0 4pt; padding-left: 13pt; }
li { margin-bottom: 1.5pt; }
pre { padding: 5pt 7pt; margin: 0 0 5pt; }
pre code { font-size: 7.2pt; line-height: 1.32; }
code { font-size: 7.6pt; }
table { font-size: 7.8pt; margin: 0 0 5pt; }
th, td { padding: 2.5pt 4pt; }
blockquote { padding: 4pt 8pt; margin: 0 0 5pt; }
hr { margin: 6pt 0; }
img { margin: 4pt auto 5pt; }
"""


def find_chrome() -> Path:
    for path in CHROME_CANDIDATES:
        if path.exists():
            return path
    raise SystemExit(
        "Chrome or Edge not found. Install one, or add its path to "
        "CHROME_CANDIDATES in this script."
    )


def inline_images(html: str, base_dir: Path) -> tuple[str, int]:
    """Replace every relative <img> source with a base64 data URI.

    Matches the whole tag and then finds `src` inside it, rather than assuming
    `src` comes first. Python-Markdown emits `<img alt="..." src="..." />`, so a
    pattern anchored on `<img src=` silently matches nothing and every image
    quietly vanishes from the PDF.

    Returns the rewritten HTML and the number of images inlined, so the caller
    can fail loudly instead of shipping a PDF with blank spaces in it.
    """
    count = 0

    def repl(match: re.Match) -> str:
        nonlocal count
        tag = match.group(0)
        src_match = re.search(r'src="([^"]+)"', tag)
        if not src_match:
            return tag
        src = src_match.group(1)
        if src.startswith(("http://", "https://", "data:")):
            return tag
        path = (base_dir / src).resolve()
        if not path.exists():
            print(f"  warning: image not found: {src}", file=sys.stderr)
            return tag
        mime = mimetypes.guess_type(path.name)[0] or "image/png"
        data = base64.b64encode(path.read_bytes()).decode("ascii")
        count += 1
        return tag.replace(src_match.group(0), f'src="data:{mime};base64,{data}"')

    return re.sub(r"<img\b[^>]*>", repl, html), count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--compact", action="store_true",
                        help="tighten spacing and drop per-section page breaks, "
                             "for documents with a page limit")
    parser.add_argument("--max-pages", type=int, default=None,
                        help="fail if the result exceeds this many pages")
    args = parser.parse_args()

    if not args.source.exists():
        raise SystemExit(f"Not found: {args.source}")
    out = args.out or args.source.with_suffix(".pdf")

    try:
        import markdown
    except ImportError:
        raise SystemExit("pip install markdown")

    text = args.source.read_text(encoding="utf-8")
    body = markdown.markdown(
        text,
        extensions=["tables", "fenced_code", "toc", "attr_list", "sane_lists"],
    )
    expected = len(re.findall(r"<img\b", body))
    body, inlined = inline_images(body, args.source.parent)
    if inlined != expected:
        raise SystemExit(
            f"Only {inlined} of {expected} images were inlined — the PDF would "
            "ship with blank gaps. Check the image paths in the source."
        )
    print(f"  inlined {inlined} images")

    style = CSS + (COMPACT_CSS if args.compact else "")
    html = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{args.source.stem}</title><style>{style}</style>"
        f"</head><body>{body}</body></html>"
    )

    tmp_dir = Path(tempfile.mkdtemp(prefix="md2pdf_"))
    tmp_html = tmp_dir / "doc.html"
    tmp_html.write_text(html, encoding="utf-8")

    chrome = find_chrome()
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            str(chrome), "--headless=new", "--disable-gpu", "--no-sandbox",
            "--no-pdf-header-footer",
            # Give the page time to lay out the inlined images before printing.
            "--virtual-time-budget=20000",
            f"--print-to-pdf={out.resolve()}",
            tmp_html.resolve().as_uri(),
        ],
        check=True,
        capture_output=True,
    )

    if not out.exists():
        raise SystemExit("Chrome did not produce a PDF.")

    pages = None
    try:
        import pymupdf
        with pymupdf.open(out) as doc:
            pages = doc.page_count
    except ImportError:
        pass

    suffix = f", {pages} pages" if pages else ""
    print(f"wrote {out}  ({out.stat().st_size / 1024:.0f} KB{suffix})")

    # A page limit is a submission requirement, not a suggestion - fail loudly
    # rather than let an over-long deliverable go out unnoticed.
    if args.max_pages and pages and pages > args.max_pages:
        raise SystemExit(
            f"ERROR: {pages} pages exceeds the {args.max_pages}-page limit. "
            "Trim the source or pass --compact."
        )


if __name__ == "__main__":
    main()
