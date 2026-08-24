"""Fill the official SIH 2026 idea-submission template with our content.

Run:
    python docs/make_ppt.py                     # uses the template in Downloads
    python docs/make_ppt.py --template X --out Y

The template's own rules drive every layout decision here:

  - **Six slides maximum, title slide included.** So the instructions slide is
    deleted and nothing new is added: exactly the five content sections the
    template defines, and no appendix.
  - **"Avoid paragraphs, use points / diagrams / infographics."** Content is
    laid out as labelled cards, a pipeline diagram and a results table. There
    is no running prose anywhere on the deck.
  - **"Only use the provided template without changing the idea details
    pointers."** Section titles are untouched. Each section's guidance pointers
    become the card headings, so a reviewer can still see the required
    structure - we answer the pointers rather than replacing them.

Colours and fonts are read off the template's own theme (Times New Roman
titles, Arial body, #1F497D / #4F81BD) so added shapes look native rather than
pasted in.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PIL import Image
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt

# --------------------------------------------------------------------------
# Design tokens, taken from the template theme
# --------------------------------------------------------------------------

NAVY = RGBColor(0x1F, 0x49, 0x7D)      # theme dk1 - headings, dark bands
BLUE = RGBColor(0x4F, 0x81, 0xBD)      # theme accent1 - primary cards
RED = RGBColor(0xC0, 0x50, 0x4D)       # theme accent2 - risks, the problem
GREEN = RGBColor(0x77, 0x93, 0x3C)     # theme accent3, darkened for contrast
SLATE = RGBColor(0x33, 0x3F, 0x50)     # body text
MUTED = RGBColor(0x5A, 0x64, 0x78)     # secondary text
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
CARD_BG = RGBColor(0xF2, 0xF5, 0xFA)   # very light blue-grey card fill
CARD_LINE = RGBColor(0xD3, 0xDD, 0xEA)

BODY_FONT = "Arial"

# Usable content band, in inches. Above 1.35 sits the title and the team oval;
# below 6.85 sits the template's footer bar.
TOP = 1.42
BOTTOM = 6.80
LEFT = 0.45
RIGHT = 12.85
WIDTH = RIGHT - LEFT


# --------------------------------------------------------------------------
# Shape helpers
# --------------------------------------------------------------------------


def clear(shape) -> None:
    """Empty a text frame without destroying the shape."""
    tf = shape.text_frame
    tf.clear()
    tf.paragraphs[0].text = ""


def set_text(tf, lines, *, size=12, color=SLATE, bold=False, space_after=4,
             align=PP_ALIGN.LEFT, bullet_char="• "):
    """Write lines into a text frame.

    Args:
        lines: list of str, or (text, level) tuples. Level 0 gets a bullet,
            level 1 is an unbulleted sub-line, level 2 is a bold sub-heading.
    """
    tf.clear()
    tf.word_wrap = True
    first = True

    for item in lines:
        text, level = item if isinstance(item, tuple) else (item, 0)
        para = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        para.alignment = align
        para.space_after = Pt(space_after)

        run = para.add_run()
        if level == 0:
            run.text = f"{bullet_char}{text}"
            run.font.size = Pt(size)
            run.font.color.rgb = color
            run.font.bold = bold
        elif level == 1:
            run.text = f"    {text}"
            run.font.size = Pt(size - 1)
            run.font.color.rgb = MUTED
        else:
            run.text = text
            run.font.size = Pt(size + 1)
            run.font.color.rgb = NAVY
            run.font.bold = True
        run.font.name = BODY_FONT


def add_card(slide, x, y, w, h, title, lines, *, accent=BLUE, size=11,
             title_size=12.5):
    """A titled card: coloured header strip over a light body panel."""
    head_h = 0.36
    head = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                  Inches(x), Inches(y), Inches(w), Inches(head_h))
    head.fill.solid()
    head.fill.fore_color.rgb = accent
    head.line.fill.background()
    head.shadow.inherit = False
    tf = head.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.10)
    tf.margin_top = Inches(0.02)
    tf.margin_bottom = 0
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    r = p.add_run()
    r.text = title
    r.font.size = Pt(title_size)
    r.font.bold = True
    r.font.color.rgb = WHITE
    r.font.name = BODY_FONT

    body = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                                  Inches(x), Inches(y + head_h),
                                  Inches(w), Inches(h - head_h))
    body.fill.solid()
    body.fill.fore_color.rgb = CARD_BG
    body.line.color.rgb = CARD_LINE
    body.line.width = Pt(0.75)
    body.shadow.inherit = False
    btf = body.text_frame
    # Autoshapes default to middle anchoring, which parks a short list in the
    # vertical centre of its card and leaves a dead band above it.
    btf.vertical_anchor = MSO_ANCHOR.TOP
    btf.margin_left = Inches(0.13)
    btf.margin_right = Inches(0.10)
    btf.margin_top = Inches(0.11)
    set_text(btf, lines, size=size)
    return body


def set_title(slide, text: str) -> None:
    """Replace a title's text while keeping the template's title formatting.

    The title frame holds several runs, so overwriting only the first leaves
    the rest of the placeholder text visible underneath. Capture the font off
    run 0, clear the frame, then rebuild a single run with it.
    """
    tf = find(slide, "Title 1").text_frame
    src = tf.paragraphs[0].runs[0].font
    name, size, bold = src.name, src.size, src.bold
    tf.clear()
    run = tf.paragraphs[0].add_run()
    run.text = text
    run.font.name = name
    run.font.size = size
    run.font.bold = bold


def add_band(slide, x, y, w, h, text, *, fill=NAVY, size=14, color=WHITE,
             align=PP_ALIGN.CENTER, bold=True):
    """A full-width statement band."""
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                 Inches(x), Inches(y), Inches(w), Inches(h))
    box.fill.solid()
    box.fill.fore_color.rgb = fill
    box.line.fill.background()
    box.shadow.inherit = False
    tf = box.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    tf.margin_left = Inches(0.15)
    tf.margin_right = Inches(0.15)
    p = tf.paragraphs[0]
    p.alignment = align
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.color.rgb = color
    r.font.name = BODY_FONT
    return box


def add_step(slide, x, y, w, h, headline, detail, *, fill=BLUE):
    """One box in the pipeline diagram."""
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                 Inches(x), Inches(y), Inches(w), Inches(h))
    box.fill.solid()
    box.fill.fore_color.rgb = fill
    box.line.fill.background()
    box.shadow.inherit = False
    tf = box.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    tf.margin_left = Inches(0.06)
    tf.margin_right = Inches(0.06)
    tf.margin_top = Inches(0.04)

    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = headline
    r.font.size = Pt(10.5)
    r.font.bold = True
    r.font.color.rgb = WHITE
    r.font.name = BODY_FONT

    p2 = tf.add_paragraph()
    p2.alignment = PP_ALIGN.CENTER
    r2 = p2.add_run()
    r2.text = detail
    r2.font.size = Pt(8.5)
    r2.font.color.rgb = RGBColor(0xE4, 0xEC, 0xF7)
    r2.font.name = BODY_FONT
    return box


def add_arrow(slide, x, y, w, h):
    arr = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW,
                                 Inches(x), Inches(y), Inches(w), Inches(h))
    arr.fill.solid()
    arr.fill.fore_color.rgb = RGBColor(0xB8, 0xC6, 0xDA)
    arr.line.fill.background()
    arr.shadow.inherit = False
    return arr


def add_table(slide, x, y, w, h, rows_data, col_widths=None, *, header_fill=NAVY,
              size=10, highlight_row=None):
    n_rows, n_cols = len(rows_data), len(rows_data[0])
    shape = slide.shapes.add_table(n_rows, n_cols, Inches(x), Inches(y),
                                   Inches(w), Inches(h))
    table = shape.table
    if col_widths:
        for i, cw in enumerate(col_widths):
            table.columns[i].width = Inches(cw)

    for ri, row in enumerate(rows_data):
        table.rows[ri].height = Inches(h / n_rows)
        for ci, val in enumerate(row):
            cell = table.cell(ri, ci)
            cell.margin_left = Inches(0.07)
            cell.margin_right = Inches(0.05)
            cell.margin_top = Inches(0.02)
            cell.margin_bottom = Inches(0.02)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            cell.fill.solid()
            if ri == 0:
                cell.fill.fore_color.rgb = header_fill
            elif ri == highlight_row:
                cell.fill.fore_color.rgb = RGBColor(0xE3, 0xEE, 0xE0)
            else:
                cell.fill.fore_color.rgb = WHITE

            tf = cell.text_frame
            tf.word_wrap = True
            p = tf.paragraphs[0]
            p.alignment = PP_ALIGN.CENTER if ci else PP_ALIGN.LEFT
            r = p.add_run()
            r.text = str(val)
            r.font.size = Pt(size)
            r.font.name = BODY_FONT
            r.font.bold = (ri == 0) or (ri == highlight_row)
            r.font.color.rgb = WHITE if ri == 0 else SLATE
    return table


def delete_slide(prs, index: int) -> None:
    """python-pptx has no public slide delete; drop the id and the relationship."""
    xml_slides = prs.slides._sldIdLst
    slides = list(xml_slides)
    rid = slides[index].get(
        "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
    )
    prs.part.drop_rel(rid)
    xml_slides.remove(slides[index])


def find(slide, name_startswith):
    for sh in slide.shapes:
        if sh.name.startswith(name_startswith):
            return sh
    return None


# --------------------------------------------------------------------------
# Slide builders
# --------------------------------------------------------------------------


def build_title(slide, team_id: str, team_name: str) -> None:
    box = find(slide, "TextBox 9")
    tf = box.text_frame
    tf.clear()
    tf.word_wrap = True

    rows = [
        ("Problem Statement ID", "26153"),
        ("Problem Statement Title",
         "AI based Network Attack Forecasting from Network Traffic Data"),
        ("Theme", "Blockchain & Cybersecurity"),
        ("PS Category", "Software"),
        ("Organisation", "National Technical Research Organisation (NTRO)"),
        ("Team ID", team_id),
        ("Team Name", team_name),
    ]
    for i, (k, v) in enumerate(rows):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(7)
        rk = p.add_run()
        rk.text = f"{k} – "
        rk.font.size = Pt(13)
        rk.font.bold = True
        rk.font.color.rgb = NAVY
        rk.font.name = BODY_FONT
        rv = p.add_run()
        rv.text = v
        rv.font.size = Pt(13)
        rv.font.color.rgb = SLATE
        rv.font.name = BODY_FONT


def build_idea(slide) -> None:
    set_title(slide, "PREDICTIVE CYBER DEFENCE")
    clear(find(slide, "TextBox 8"))

    add_band(slide, LEFT, TOP, WIDTH, 0.62,
             "We do not classify traffic — we learn how a network's state "
             "evolves, then run that model forward to see where a host is heading.",
             size=13.5)

    col_w, gap = 3.95, 0.25
    y, h = TOP + 0.80, 3.62
    add_card(slide, LEFT, y, col_w, h,
             "Proposed Solution",
             [
                 "Traffic → 60-second windows; each becomes a 39-feature "
                 "snapshot of one host",
                 "A world model learns the transition: what state usually "
                 "follows this state",
                 "Stop feeding it traffic — it generates the next 10 states "
                 "on its own",
                 "Each imagined state is scored: infiltration risk + MITRE "
                 "ATT&CK stage",
             ], accent=BLUE)

    add_card(slide, LEFT + col_w + gap, y, col_w, h,
             "How It Addresses the Problem",
             [
                 "Answers “where is this host heading”, not “was "
                 "that flow bad”",
                 "10-minute lookahead — acts before the kill chain closes",
                 "Flow-level and packet-level features together: TTL variance, "
                 "TCP window, retransmissions, scan signatures",
                 "Every alert carries three explanations — no black box",
             ], accent=NAVY)

    add_card(slide, LEFT + 2 * (col_w + gap), y, col_w, h,
             "Innovation and Uniqueness",
             [
                 "World model, not a classifier — the heads read the latent "
                 "state, so they still work on imagined states",
                 "Provable: an imagination-only loss yields zero encoder "
                 "gradient (asserted in our test suite)",
                 "ATT&CK stages derived from CTU-13's own flow annotations, not "
                 "hand-waved",
                 "Runs fully offline on CPU — 138k parameters",
             ], accent=GREEN)

    add_band(slide, LEFT, y + h + 0.20, WIDTH, 0.56,
             "Working prototype today  •  258,229 network states from all 13 CTU-13 "
             "captures  •  28 of 30 infected hosts flagged at 4.9% false alarms "
             "•  transfers to unseen malware families  •  runs offline on CPU",
             fill=GREEN, size=12)


def build_technical(slide) -> None:
    clear(find(slide, "TextBox 8"))

    steps = [
        ("Ingest", "NetFlow / PCAP\n(Scapy)"),
        ("Feature extraction", "39 flow + 23 packet\nfeatures"),
        ("Network state", "60-second\n(host, window) cells"),
        ("World model", "Encoder → GRU →\nprior / posterior"),
        ("Forward simulation", "10 imagined states\n+ uncertainty band"),
        ("Decision support", "Risk • ATT&CK stage\n• explanations"),
    ]
    n = len(steps)
    arrow_w, gap = 0.22, 0.07
    box_w = (WIDTH - (n - 1) * (arrow_w + 2 * gap)) / n
    y, h = TOP + 0.04, 0.95
    x = LEFT
    for i, (head, detail) in enumerate(steps):
        fill = NAVY if i in (3, 4) else BLUE
        add_step(slide, x, y, box_w, h, head, detail, fill=fill)
        x += box_w
        if i < n - 1:
            add_arrow(slide, x + gap, y + h / 2 - 0.11, arrow_w, 0.22)
            x += arrow_w + 2 * gap

    cy, ch = y + h + 0.24, 3.35
    col_w, cgap = 4.0, 0.22
    add_card(slide, LEFT, cy, col_w, ch,
             "Technologies Used",
             [
                 "Python 3.13, PyTorch (CPU-only)",
                 "Scapy — raw PCAP parsing, flow reconstruction",
                 "pandas / NumPy — vectorised feature pipeline",
                 "scikit-learn — baselines and metrics",
                 "FastAPI + zero-dependency HTML dashboard",
                 "100% open source • no cloud, no external API",
             ], accent=BLUE)

    add_card(slide, LEFT + col_w + cgap, cy, col_w, ch,
             "Model — Recurrent State-Space",
             [
                 "Encoder compresses each window into a latent state",
                 "GRU carries context; a prior predicts the next latent "
                 "without seeing traffic",
                 "Decoder reconstructs traffic, so the latent must encode "
                 "real network state",
                 "Trained on its own rollouts, so multi-step forecasting is "
                 "learned, not hoped for",
                 "Causal attention — masked so no step sees its future",
             ], accent=NAVY)

    add_card(slide, LEFT + 2 * (col_w + cgap), cy, col_w, ch,
             "Methodology and Validation",
             [
                 "Dataset: CTU-13 (13 real botnet captures, CC BY)",
                 "Split by time, never randomly — train on each capture's "
                 "past, test on its future, with a guard band",
                 "Baselines given identical features, scaler and labels",
                 "Deterministic inference + seeded rollouts — the benchmark "
                 "reproduces byte for byte",
                 "Test suites for model shapes and PCAP header parsing",
             ], accent=GREEN)

    add_band(slide, LEFT, cy + ch + 0.16, WIDTH, 0.44,
             "Offline dashboard: minute-by-minute replay of the forecast  •  "
             "kill-chain timeline  •  network topology  •  three explanation "
             "channels per prediction",
             fill=RED, size=11.5)


def build_feasibility(slide, images_dir: Path) -> None:
    clear(find(slide, "TextBox 8"))

    left_w = 6.15
    right_x = LEFT + left_w + 0.35
    right_w = RIGHT - right_x

    add_band(slide, LEFT, TOP, left_w, 0.44,
             "Feasibility — where the model actually wins", fill=NAVY, size=12.5)

    add_table(slide, LEFT, TOP + 0.54, left_w, 1.60,
              [
                  ["Stage forecast, macro-F1 by horizon", "+2", "+4", "+10"],
                  ["World model (ours)", "0.583", "0.642", "0.524"],
                  ["“assume nothing changes” baseline", "0.473", "0.474", "0.436"],
                  ["Detection F1: 0.979 vs 0.977 — a tie", "", "", ""],
              ],
              col_widths=[2.85, 1.10, 1.10, 1.10], highlight_row=1, size=10)

    add_card(slide, LEFT, TOP + 2.24, left_w, 3.12,
             "Why it is deployable",
             [
                 "Runs on a laptop CPU — no GPU, no cloud, no licence cost",
                 "Consumes NetFlow/IPFIX that enterprises already export",
                 "Sub-second triage of a full capture after first load",
                 "Fully offline — suitable for air-gapped Critical "
                 "Information Infrastructure",
                 "MITRE stage macro-F1 0.537 vs 0.453 for the baseline",
                 "Transfers to unseen malware families — trained on Neris and "
                 "Rbot, F1 0.874 and ROC-AUC 0.982 on Virut and Murlo",
                 "Replay reconstructs what the model knew at every minute, so "
                 "an analyst can audit a decision after the fact",
             ], accent=BLUE, size=10)

    # One header only. An earlier revision stacked a band above this card and
    # the slide came out with two red bars saying the same thing.
    add_card(slide, right_x, TOP, right_w, 2.70,
             "Potential Challenges and Risks  →  Our Mitigation",
             [
                 ("Label leak through metadata", 2),
                 ("The available PCAP held only botnet traffic, so a “packet "
                  "data present” flag became a perfect label proxy → detected "
                  "it, removed it; F1 rose 0.23 → 0.98", 1),
                 ("Detection is no better than logistic regression", 2),
                 ("0.979 vs 0.977. An earlier 0.984-vs-0.744 gap was an "
                  "artefact of a test split whose positives came from one "
                  "host → the model earns its place on forecasting, not "
                  "detection", 1),
                 ("Short-burst compromise", 2),
                 ("The risk head needs sustained activity → the unsupervised "
                  "surprise channel covers that gap; triage flags on either, "
                  "catching 28 of 30 hosts at 4.9% false alarms", 1),
                 ("Stage forecasting does not cross families", 2),
                 ("Detection transfers to unseen malware, progression does "
                  "not — reported, not hidden", 1),
             ], accent=RED, size=9.5)

    # A screenshot from the running prototype. The deck is read without the
    # demo in the room, so one frame of real output does more for credibility
    # than another paragraph claiming the thing works. The kill-chain strip is
    # the right pick: a ~20:1 aspect fits a full-width band, and the blue-to-red
    # break is the reconnaissance-to-exfiltration transition we forecast.
    # A screenshot from the running prototype, sized to actually be recognised
    # as one. The first attempt used the kill-chain strip: correct content, but
    # a 34:1 sliver at the foot of the slide that reads as a decorative rule
    # rather than as evidence the software exists. The topology view survives
    # being small - the red starburst is legible at a glance.
    shot = images_dir / "topology-wide.png"
    y = TOP + 2.80
    add_band(slide, right_x, y, right_w, 0.28,
             "Live output — the compromised host and its malicious fan-out",
             fill=GREEN, size=10)
    if shot.exists():
        # Height from the crop's own aspect so the screenshot is never
        # stretched; a squashed screenshot looks exactly like one.
        with Image.open(shot) as img:
            aspect = img.width / img.height
        slide.shapes.add_picture(
            str(shot), Inches(right_x), Inches(y + 0.35),
            width=Inches(right_w), height=Inches(right_w / aspect),
        )
    else:
        print(f"  warning: {shot.name} missing, slide 4 screenshot skipped",
              file=sys.stderr)


def build_impact(slide) -> None:
    clear(find(slide, "TextBox 8"))

    add_band(slide, LEFT, TOP, WIDTH, 0.56,
             "Shifting the defender from reacting after compromise to acting "
             "during the kill chain", size=13.5)

    col_w, gap = 3.95, 0.25
    y, h = TOP + 0.72, 3.52

    add_card(slide, LEFT, y, col_w, h,
             "Who Benefits",
             [
                 "SOC analysts — a ranked queue instead of an alert flood",
                 "Critical Information Infrastructure: power, banking, "
                 "telecom, transport",
                 "CERT-In and national response teams",
                 "Enterprises already exporting NetFlow, with no new hardware "
                 "to buy",
             ], accent=BLUE)

    add_card(slide, LEFT + col_w + gap, y, col_w, h,
             "Operational Benefits",
             [
                 "Up to 10 minutes of warning before the kill chain closes",
                 "False positive rate 0.000 on the held-out period — "
                 "analyst time is not wasted",
                 "Replay lets an analyst rewind an incident minute by minute "
                 "and see what the model knew, when",
                 "Explanations make alerts auditable and challengeable",
                 "ATT&CK stage names map onto existing playbooks",
             ], accent=NAVY)

    add_card(slide, LEFT + 2 * (col_w + gap), y, col_w, h,
             "Strategic and Economic",
             [
                 "Fully indigenous, open-source — no foreign vendor "
                 "dependency for national infrastructure",
                 "Zero licence cost; runs on existing hardware",
                 "Air-gap friendly — nothing leaves the network",
                 "Earlier detection cuts breach cost, downtime and data loss",
             ], accent=GREEN)

    add_band(slide, LEFT, y + h + 0.20, WIDTH, 0.56,
             "Every claim on this deck is reproducible from the repository: "
             "one command prepares the data, one trains, one benchmarks.",
             fill=GREEN, size=12.5)


def build_references(slide) -> None:
    clear(find(slide, "TextBox 8"))

    col_w, gap = 6.15, 0.55
    y, h = TOP, 5.34

    add_card(slide, LEFT, y, col_w, h,
             "Datasets and Knowledge Bases",
             [
                 ("CTU-13 Dataset — Stratosphere IPS, CTU Prague", 2),
                 ("García et al., “An empirical comparison of botnet "
                  "detection methods”, Computers & Security, 2014", 1),
                 ("mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/", 1),
                 ("MITRE ATT&CK Enterprise Matrix", 2),
                 ("Tactics TA0043, TA0001, TA0008, TA0011, TA0010", 1),
                 ("attack.mitre.org", 1),
                 ("CIC-IDS2017 / CSE-CIC-IDS2018 — UNB", 2),
                 ("Reviewed; access now gated behind registration", 1),
                 ("NCIIPC — nciipc.gov.in", 2),
             ], accent=BLUE, size=10.5)

    add_card(slide, LEFT + col_w + gap, y, col_w, h,
             "Methods and Literature",
             [
                 ("World models / latent dynamics", 2),
                 ("Ha & Schmidhuber, “World Models”, NeurIPS 2018", 1),
                 ("Hafner et al., “Learning Latent Dynamics for Planning "
                  "from Pixels” (PlaNet/RSSM), ICML 2019", 1),
                 ("Hafner et al., “Dream to Control” (Dreamer), ICLR 2020", 1),
                 ("Explainability", 2),
                 ("Sundararajan et al., “Axiomatic Attribution for Deep "
                  "Networks” (Integrated Gradients), ICML 2017", 1),
                 ("Vaswani et al., “Attention Is All You Need”, "
                  "NeurIPS 2017", 1),
                 ("Tools", 2),
                 ("Scapy • PyTorch • scikit-learn • FastAPI", 1),
             ], accent=NAVY, size=10.5)


# --------------------------------------------------------------------------


def main() -> None:
    default_template = (Path.home() / "Downloads" /
                        "SIH2026-IDEA-Presentation-Format.pptx")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, default=default_template)
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).parent.parent /
                        "SIH2026_PS26153_Presentation.pptx")
    parser.add_argument("--team-id", default="[Team ID]")
    parser.add_argument("--team-name", default="Git with It")
    args = parser.parse_args()

    if not args.template.exists():
        raise SystemExit(f"Template not found: {args.template}")

    prs = Presentation(str(args.template))

    build_title(prs.slides[0], args.team_id, args.team_name)
    build_idea(prs.slides[1])
    build_technical(prs.slides[2])
    build_feasibility(prs.slides[3], Path(__file__).parent / "images")
    build_impact(prs.slides[4])
    build_references(prs.slides[5])

    # The template caps the deck at six slides including the title, and says
    # the instructions slide may be removed before upload.
    delete_slide(prs, 6)

    # The team-name ovals are template furniture; fill them so the deck does
    # not go out with placeholder text on every slide.
    for slide in prs.slides:
        for shape in slide.shapes:
            if shape.name.startswith("Oval") and shape.has_text_frame:
                if "Your Team Name" in shape.text_frame.text:
                    for para in shape.text_frame.paragraphs:
                        for run in para.runs:
                            run.text = args.team_name
                            run.font.size = Pt(9)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(args.out))
    print(f"wrote {args.out}  ({len(prs.slides.__iter__.__self__._sldIdLst)} slides)")


if __name__ == "__main__":
    main()
