#!/usr/bin/env python3
"""Build the canonical eight-page Detection Threat Landscape PDF from report.json."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from datetime import date
from pathlib import Path

from reportlab.lib.colors import Color, HexColor, white
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas


PAGE_W, PAGE_H = A4
MM = 72 / 25.4
INK = HexColor("#09090D")
INK_SOFT = HexColor("#17131F")
PAPER = HexColor("#FFFFFF")
PAPER_SOFT = HexColor("#F6F4FA")
PAPER_VIOLET = HexColor("#EEE9FF")
MUTED = HexColor("#625F6D")
LINE = HexColor("#DED9E7")
LINE_STRONG = HexColor("#B9B1C8")
VIOLET_DEEP = HexColor("#5420A8")
VIOLET = HexColor("#8957F4")
MAGENTA = HexColor("#DA3FE6")
LIME = HexColor("#C7F000")
SUCCESS = HexColor("#176B3A")
DANGER = HexColor("#B42318")
LAYOUT_VERSION = "2.0"

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")
FONT_REGULAR = "DTTL-Regular"
FONT_BOLD = "DTTL-Bold"
FONT_MONO = "DTTL-Mono"


def register_fonts() -> None:
    pdfmetrics.registerFont(TTFont(FONT_REGULAR, str(FONT_DIR / "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont(FONT_BOLD, str(FONT_DIR / "DejaVuSans-Bold.ttf")))
    pdfmetrics.registerFont(TTFont(FONT_MONO, str(FONT_DIR / "DejaVuSansMono.ttf")))


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def clean_text(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def split_words(text: str, font: str, size: float, width: float) -> list[str]:
    lines: list[str] = []
    for paragraph in str(text).splitlines() or [""]:
        words = paragraph.split()
        if not words:
            lines.append("")
            continue
        current = words[0]
        for word in words[1:]:
            candidate = f"{current} {word}"
            if pdfmetrics.stringWidth(candidate, font, size) <= width:
                current = candidate
            else:
                lines.append(current)
                current = word
        lines.append(current)
    return lines


def draw_wrapped(
    c: canvas.Canvas,
    text: str,
    x: float,
    y: float,
    width: float,
    *,
    font: str = FONT_REGULAR,
    size: float = 8.4,
    leading: float | None = None,
    color=INK,
    max_lines: int | None = None,
) -> float:
    leading = leading or size * 1.38
    lines = split_words(clean_text(text), font, size, width)
    if max_lines and len(lines) > max_lines:
        lines = lines[:max_lines]
        tail = lines[-1]
        while tail and pdfmetrics.stringWidth(tail + "...", font, size) > width:
            tail = tail[:-1]
        lines[-1] = tail.rstrip() + "..."
    c.setFont(font, size)
    c.setFillColor(color)
    for line in lines:
        c.drawString(x, y, line)
        y -= leading
    return y


def draw_label(c: canvas.Canvas, text: str, x: float, y: float, color=VIOLET) -> None:
    c.setFillColor(color)
    c.setFont(FONT_BOLD, 6.4)
    c.drawString(x, y, clean_text(text).upper())


def draw_card(
    c: canvas.Canvas,
    x: float,
    top: float,
    width: float,
    height: float,
    label: str,
    body: str,
    *,
    accent=VIOLET,
    fill=PAPER_SOFT,
    body_size: float = 8.0,
    max_lines: int | None = None,
) -> None:
    c.setFillColor(fill)
    c.setStrokeColor(LINE)
    c.setLineWidth(0.45)
    c.roundRect(x, top - height, width, height, 3 * MM, fill=1, stroke=1)
    c.setFillColor(accent)
    c.roundRect(x, top - height, 1.1 * MM, height, 0.5 * MM, fill=1, stroke=0)
    draw_label(c, label, x + 5 * MM, top - 7 * MM, accent)
    draw_wrapped(
        c,
        body,
        x + 5 * MM,
        top - 13 * MM,
        width - 10 * MM,
        size=body_size,
        leading=body_size * 1.42,
        max_lines=max_lines,
    )


def draw_bullet_list(
    c: canvas.Canvas,
    items: list[str],
    x: float,
    y: float,
    width: float,
    *,
    size: float = 7.7,
    accent=VIOLET,
    max_lines_each: int = 3,
    gap: float = 2.2 * MM,
) -> float:
    for item in items:
        c.setFillColor(accent)
        c.circle(x + 1.2 * MM, y + 0.7 * MM, 0.8 * MM, fill=1, stroke=0)
        y = draw_wrapped(
            c,
            item,
            x + 4 * MM,
            y + 1.8 * MM,
            width - 4 * MM,
            size=size,
            leading=size * 1.42,
            max_lines=max_lines_each,
        )
        y -= gap
    return y


def draw_top_bar(c: canvas.Canvas) -> None:
    segments = [(0, 0.19, INK), (0.19, 0.58, VIOLET_DEEP), (0.58, 0.86, VIOLET), (0.86, 1, LIME)]
    for start, end, color in segments:
        c.setFillColor(color)
        c.rect(start * PAGE_W, PAGE_H - 2.2 * MM, (end - start) * PAGE_W, 2.2 * MM, fill=1, stroke=0)


def draw_internal_base(c: canvas.Canvas, report: dict, page_no: int, section: str) -> None:
    c.setFillColor(PAPER)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    draw_top_bar(c)
    c.setFillColor(INK)
    c.setFont(FONT_BOLD, 6.5)
    c.drawString(15 * MM, PAGE_H - 10 * MM, "DETECTION THREAT LANDSCAPE")
    c.setFillColor(MUTED)
    c.setFont(FONT_BOLD, 6.3)
    c.drawRightString(PAGE_W - 15 * MM, PAGE_H - 10 * MM, section.upper())
    c.setStrokeColor(LINE)
    c.setLineWidth(0.35)
    c.line(15 * MM, 12 * MM, PAGE_W - 15 * MM, 12 * MM)
    c.setFillColor(MUTED)
    c.setFont(FONT_REGULAR, 6.3)
    c.drawString(15 * MM, 7 * MM, report["short_title"].upper())
    c.drawCentredString(PAGE_W / 2, 7 * MM, f"CANONICAL LAYOUT v{LAYOUT_VERSION}")
    c.drawRightString(PAGE_W - 15 * MM, 7 * MM, f"{page_no:02d} / 08")


def draw_section_header(c: canvas.Canvas, index: str, title: str, subtitle: str, tag: str) -> float:
    top = PAGE_H - 21 * MM
    c.setFillColor(VIOLET)
    c.circle(21 * MM, top - 4 * MM, 5.2 * MM, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont(FONT_BOLD, 7.2)
    c.drawCentredString(21 * MM, top - 6.1 * MM, index)
    c.setFillColor(INK)
    c.setFont(FONT_BOLD, 19)
    c.drawString(31 * MM, top, title)
    c.setFillColor(MUTED)
    c.setFont(FONT_REGULAR, 7.3)
    c.drawString(31 * MM, top - 6 * MM, subtitle)
    tag_width = max(24 * MM, pdfmetrics.stringWidth(tag.upper(), FONT_BOLD, 6.2) + 8 * MM)
    c.setFillColor(PAPER_VIOLET)
    c.roundRect(PAGE_W - 15 * MM - tag_width, top - 7 * MM, tag_width, 8 * MM, 4 * MM, fill=1, stroke=0)
    c.setFillColor(VIOLET_DEEP)
    c.setFont(FONT_BOLD, 6.2)
    c.drawCentredString(PAGE_W - 15 * MM - tag_width / 2, top - 4.2 * MM, tag.upper())
    return top - 17 * MM


def gradient_color(a: Color, b: Color, ratio: float) -> Color:
    return Color(
        a.red + (b.red - a.red) * ratio,
        a.green + (b.green - a.green) * ratio,
        a.blue + (b.blue - a.blue) * ratio,
    )


def draw_cover_background(c: canvas.Canvas) -> None:
    left = HexColor("#050509")
    right = HexColor("#25093D")
    steps = 150
    for i in range(steps):
        ratio = i / (steps - 1)
        c.setFillColor(gradient_color(left, right, ratio))
        c.rect(i * PAGE_W / steps, 0, PAGE_W / steps + 1, PAGE_H, fill=1, stroke=0)
    c.saveState()
    c.setFillAlpha(0.18)
    c.setFillColor(MAGENTA)
    c.circle(PAGE_W * 0.80, PAGE_H * 0.84, 42 * MM, fill=1, stroke=0)
    c.setFillColor(VIOLET)
    c.circle(PAGE_W * 0.18, PAGE_H * 0.12, 48 * MM, fill=1, stroke=0)
    c.restoreState()


def draw_artwork(c: canvas.Canvas, report: dict) -> None:
    kind = report.get("artwork", {}).get("kind", "generic")
    x0, y0 = 128 * MM, 46 * MM
    width, height = 68 * MM, 216 * MM
    c.saveState()
    c.setStrokeAlpha(0.78)
    c.setFillAlpha(0.22)
    for i in range(7):
        c.setStrokeColor(Color(1, 1, 1, alpha=max(0.04, 0.18 - i * 0.018)))
        c.line(x0 + i * 10 * MM, y0, x0 + i * 10 * MM, y0 + height)
    for i in range(12):
        c.line(x0, y0 + i * 18 * MM, x0 + width, y0 + i * 18 * MM)
    c.setFillAlpha(1)
    c.setStrokeAlpha(1)

    seed = int(hashlib.sha256(report["id"].encode("utf-8")).hexdigest()[:8], 16)
    drift = ((seed % 9) - 4) * MM

    if kind == "supply-chain-ssh":
        c.setStrokeColor(VIOLET)
        c.setLineWidth(2.2)
        c.roundRect(x0 + 7 * MM, y0 + 144 * MM, 51 * MM, 28 * MM, 5 * MM, fill=0, stroke=1)
        c.setFillColor(white)
        c.setFont(FONT_BOLD, 8)
        c.drawCentredString(x0 + 32.5 * MM, y0 + 156 * MM, "EXTENSION")
        c.setFillColor(LIME)
        c.circle(x0 + 33 * MM, y0 + 112 * MM, 10 * MM, fill=1, stroke=0)
        c.setFillColor(INK)
        c.setFont(FONT_BOLD, 16)
        c.drawCentredString(x0 + 33 * MM, y0 + 108.5 * MM, "KEY")
        c.setStrokeColor(MAGENTA)
        c.setLineWidth(4)
        c.line(x0 + 33 * MM, y0 + 144 * MM, x0 + 33 * MM, y0 + 122 * MM)
        c.line(x0 + 33 * MM, y0 + 102 * MM, x0 + 33 * MM, y0 + 78 * MM)
        c.setStrokeColor(VIOLET)
        c.setLineWidth(3)
        c.arc(x0 + 7 * MM, y0 + 35 * MM, x0 + 59 * MM, y0 + 87 * MM, 15, 150)
        c.arc(x0 + 14 * MM, y0 + 42 * MM, x0 + 52 * MM, y0 + 80 * MM, 15, 150)
        c.setFillColor(MAGENTA)
        c.circle(x0 + 33 * MM, y0 + 58 * MM, 5 * MM, fill=1, stroke=0)
        c.setFillColor(white)
        c.setFont(FONT_BOLD, 7)
        c.drawCentredString(x0 + 33 * MM, y0 + 26 * MM, "REVERSE SSH")
    elif kind == "log-injection":
        c.setStrokeColor(VIOLET)
        c.setLineWidth(2)
        for i, w in enumerate((52, 47, 55, 43)):
            yy = y0 + (164 - i * 16) * MM
            c.roundRect(x0 + 5 * MM, yy, w * MM, 10 * MM, 3 * MM, fill=0, stroke=1)
        c.setFillColor(LIME)
        c.setFont(FONT_BOLD, 20)
        c.drawCentredString(x0 + 33 * MM, y0 + 93 * MM, "LOG")
        c.setStrokeColor(MAGENTA)
        c.setLineWidth(5)
        c.line(x0 + 33 * MM, y0 + 123 * MM, x0 + 33 * MM, y0 + 103 * MM)
        c.line(x0 + 33 * MM, y0 + 84 * MM, x0 + 33 * MM, y0 + 59 * MM)
        c.setFillColor(MAGENTA)
        c.circle(x0 + 33 * MM, y0 + 47 * MM, 15 * MM, fill=1, stroke=0)
        c.setFillColor(white)
        c.setFont(FONT_BOLD, 22)
        c.drawCentredString(x0 + 33 * MM, y0 + 40 * MM, ">$ _")
    elif kind == "cloud-role":
        c.setStrokeColor(VIOLET)
        c.setLineWidth(4)
        c.circle(x0 + 33 * MM, y0 + 151 * MM, 18 * MM, fill=0, stroke=1)
        c.setFillColor(MAGENTA)
        c.circle(x0 + 33 * MM, y0 + 151 * MM, 7 * MM, fill=1, stroke=0)
        c.setStrokeColor(LIME)
        c.line(x0 + 33 * MM, y0 + 132 * MM, x0 + 33 * MM, y0 + 95 * MM)
        c.line(x0 + 14 * MM, y0 + 95 * MM, x0 + 52 * MM, y0 + 95 * MM)
        c.line(x0 + 14 * MM, y0 + 95 * MM, x0 + 14 * MM, y0 + 65 * MM)
        c.line(x0 + 52 * MM, y0 + 95 * MM, x0 + 52 * MM, y0 + 65 * MM)
        for xx, label in ((x0 + 14 * MM, "APP"), (x0 + 52 * MM, "ROLE")):
            c.setFillColor(white)
            c.roundRect(xx - 12 * MM, y0 + 50 * MM, 24 * MM, 15 * MM, 4 * MM, fill=1, stroke=0)
            c.setFillColor(INK)
            c.setFont(FONT_BOLD, 7)
            c.drawCentredString(xx, y0 + 56 * MM, label)
    elif kind == "phishing-mail":
        c.setStrokeColor(VIOLET)
        c.setLineWidth(3)
        bx, by = x0 + 7 * MM, y0 + 128 * MM + drift
        c.roundRect(bx, by, 52 * MM, 34 * MM, 5 * MM, fill=0, stroke=1)
        c.line(bx, by + 34 * MM, bx + 26 * MM, by + 15 * MM)
        c.line(bx + 52 * MM, by + 34 * MM, bx + 26 * MM, by + 15 * MM)
        c.setFillColor(LIME)
        for row in range(4):
            for col in range(4):
                if (row * 5 + col + seed) % 3:
                    c.rect(x0 + (19 + col * 7) * MM, y0 + (72 + row * 7) * MM, 4 * MM, 4 * MM, fill=1, stroke=0)
        c.setStrokeColor(MAGENTA)
        c.line(x0 + 33 * MM, by - 5 * MM, x0 + 33 * MM, y0 + 104 * MM)
        c.setFillColor(MAGENTA)
        c.circle(x0 + 33 * MM, y0 + 48 * MM, 9 * MM, fill=1, stroke=0)
        c.setFillColor(white)
        c.setFont(FONT_BOLD, 10)
        c.drawCentredString(x0 + 33 * MM, y0 + 45 * MM, "ID")
    elif kind == "identity-access":
        c.setStrokeColor(VIOLET)
        c.setLineWidth(4)
        c.circle(x0 + 33 * MM, y0 + 154 * MM + drift, 18 * MM, fill=0, stroke=1)
        c.setFillColor(MAGENTA)
        c.circle(x0 + 33 * MM, y0 + 154 * MM + drift, 7 * MM, fill=1, stroke=0)
        c.setStrokeColor(LIME)
        c.setLineWidth(3)
        c.line(x0 + 33 * MM, y0 + 136 * MM + drift, x0 + 33 * MM, y0 + 97 * MM)
        c.line(x0 + 14 * MM, y0 + 97 * MM, x0 + 52 * MM, y0 + 97 * MM)
        for idx, xx in enumerate((x0 + 14 * MM, x0 + 52 * MM)):
            c.line(xx, y0 + 97 * MM, xx, y0 + 69 * MM + (idx * 3 - 1) * MM)
            c.setFillColor((white, LIME)[idx])
            c.roundRect(xx - 11 * MM, y0 + 54 * MM + (idx * 3 - 1) * MM, 22 * MM, 15 * MM, 4 * MM, fill=1, stroke=0)
            c.setFillColor(INK)
            c.setFont(FONT_BOLD, 6.5)
            c.drawCentredString(xx, y0 + 60 * MM + (idx * 3 - 1) * MM, ("USER", "ROLE")[idx])
    elif kind == "cloud-control":
        c.setStrokeColor(VIOLET)
        c.setLineWidth(3)
        cy = y0 + 147 * MM + drift
        c.arc(x0 + 7 * MM, cy - 18 * MM, x0 + 35 * MM, cy + 10 * MM, 15, 190)
        c.arc(x0 + 20 * MM, cy - 12 * MM, x0 + 54 * MM, cy + 22 * MM, 20, 220)
        c.line(x0 + 9 * MM, cy - 6 * MM, x0 + 57 * MM, cy - 6 * MM)
        c.setStrokeColor(MAGENTA)
        c.line(x0 + 33 * MM, cy - 8 * MM, x0 + 33 * MM, y0 + 91 * MM)
        for idx, (xx, yy) in enumerate(((15, 66), (51, 66), (33, 37))):
            c.setFillColor((LIME, VIOLET, MAGENTA)[idx])
            c.circle(x0 + xx * MM, y0 + yy * MM, (8 + (seed + idx) % 4) * MM, fill=1, stroke=0)
        c.setStrokeColor(LIME)
        c.line(x0 + 33 * MM, y0 + 91 * MM, x0 + 15 * MM, y0 + 74 * MM)
        c.line(x0 + 33 * MM, y0 + 91 * MM, x0 + 51 * MM, y0 + 74 * MM)
        c.line(x0 + 33 * MM, y0 + 91 * MM, x0 + 33 * MM, y0 + 48 * MM)
    elif kind == "persistence":
        c.setStrokeColor(VIOLET)
        c.setLineWidth(4)
        c.circle(x0 + 33 * MM, y0 + 142 * MM + drift, 25 * MM, fill=0, stroke=1)
        c.setStrokeColor(MAGENTA)
        c.line(x0 + 33 * MM, y0 + 142 * MM + drift, x0 + 33 * MM, y0 + 160 * MM + drift)
        c.line(x0 + 33 * MM, y0 + 142 * MM + drift, x0 + 47 * MM, y0 + 133 * MM + drift)
        c.setFillColor(LIME)
        c.circle(x0 + 33 * MM, y0 + 142 * MM + drift, 6 * MM, fill=1, stroke=0)
        for idx, label in enumerate(("BOOT", "TASK", "RUN")):
            yy = y0 + (88 - idx * 24) * MM
            c.setFillColor(Color(1, 1, 1, alpha=0.9))
            c.roundRect(x0 + (7 + (idx % 2) * 10) * MM, yy, 48 * MM, 14 * MM, 4 * MM, fill=1, stroke=0)
            c.setFillColor(INK)
            c.setFont(FONT_BOLD, 7)
            c.drawCentredString(x0 + (31 + (idx % 2) * 10) * MM, yy + 5.5 * MM, label)
    elif kind == "library-load":
        c.setStrokeColor(VIOLET)
        c.setLineWidth(3)
        c.roundRect(x0 + 6 * MM, y0 + 127 * MM + drift, 34 * MM, 48 * MM, 5 * MM, fill=0, stroke=1)
        c.setFillColor(MAGENTA)
        c.roundRect(x0 + 29 * MM, y0 + 96 * MM, 30 * MM, 28 * MM, 4 * MM, fill=1, stroke=0)
        c.setFillColor(white)
        c.setFont(FONT_BOLD, 10)
        c.drawCentredString(x0 + 44 * MM, y0 + 107 * MM, "DLL")
        c.setStrokeColor(LIME)
        c.setLineWidth(5)
        c.line(x0 + 23 * MM, y0 + 127 * MM + drift, x0 + 40 * MM, y0 + 122 * MM)
        c.line(x0 + 44 * MM, y0 + 96 * MM, x0 + 44 * MM, y0 + 63 * MM)
        c.setFillColor(LIME)
        c.circle(x0 + 44 * MM, y0 + 48 * MM, 10 * MM, fill=1, stroke=0)
    elif kind == "command-chain":
        labels = (">_", "CMD", "EXEC")
        for idx, label in enumerate(labels):
            xx = x0 + (5 + idx * 7) * MM
            yy = y0 + (157 - idx * 49) * MM + (drift if idx == 0 else 0)
            c.setStrokeColor((VIOLET, MAGENTA, LIME)[idx])
            c.setLineWidth(3)
            c.roundRect(xx, yy, 52 * MM, 27 * MM, 5 * MM, fill=0, stroke=1)
            c.setFillColor(white)
            c.setFont(FONT_BOLD, 12)
            c.drawString(xx + 7 * MM, yy + 9 * MM, label)
            if idx < 2:
                c.line(xx + 26 * MM, yy - 4 * MM, xx + 33 * MM, yy - 19 * MM)
    elif kind == "network-path":
        points = [(x0 + 8 * MM, y0 + 161 * MM + drift), (x0 + 48 * MM, y0 + 126 * MM), (x0 + 16 * MM, y0 + 87 * MM), (x0 + 53 * MM, y0 + 48 * MM)]
        c.setStrokeColor(VIOLET)
        c.setLineWidth(4)
        for a, b in zip(points, points[1:]):
            c.line(a[0], a[1], b[0], b[1])
        for idx, (xx, yy) in enumerate(points):
            c.setFillColor((LIME, MAGENTA, VIOLET, white)[idx])
            c.circle(xx, yy, (7 + (seed + idx) % 5) * MM, fill=1, stroke=0)
        c.setStrokeColor(MAGENTA)
        c.setLineWidth(1.5)
        c.arc(x0 + 3 * MM, y0 + 39 * MM, x0 + 62 * MM, y0 + 177 * MM, 250, 220)
    elif kind == "exploit-boundary":
        wall_x = x0 + 39 * MM
        c.setStrokeColor(VIOLET)
        c.setLineWidth(5)
        for idx in range(5):
            yy = y0 + (55 + idx * 26) * MM
            c.line(wall_x - (idx % 2) * 8 * MM, yy, wall_x + 20 * MM, yy)
        c.setStrokeColor(MAGENTA)
        c.setLineWidth(4)
        c.line(x0 + 4 * MM, y0 + 144 * MM + drift, wall_x - 5 * MM, y0 + 116 * MM)
        c.line(wall_x - 5 * MM, y0 + 116 * MM, x0 + 24 * MM, y0 + 111 * MM)
        c.line(wall_x - 5 * MM, y0 + 116 * MM, x0 + 28 * MM, y0 + 128 * MM)
        c.setFillColor(LIME)
        c.circle(x0 + 13 * MM, y0 + 151 * MM + drift, 9 * MM, fill=1, stroke=0)
        c.setFillColor(MAGENTA)
        c.circle(wall_x + 9 * MM, y0 + 42 * MM, 13 * MM, fill=1, stroke=0)
        c.setFillColor(white)
        c.setFont(FONT_BOLD, 9)
        c.drawCentredString(wall_x + 9 * MM, y0 + 39 * MM, "RCE")
    elif kind == "supply-chain":
        c.setStrokeColor(VIOLET)
        c.setLineWidth(3)
        c.roundRect(x0 + 8 * MM, y0 + 143 * MM + drift, 48 * MM, 34 * MM, 5 * MM, fill=0, stroke=1)
        c.setFillColor(white)
        c.setFont(FONT_BOLD, 9)
        c.drawCentredString(x0 + 32 * MM, y0 + 157 * MM + drift, "PACKAGE")
        c.setStrokeColor(MAGENTA)
        c.line(x0 + 32 * MM, y0 + 143 * MM + drift, x0 + 32 * MM, y0 + 102 * MM)
        c.setFillColor(MAGENTA)
        c.circle(x0 + 32 * MM, y0 + 91 * MM, 12 * MM, fill=1, stroke=0)
        c.setFillColor(white)
        c.setFont(FONT_BOLD, 12)
        c.drawCentredString(x0 + 32 * MM, y0 + 87 * MM, "+")
        c.setStrokeColor(LIME)
        c.line(x0 + 32 * MM, y0 + 78 * MM, x0 + 32 * MM, y0 + 48 * MM)
        c.setFillColor(LIME)
        c.roundRect(x0 + 15 * MM, y0 + 34 * MM, 34 * MM, 16 * MM, 4 * MM, fill=1, stroke=0)
    elif kind == "impact":
        c.setStrokeColor(VIOLET)
        c.setLineWidth(4)
        c.arc(x0 + 17 * MM, y0 + 126 * MM + drift, x0 + 49 * MM, y0 + 166 * MM + drift, 0, 180)
        c.setFillColor(MAGENTA)
        c.roundRect(x0 + 10 * MM, y0 + 88 * MM, 46 * MM, 46 * MM, 6 * MM, fill=1, stroke=0)
        c.setFillColor(INK)
        c.circle(x0 + 33 * MM, y0 + 111 * MM, 7 * MM, fill=1, stroke=0)
        c.rect(x0 + 31 * MM, y0 + 94 * MM, 4 * MM, 17 * MM, fill=1, stroke=0)
        for idx in range(5):
            c.setFillColor((LIME, VIOLET)[idx % 2])
            c.rect(x0 + (8 + idx * 12) * MM, y0 + 49 * MM, 8 * MM, (12 + ((seed + idx) % 4) * 5) * MM, fill=1, stroke=0)
    elif kind == "data-transfer":
        c.setStrokeColor(VIOLET)
        c.setLineWidth(3)
        c.ellipse(x0 + 6 * MM, y0 + 150 * MM + drift, x0 + 38 * MM, y0 + 166 * MM + drift, fill=0, stroke=1)
        c.rect(x0 + 6 * MM, y0 + 113 * MM + drift, 32 * MM, 45 * MM, fill=0, stroke=1)
        c.arc(x0 + 6 * MM, y0 + 105 * MM + drift, x0 + 38 * MM, y0 + 121 * MM + drift, 180, 180)
        c.setStrokeColor(MAGENTA)
        c.setLineWidth(5)
        c.line(x0 + 38 * MM, y0 + 136 * MM, x0 + 57 * MM, y0 + 94 * MM)
        c.line(x0 + 57 * MM, y0 + 94 * MM, x0 + 47 * MM, y0 + 100 * MM)
        c.line(x0 + 57 * MM, y0 + 94 * MM, x0 + 55 * MM, y0 + 106 * MM)
        c.setFillColor(LIME)
        c.circle(x0 + 50 * MM, y0 + 53 * MM, 15 * MM, fill=1, stroke=0)
    elif kind == "endpoint-process":
        nodes = [
            (x0 + 31 * MM, y0 + 166 * MM + drift, "PARENT", VIOLET),
            (x0 + 13 * MM, y0 + 112 * MM, "FILE", LIME),
            (x0 + 51 * MM, y0 + 112 * MM, "CHILD", MAGENTA),
            (x0 + 31 * MM, y0 + 58 * MM, "EVENT", VIOLET),
        ]
        c.setStrokeColor(Color(1, 1, 1, alpha=0.75))
        c.setLineWidth(3)
        c.line(nodes[0][0], nodes[0][1] - 10 * MM, nodes[1][0], nodes[1][1] + 10 * MM)
        c.line(nodes[0][0], nodes[0][1] - 10 * MM, nodes[2][0], nodes[2][1] + 10 * MM)
        c.line(nodes[1][0], nodes[1][1] - 10 * MM, nodes[3][0], nodes[3][1] + 10 * MM)
        c.line(nodes[2][0], nodes[2][1] - 10 * MM, nodes[3][0], nodes[3][1] + 10 * MM)
        for idx, (xx, yy, label, color) in enumerate(nodes):
            c.setFillColor(color)
            c.circle(xx, yy, (10 + (seed + idx) % 4) * MM, fill=1, stroke=0)
            c.setFillColor(INK if color == LIME else white)
            c.setFont(FONT_BOLD, 6.2)
            c.drawCentredString(xx, yy - 2 * MM, label)
    else:
        c.setStrokeColor(VIOLET)
        c.setLineWidth(2)
        points = []
        seed = sum(ord(ch) for ch in report["id"])
        for i in range(8):
            xx = x0 + (8 + ((seed * (i + 3)) % 52)) * MM
            yy = y0 + (30 + ((seed * (i + 7)) % 150)) * MM
            points.append((xx, yy))
        for a, b in zip(points, points[1:]):
            c.line(a[0], a[1], b[0], b[1])
        for i, (xx, yy) in enumerate(points):
            c.setFillColor((LIME, VIOLET, MAGENTA)[i % 3])
            c.circle(xx, yy, (3 + i % 4) * MM, fill=1, stroke=0)

    c.setFillAlpha(0.55)
    c.setFillColor(white)
    c.setFont(FONT_BOLD, 5.8)
    c.drawCentredString(x0 + width / 2, y0 + 8 * MM, report.get("artwork", {}).get("label", "OBSERVABILITY").upper())
    c.restoreState()


def page_cover(c: canvas.Canvas, report: dict) -> None:
    draw_cover_background(c)
    c.setStrokeColor(Color(1, 1, 1, alpha=0.15))
    c.line(123 * MM, 0, 123 * MM, PAGE_H)
    c.setFillColor(LIME)
    c.rect(16 * MM, PAGE_H - 29 * MM, 10 * MM, 1.1 * MM, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont(FONT_BOLD, 7.1)
    c.drawString(30 * MM, PAGE_H - 30 * MM, "DETECTION THREAT LANDSCAPE")
    c.setFillColor(Color(1, 1, 1, alpha=0.45))
    c.setFont(FONT_BOLD, 5.7)
    c.drawRightString(PAGE_W - 15 * MM, PAGE_H - 24 * MM, report.get("artwork", {}).get("label", "THREAT DOSSIER").upper())

    title_size = 28
    title_lines = split_words(report["title"].upper(), FONT_BOLD, title_size, 96 * MM)
    for candidate in (26, 24, 22, 20, 18, 16):
        if len(title_lines) <= 5:
            break
        title_size = candidate
        title_lines = split_words(report["title"].upper(), FONT_BOLD, title_size, 96 * MM)
    y = PAGE_H - 64 * MM
    c.setFillColor(white)
    c.setFont(FONT_BOLD, title_size)
    for line in title_lines:
        c.drawString(16 * MM, y, line)
        y -= title_size * 1.02
    y -= 5 * MM
    draw_wrapped(c, report["subtitle"], 16 * MM, y, 96 * MM, size=9.2, leading=13, color=Color(1, 1, 1, alpha=0.82), max_lines=4)

    badge_y = 74 * MM
    classification = report["classification"].upper()
    badge_w = pdfmetrics.stringWidth(classification, FONT_BOLD, 6.2) + 9 * MM
    c.setFillColor(LIME)
    c.roundRect(16 * MM, badge_y, badge_w, 8 * MM, 4 * MM, fill=1, stroke=0)
    c.setFillColor(INK)
    c.setFont(FONT_BOLD, 6.2)
    c.drawCentredString(16 * MM + badge_w / 2, badge_y + 2.7 * MM, classification)
    confidence = f"CONFIDENCE: {report['confidence'].upper()}"
    conf_w = pdfmetrics.stringWidth(confidence, FONT_BOLD, 6.2) + 9 * MM
    c.setFillColor(Color(VIOLET.red, VIOLET.green, VIOLET.blue, alpha=0.18))
    c.setStrokeColor(VIOLET)
    c.roundRect(19 * MM + badge_w, badge_y, conf_w, 8 * MM, 4 * MM, fill=1, stroke=1)
    c.setFillColor(white)
    c.drawCentredString(19 * MM + badge_w + conf_w / 2, badge_y + 2.7 * MM, confidence)

    c.setStrokeColor(Color(1, 1, 1, alpha=0.18))
    c.line(16 * MM, 57 * MM, 112 * MM, 57 * MM)
    meta = [
        ("REPORT TYPE", report["report_type"]),
        ("STATUS", report["query"]["status"]),
        ("PRIMARY PLATFORM", report["primary_platform"]),
        ("OPERATIONAL VALUE", f"{report['operational_value']} / 10"),
    ]
    for i, (label, value) in enumerate(meta):
        xx = 16 * MM + (i % 2) * 50 * MM
        yy = 48 * MM - (i // 2) * 17 * MM
        c.setFillColor(Color(1, 1, 1, alpha=0.45))
        c.setFont(FONT_BOLD, 5.5)
        c.drawString(xx, yy, label)
        c.setFillColor(white)
        c.setFont(FONT_BOLD, 6.8)
        draw_wrapped(c, value, xx, yy - 4.7 * MM, 45 * MM, font=FONT_BOLD, size=6.8, leading=8.4, color=white, max_lines=2)
    draw_artwork(c, report)
    c.setFillColor(Color(1, 1, 1, alpha=0.55))
    c.setFont(FONT_REGULAR, 5.6)
    c.drawString(16 * MM, 8 * MM, report["published"])
    c.drawRightString(PAGE_W - 15 * MM, 8 * MM, "01 / 08")
    c.showPage()


def page_executive(c: canvas.Canvas, report: dict) -> None:
    draw_internal_base(c, report, 2, "Executive assessment")
    y = draw_section_header(c, "01", "Executive Assessment", "Decision-grade summary with explicit evidence boundaries.", "Assessment")
    draw_card(c, 15 * MM, y, 180 * MM, 27 * MM, "Decision", report["decision"], accent=LIME, body_size=7.7, max_lines=5)
    y -= 32 * MM
    col_w = 56.5 * MM
    source_label = "Legacy evidence record" if report.get("migration", {}).get("provenance_status") == "legacy-review-required" else "Source-confirmed"
    groups = [
        (source_label, report["source_facts"], VIOLET),
        ("Analyst assessment", report["analyst_assessment"], MAGENTA),
        ("Detection assumptions", report["assumptions"], LIME),
    ]
    for idx, (label, items, accent) in enumerate(groups):
        x = 15 * MM + idx * 61.75 * MM
        c.setFillColor(PAPER_SOFT)
        c.setStrokeColor(LINE)
        c.roundRect(x, y - 63 * MM, col_w, 63 * MM, 3 * MM, fill=1, stroke=1)
        draw_label(c, label, x + 4 * MM, y - 7 * MM, accent)
        draw_bullet_list(c, items[:3], x + 4 * MM, y - 14 * MM, col_w - 8 * MM, size=6.9, accent=accent, max_lines_each=3, gap=1.2 * MM)
    y -= 69 * MM
    draw_label(c, "Key findings", 15 * MM, y, VIOLET_DEEP)
    y -= 5 * MM
    for idx, item in enumerate(report["key_findings"][:3]):
        x = 15 * MM + idx * 61.75 * MM
        draw_card(c, x, y, col_w, 35 * MM, f"Finding {idx + 1}", item, accent=(VIOLET, MAGENTA, LIME)[idx], body_size=6.9, max_lines=7)
    y -= 41 * MM
    draw_card(c, 15 * MM, y, 180 * MM, 28 * MM, "Evidence boundary", " ".join(report["unknowns"]), accent=DANGER, body_size=7.2, max_lines=5)
    c.showPage()


def page_mechanics(c: canvas.Canvas, report: dict) -> None:
    draw_internal_base(c, report, 3, "Threat mechanics")
    y = draw_section_header(c, "02", "Threat Mechanics", "Technical mechanism, observable transitions and supported scope.", "Attack flow")
    draw_card(c, 15 * MM, y, 180 * MM, 33 * MM, "Technical background", report["technical_background"], accent=VIOLET, body_size=7.2, max_lines=7)
    y -= 39 * MM
    stages = report["attack_chain"][:5]
    card_h = 29 * MM if len(stages) <= 4 else 24 * MM
    for idx, stage in enumerate(stages):
        c.setFillColor((INK, VIOLET_DEEP, VIOLET, MAGENTA, LIME)[idx])
        c.circle(21 * MM, y - 8 * MM, 5 * MM, fill=1, stroke=0)
        c.setFillColor(white if idx < 4 else INK)
        c.setFont(FONT_BOLD, 7)
        c.drawCentredString(21 * MM, y - 10 * MM, str(idx + 1))
        draw_card(
            c,
            30 * MM,
            y,
            165 * MM,
            card_h,
            stage["phase"],
            f"{stage['behavior']} Observable: {stage['observable']}",
            accent=(VIOLET, MAGENTA, LIME)[idx % 3],
            body_size=6.8,
            max_lines=5,
        )
        y -= card_h + 4 * MM
    c.showPage()


def page_telemetry(c: canvas.Canvas, report: dict) -> None:
    draw_internal_base(c, report, 4, "Telemetry and evidence")
    y = draw_section_header(c, "03", "Telemetry & Evidence Model", "Minimum data contract and known visibility gaps.", "Data contract")
    draw_card(c, 15 * MM, y, 180 * MM, 24 * MM, "Primary platform", f"{report['primary_platform']}. {report['query']['logic']}", accent=VIOLET, body_size=7.5, max_lines=4)
    y -= 31 * MM
    rows = report["telemetry"][:8]
    row_h = 18 * MM if len(rows) <= 6 else 15 * MM
    widths = [52 * MM, 30 * MM, 98 * MM]
    headers = ["FIELD / TABLE", "STATUS", "PURPOSE"]
    x = 15 * MM
    c.setFillColor(INK)
    c.rect(x, y - 10 * MM, sum(widths), 10 * MM, fill=1, stroke=0)
    cursor = x
    for header, width in zip(headers, widths):
        c.setFillColor(white)
        c.setFont(FONT_BOLD, 6.4)
        c.drawString(cursor + 3 * MM, y - 6.3 * MM, header)
        cursor += width
    y -= 10 * MM
    for idx, row in enumerate(rows):
        c.setFillColor(PAPER_SOFT if idx % 2 == 0 else white)
        c.setStrokeColor(LINE)
        c.rect(x, y - row_h, sum(widths), row_h, fill=1, stroke=1)
        values = [row["field"], row["status"], row["purpose"]]
        cursor = x
        for col, (value, width) in enumerate(zip(values, widths)):
            draw_wrapped(c, value, cursor + 3 * MM, y - 6 * MM, width - 6 * MM, font=FONT_BOLD if col < 2 else FONT_REGULAR, size=6.5, leading=8.5, color=VIOLET_DEEP if col == 1 else INK, max_lines=3)
            cursor += width
        y -= row_h
    y -= 5 * MM
    gaps = report["validation"].get("visibility_gaps", [])
    draw_card(c, 15 * MM, y, 180 * MM, 30 * MM, "Known visibility gaps", " ".join(gaps), accent=DANGER, body_size=7.2, max_lines=6)
    c.showPage()


def page_query(c: canvas.Canvas, report: dict, package: Path) -> None:
    draw_internal_base(c, report, 5, "Detection logic")
    y = draw_section_header(c, "04", "Primary Detection Logic", "Native query, explicit condition evidence and match meaning.", report["query"]["language"])
    query_path = package / report["query"]["file"]
    query_text = query_path.read_text(encoding="utf-8") if query_path.exists() else "Query file missing"
    lines = query_text.rstrip().splitlines()
    max_lines = 52
    clipped = len(lines) > max_lines
    visible = lines[:max_lines]
    if clipped:
        visible[-1] = f"// ... complete {len(lines)}-line query in {query_path.name}"
    panel_h = 128 * MM
    c.setFillColor(INK_SOFT)
    c.roundRect(15 * MM, y - panel_h, 180 * MM, panel_h, 4 * MM, fill=1, stroke=0)
    code_size = 4.8 if len(visible) > 42 else 5.4
    leading = 5.75 if len(visible) > 42 else 6.45
    c.setFont(FONT_MONO, code_size)
    c.setFillColor(Color(0.89, 0.88, 0.94))
    yy = y - 7 * MM
    for line in visible:
        safe = line.replace("\t", "    ")
        while pdfmetrics.stringWidth(safe, FONT_MONO, code_size) > 169 * MM and len(safe) > 8:
            safe = safe[:-1]
        c.drawString(20 * MM, yy, safe)
        yy -= leading
    y -= panel_h + 5 * MM
    draw_card(c, 15 * MM, y, 87 * MM, 34 * MM, "What a match proves", report["query"]["match_proves"], accent=LIME, body_size=6.8, max_lines=7)
    draw_card(c, 108 * MM, y, 87 * MM, 34 * MM, "What it does not prove", report["query"]["match_does_not_prove"], accent=MAGENTA, body_size=6.8, max_lines=7)
    y -= 40 * MM
    draw_card(c, 15 * MM, y, 180 * MM, 24 * MM, "Maturity", f"{report['classification']} - {report['query']['status']}. {report['query']['logic']}", accent=VIOLET, body_size=7.0, max_lines=4)
    c.showPage()


def page_triage(c: canvas.Canvas, report: dict) -> None:
    draw_internal_base(c, report, 6, "Triage and hunting")
    y = draw_section_header(c, "05", "Triage & Hunting Playbook", "Evidence-preserving workflow from match to disposition.", "Workflow")
    steps = report["triage"][:6]
    card_h = 27 * MM if len(steps) <= 5 else 22 * MM
    for idx, step in enumerate(steps):
        draw_card(c, 15 * MM, y, 180 * MM, card_h, f"{idx + 1:02d}", step, accent=(VIOLET, MAGENTA, LIME)[idx % 3], body_size=7.2, max_lines=5)
        y -= card_h + 4 * MM
    draw_card(c, 15 * MM, y, 180 * MM, 27 * MM, "Disposition rule", f"Escalate only when the evidence establishes the behavior described by the query. {report['query']['match_does_not_prove']}", accent=DANGER, body_size=7.0, max_lines=5)
    c.showPage()


def page_validation(c: canvas.Canvas, report: dict) -> None:
    draw_internal_base(c, report, 7, "False positives and validation")
    y = draw_section_header(c, "06", "False Positives & Validation", "Overlap model, controlled checks and promotion gate.", "Quality gate")
    fps = report["false_positives"][:4]
    if fps:
        row_h = 20 * MM
        for idx, fp in enumerate(fps):
            draw_card(c, 15 * MM, y, 180 * MM, row_h, fp["source"], fp["control"], accent=(MAGENTA, VIOLET, LIME)[idx % 3], body_size=6.8, max_lines=4)
            y -= row_h + 3 * MM
    draw_label(c, "Validation sequence", 15 * MM, y - 1 * MM, VIOLET_DEEP)
    y -= 8 * MM
    y = draw_bullet_list(c, report["validation"]["steps"][:5], 15 * MM, y, 180 * MM, size=7.1, accent=VIOLET, max_lines_each=2, gap=1 * MM)
    y -= 2 * MM
    draw_card(c, 15 * MM, y, 87 * MM, 28 * MM, "Success", report["validation"]["success"], accent=SUCCESS, body_size=6.7, max_lines=6)
    draw_card(c, 108 * MM, y, 87 * MM, 28 * MM, "Rejection", report["validation"]["rejection"], accent=DANGER, body_size=6.7, max_lines=6)
    y -= 34 * MM
    draw_card(c, 15 * MM, y, 180 * MM, 25 * MM, "Promotion gate", report["validation"]["promotion_gate"], accent=LIME, body_size=7.0, max_lines=5)
    c.showPage()


def page_conclusion(c: canvas.Canvas, report: dict, references: dict) -> None:
    draw_internal_base(c, report, 8, "Assessment and references")
    y = draw_section_header(c, "07", "Analyst Assessment & References", "Coverage statement, open questions and source record.", "Final")
    draw_card(c, 15 * MM, y, 180 * MM, 31 * MM, "Conclusion", report["conclusion"], accent=LIME, body_size=7.4, max_lines=6)
    y -= 37 * MM
    draw_card(c, 15 * MM, y, 180 * MM, 24 * MM, "MITRE ATT&CK", " / ".join(report["mitre"]), accent=VIOLET, body_size=8.0, max_lines=3)
    y -= 30 * MM
    draw_label(c, "Primary and authoritative references", 15 * MM, y, VIOLET_DEEP)
    y -= 6 * MM
    for source in references.get("sources", [])[:6]:
        label = f"{source['id']}  {source['organization']} - {source['title']} ({source['published']})"
        c.setFillColor(PAPER_SOFT)
        c.setStrokeColor(LINE)
        c.roundRect(15 * MM, y - 20 * MM, 180 * MM, 18 * MM, 2 * MM, fill=1, stroke=1)
        draw_wrapped(c, label, 19 * MM, y - 7 * MM, 172 * MM, font=FONT_BOLD, size=6.6, leading=8.3, max_lines=2)
        url = source["url"].replace("https://", "hxxps://").replace(".", "[.]")
        draw_wrapped(c, url, 19 * MM, y - 14 * MM, 172 * MM, size=5.4, leading=6.6, color=MUTED, max_lines=2)
        y -= 21 * MM
    y -= 2 * MM
    open_questions = " ".join(report["unknowns"])
    draw_card(c, 15 * MM, y, 180 * MM, 25 * MM, "Open questions", open_questions, accent=MAGENTA, body_size=6.9, max_lines=5)
    y -= 30 * MM
    control = (
        f"Schema {report['schema_version']} | Layout {LAYOUT_VERSION} | "
        f"Maturity {report['maturity']} | Confidence {report['confidence']} | "
        "No customer data | Evidence ledger required"
    )
    draw_card(c, 15 * MM, y, 180 * MM, 20 * MM, "Document control", control, accent=INK, body_size=6.5, max_lines=3)
    c.showPage()


def build(package: Path, output: Path | None = None) -> Path:
    report = load_json(package / "report.json")
    references = load_json(package / "references.json")
    output = output or package / "threat-analysis.pdf"
    output.parent.mkdir(parents=True, exist_ok=True)
    register_fonts()
    c = canvas.Canvas(
        str(output),
        pagesize=A4,
        pageCompression=1,
        initialFontName=FONT_REGULAR,
        initialFontSize=10,
    )
    c.setTitle(report["title"])
    c.setAuthor("Detection Threat Landscape")
    c.setSubject(f"{report['classification']} | {report['primary_platform']}")
    c.setKeywords(f"canonical-layout-v{LAYOUT_VERSION}, {', '.join(report['mitre'])}")
    page_cover(c, report)
    page_executive(c, report)
    page_mechanics(c, report)
    page_telemetry(c, report)
    page_query(c, report, package)
    page_triage(c, report)
    page_validation(c, report)
    page_conclusion(c, report, references)
    c.save()
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path, help="Detection package directory containing report.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = build(args.package.resolve(), args.output.resolve() if args.output else None)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
