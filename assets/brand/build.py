#!/usr/bin/env python3
"""Build the shipping asset set from the geometry in gen.py.

Two drawings, not three. The full wheel below 32px produced an unreadable F no
matter how the numbers were tuned - 16x16 is 256 pixels and a ring, six handles
and a letterform cannot all have some. So the small mark drops the handles,
which is *less detail of the same shape* rather than a different shape, and the
crossover is measured rather than guessed: see preview/crossover.png.
"""
import io
import math
import struct
from pathlib import Path

import cairosvg
from PIL import Image
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont

from gen import NAVY, WHITE, f_path, wheel_masked, FF, BASE, ring_only

HERE = Path(__file__).parent
SVG, PNG, ICO = HERE / "svg", HERE / "png", HERE / "icons"
for d in (SVG, PNG, ICO):
    d.mkdir(exist_ok=True)

CROSSOVER = 32  # below this, the small mark. Measured, not chosen.

INTER_BOLD = "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf"
INTER_REG = "/usr/share/fonts/opentype/inter/Inter-Regular.otf"


# ------------------------------------------------------------------ the marks

def mark_full(fill=NAVY):
    """32px and up. Wheel, six node-handles, F. No interior chords: the handles
    already are the endpoints and the ring already is what joins them."""
    return wheel_masked(**BASE, chords=None, fill=fill, f=f_path(**FF), uid="f")


def mark_small(fill=NAVY):
    """16-24px. The same object with the handles removed."""
    return ring_only(
        16, r=6.4, w=1.7, fill=fill,
        f=f_path(x0=5.6, y0=4.3, h=7.4, stem=1.7, w_top=4.8, w_mid=3.7, mid_at=0.40),
    )


def mark_logo(fill=NAVY):
    """The logo mark: the wheel with its interior connections drawn.

    Chords are deliberately absent from every icon size - they turn to mush below
    128px and crowd the F. The logo is the one place with room for them, and it is
    where the mark has to say *network* rather than just *wheel*, because it is
    seen once at the top of a page instead of a hundred times in a tray.

    Every pair of nodes is joined except the adjacent ones, whose chords would
    only trace the ring they already sit on. The F is drawn last and solid, so it
    reads over the web rather than through it."""
    n = BASE["n_nodes"]
    chords = [(i, j) for i in range(n) for j in range(i + 1, n)
              if min(j - i, n - (j - i)) > 1]
    return wheel_masked(**BASE, chords=chords, chord_w=0.95, knockout=0.0,
                        fill=fill, f=f_path(**FF), uid="lg")


def for_size(px, fill=NAVY):
    return mark_small(fill) if px < CROSSOVER else mark_full(fill)


# ------------------------------------------------------------------ wordmark

def text_path(text, font_path, size, x, y, tracking=0.0):
    """Glyph outlines, not a <text> element. A logo that needs a font installed
    is a logo that renders as Times New Roman on someone else's machine."""
    font = TTFont(font_path)
    upem = font["head"].unitsPerEm
    glyphs = font.getGlyphSet()
    cmap = font.getBestCmap()
    scale = size / upem
    out, pen_x = [], 0.0
    for ch in text:
        name = cmap.get(ord(ch))
        if name is None:
            continue
        pen = SVGPathPen(glyphs)
        glyphs[name].draw(pen)
        d = pen.getCommands()
        if d:
            out.append(
                f'<g transform="translate({x + pen_x * scale:.3f},{y:.3f}) '
                f'scale({scale:.6f},{-scale:.6f})"><path d="{d}"/></g>'
            )
        pen_x += glyphs[name].width + tracking * upem
    width = pen_x * scale
    return "\n".join(out), width


def lockup(fill=NAVY):
    """Horizontal logo. The mark spans the full text block rather than sitting at
    cap height - undersizing it was one of the things wrong with round 3."""
    mh, gap = 72, 22
    word_size, tag_size = 46, 15.5
    tx, H = mh + gap, 80
    word_base, tag_base = 46.0, 70.0

    # Measured once to size the viewBox, then emitted at the real coordinates.
    # Positioning glyphs by string-substitution after the fact only ever moves
    # the one that happened to land on the origin.
    _, ww = text_path("Ferryman", INTER_BOLD, word_size, 0, 0)
    _, tw = text_path("private coordination for AI agents", INTER_REG, tag_size, 0, 0)
    word, _ = text_path("Ferryman", INTER_BOLD, word_size, tx, word_base)
    tag, _ = text_path("private coordination for AI agents", INTER_REG,
                       tag_size, tx + 1.5, tag_base)

    inner = mark_logo(fill).split("\n", 1)[1].rsplit("</svg>", 1)[0]
    W = tx + max(ww, tw) + 6

    return "\n".join([
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W:.1f} {H:.1f}" '
        f'width="{W:.1f}" height="{H:.1f}" fill="none">',
        f'<g transform="translate(0,{(H-mh)/2:.2f}) scale({mh/64:.5f})">{inner}</g>',
        f'<g fill="{fill}">', word, "</g>",
        f'<g fill="{fill}" opacity="0.85">', tag, "</g>",
        "</svg>",
    ])


# ------------------------------------------------------------------ raster

def png_bytes(svg_text, px):
    return cairosvg.svg2png(bytestring=svg_text.encode(), output_width=px, output_height=px)


def write_ico(path, sizes, fill=NAVY):
    """Hand-rolled so each size embeds the art drawn FOR that size. Pillow's ICO
    writer resamples one image to every size, which is exactly the mistake this
    whole exercise exists to avoid."""
    blobs = [png_bytes(for_size(s, fill), s) for s in sizes]
    n = len(sizes)
    header = struct.pack("<HHH", 0, 1, n)
    offset = 6 + 16 * n
    entries, body = b"", b""
    for s, b in zip(sizes, blobs):
        entries += struct.pack(
            "<BBBBHHII", s if s < 256 else 0, s if s < 256 else 0, 0, 0, 1, 32,
            len(b), offset)
        offset += len(b)
        body += b
    path.write_bytes(header + entries + body)
    return path


ICNS_TYPES = [(b"ic11", 32), (b"ic12", 64), (b"ic07", 128), (b"ic08", 256), (b"ic09", 512)]


def write_icns(path, fill=NAVY):
    chunks = b""
    for tag, s in ICNS_TYPES:
        data = png_bytes(for_size(s, fill), s)
        chunks += tag + struct.pack(">I", len(data) + 8) + data
    path.write_bytes(b"icns" + struct.pack(">I", len(chunks) + 8) + chunks)
    return path


if __name__ == "__main__":
    for name, fn in (("ferryman-mark", mark_full), ("ferryman-mark-small", mark_small),
                     ("ferryman-mark-logo", mark_logo), ("ferryman-logo", lockup)):
        (SVG / f"{name}.svg").write_text(fn(NAVY))
        (SVG / f"{name}-dark.svg").write_text(fn(WHITE))

    sizes = [16, 20, 24, 32, 48, 64, 128, 256, 512, 1024]
    for s in sizes:
        for suffix, fill in (("", NAVY), ("-dark", WHITE)):
            (PNG / f"ferryman-{s}{suffix}.png").write_bytes(png_bytes(for_size(s, fill), s))

    write_ico(ICO / "ferryman.ico", [16, 20, 24, 32, 48, 64, 128, 256], NAVY)
    write_ico(ICO / "ferryman-dark.ico", [16, 20, 24, 32, 48, 64, 128, 256], WHITE)
    write_icns(ICO / "ferryman.icns", NAVY)

    print(f"svg: {len(list(SVG.glob('ferryman*')))}  png: {len(list(PNG.glob('*.png')))}  "
          f"icons: {[p.name for p in sorted(ICO.iterdir())]}")
