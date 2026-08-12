#!/usr/bin/env python3
"""Ferryman mark: hand-authored geometry, drawn per tier on its own pixel grid.

Nothing here is traced from a raster. Every tier is a function of a handful of
numbers so a size that fails can be fixed by changing the number that caused it.
"""
import math
from pathlib import Path

NAVY = "#0D132B"
WHITE = "#FFFFFF"

HERE = Path(__file__).parent


def polar(cx, cy, r, deg):
    a = math.radians(deg)
    return cx + r * math.cos(a), cy + r * math.sin(a)


def f_path(x0, y0, h, stem, w_top, w_mid, mid_at):
    """A geometric F as a filled path. No font, so no font to ship."""
    my = y0 + h * mid_at
    return (
        f"M{x0:.3f},{y0:.3f} H{x0+w_top:.3f} V{y0+stem:.3f} H{x0+stem:.3f} "
        f"V{my:.3f} H{x0+w_mid:.3f} V{my+stem:.3f} H{x0+stem:.3f} "
        f"V{y0+h:.3f} H{x0:.3f} Z"
    )


def wheel(size, r_ring, w_ring, n_nodes, r_node, d_node, w_spoke,
          rot=-90, chords=None, fill=NAVY, f=None):
    """One mark. `chords` is a list of (i, j) node-index pairs."""
    c = size / 2
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
        f'width="{size}" height="{size}" fill="none">'
    ]
    g = [f'<g stroke="{fill}" fill="none" stroke-linecap="round">']

    pts = [polar(c, c, d_node, rot + i * (360 / n_nodes)) for i in range(n_nodes)]

    # Chords first, so everything else sits on top of them.
    for (i, j) in (chords or []):
        x1, y1 = pts[i]
        x2, y2 = pts[j]
        g.append(
            f'<line x1="{x1:.3f}" y1="{y1:.3f}" x2="{x2:.3f}" y2="{y2:.3f}" '
            f'stroke-width="{w_ring*0.24:.3f}" opacity="0.55"/>'
        )

    # Spokes: stubs from the ring out to each node, never crossing the centre.
    for i in range(n_nodes):
        x1, y1 = polar(c, c, r_ring, rot + i * (360 / n_nodes))
        x2, y2 = pts[i]
        g.append(
            f'<line x1="{x1:.3f}" y1="{y1:.3f}" x2="{x2:.3f}" y2="{y2:.3f}" '
            f'stroke-width="{w_spoke:.3f}"/>'
        )

    g.append(
        f'<circle cx="{c}" cy="{c}" r="{r_ring:.3f}" stroke-width="{w_ring:.3f}"/>'
    )
    for (x, y) in pts:
        g.append(f'<circle cx="{x:.3f}" cy="{y:.3f}" r="{r_node:.3f}" stroke="none" fill="{fill}"/>')

    if f:
        g.append(f'<path d="{f}" stroke="none" fill="{fill}"/>')

    g.append("</g>")
    parts += g + ["</svg>"]
    return "\n".join(parts)


def ring_only(size, r, w, fill=NAVY, f=None):
    c = size / 2
    body = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
        f'width="{size}" height="{size}" fill="none">',
        f'<g stroke="{fill}" fill="none">',
        f'<circle cx="{c}" cy="{c}" r="{r:.3f}" stroke-width="{w:.3f}"/>',
    ]
    if f:
        body.append(f'<path d="{f}" stroke="none" fill="{fill}"/>')
    body += ["</g>", "</svg>"]
    return "\n".join(body)


# ---------------------------------------------------------------- tiers

def tier_c(fill=NAVY):
    """128px+. Full mark: one deliberate triangle of chords, not a web."""
    S = 64
    return wheel(
        S, r_ring=19, w_ring=5.0, n_nodes=6, r_node=4.0, d_node=25.4,
        w_spoke=3.0, chords=[(0, 2), (2, 4), (4, 0)], fill=fill,
        f=f_path(x0=26.6, y0=23.2, h=17.6, stem=4.1, w_top=11.0,
                 w_mid=8.4, mid_at=0.40),
    )


def tier_b(fill=NAVY):
    """32-64px. Same mark, chords dropped."""
    S = 64
    return wheel(
        S, r_ring=18.5, w_ring=5.6, n_nodes=6, r_node=4.3, d_node=25.2,
        w_spoke=3.2, chords=None, fill=fill,
        f=f_path(x0=26.4, y0=23.4, h=17.2, stem=4.4, w_top=11.2,
                 w_mid=8.6, mid_at=0.40),
    )


def tier_a_wheel(fill=NAVY):
    """16px, option 1: wheel silhouette, F dropped. 4 nodes, on-grid."""
    S = 16
    return wheel(
        S, r_ring=4.3, w_ring=1.9, n_nodes=4, r_node=1.5, d_node=6.2,
        w_spoke=1.4, rot=-90, chords=None, fill=fill,
    )


def tier_a_wheel6(fill=NAVY):
    """16px, option 1b: the same, keeping all six nodes."""
    S = 16
    return wheel(
        S, r_ring=4.3, w_ring=1.9, n_nodes=6, r_node=1.35, d_node=6.2,
        w_spoke=1.3, rot=-90, chords=None, fill=fill,
    )


def tier_a_f(fill=NAVY):
    """16px, option 2: F in a plain circle, handles dropped."""
    S = 16
    return ring_only(
        S, r=6.4, w=1.7, fill=fill,
        f=f_path(x0=5.6, y0=4.3, h=7.4, stem=1.7, w_top=4.8,
                 w_mid=3.7, mid_at=0.40),
    )


def tier_a_both(fill=NAVY):
    """16px, option 3: what round 3 attempted - both, shrunk. The control."""
    S = 16
    return wheel(
        S, r_ring=4.6, w_ring=1.4, n_nodes=6, r_node=1.1, d_node=6.3,
        w_spoke=1.0, fill=fill,
        f=f_path(x0=6.4, y0=5.6, h=4.6, stem=1.05, w_top=2.9,
                 w_mid=2.2, mid_at=0.40),
    )


VARIANTS = {
    "tier-c": tier_c,
    "tier-b": tier_b,
    "tier-a-wheel4": tier_a_wheel,
    "tier-a-wheel6": tier_a_wheel6,
    "tier-a-f": tier_a_f,
    "tier-a-both": tier_a_both,
}

if __name__ == "__main__":
    out = HERE / "svg"
    out.mkdir(exist_ok=True)
    for name, fn in VARIANTS.items():
        (out / f"{name}.svg").write_text(fn(NAVY))
        (out / f"{name}-dark.svg").write_text(fn(WHITE))
    print(f"wrote {2*len(VARIANTS)} svgs")


def wheel_masked(size, r_ring, w_ring, n_nodes, r_node, d_node, w_spoke,
                 rot=-90, chords=None, chord_w=1.2, knockout=0.0,
                 fill=NAVY, f=None, uid="m"):
    """As `wheel`, but chords are cut by a mask around the centre rather than
    covered by a background-coloured disc. A knockout that assumes the backdrop
    colour is a knockout that breaks the moment someone drops the mark on a
    photo or a coloured header."""
    c = size / 2
    pts = [polar(c, c, d_node, rot + i * (360 / n_nodes)) for i in range(n_nodes)]
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
        f'width="{size}" height="{size}" fill="none">'
    ]
    if knockout > 0:
        out += [
            "<defs>",
            f'<mask id="{uid}" maskUnits="userSpaceOnUse" x="0" y="0" '
            f'width="{size}" height="{size}">',
            f'<rect x="0" y="0" width="{size}" height="{size}" fill="white"/>',
            f'<circle cx="{c}" cy="{c}" r="{knockout:.3f}" fill="black"/>',
            "</mask></defs>",
        ]
    if chords:
        m = f' mask="url(#{uid})"' if knockout > 0 else ""
        out.append(f'<g stroke="{fill}" fill="none" stroke-linecap="round"{m}>')
        for (i, j) in chords:
            x1, y1 = pts[i]
            x2, y2 = pts[j]
            out.append(
                f'<line x1="{x1:.3f}" y1="{y1:.3f}" x2="{x2:.3f}" y2="{y2:.3f}" '
                f'stroke-width="{chord_w:.3f}"/>'
            )
        out.append("</g>")
    out.append(f'<g stroke="{fill}" fill="none" stroke-linecap="round">')
    for i in range(n_nodes):
        x1, y1 = polar(c, c, r_ring, rot + i * (360 / n_nodes))
        x2, y2 = pts[i]
        out.append(
            f'<line x1="{x1:.3f}" y1="{y1:.3f}" x2="{x2:.3f}" y2="{y2:.3f}" '
            f'stroke-width="{w_spoke:.3f}"/>'
        )
    out.append(f'<circle cx="{c}" cy="{c}" r="{r_ring:.3f}" stroke-width="{w_ring:.3f}"/>')
    for (x, y) in pts:
        out.append(f'<circle cx="{x:.3f}" cy="{y:.3f}" r="{r_node:.3f}" stroke="none" fill="{fill}"/>')
    if f:
        out.append(f'<path d="{f}" stroke="none" fill="{fill}"/>')
    out += ["</g>", "</svg>"]
    return "\n".join(out)


FF = dict(x0=26.6, y0=23.2, h=17.6, stem=4.1, w_top=11.0, w_mid=8.4, mid_at=0.40)
BASE = dict(size=64, r_ring=19, w_ring=5.0, n_nodes=6, r_node=4.0,
            d_node=25.4, w_spoke=3.0)

def c_none(fill=NAVY):
    return wheel_masked(**BASE, chords=None, fill=fill, f=f_path(**FF), uid="k0")

def c_tri(fill=NAVY):
    return wheel_masked(**BASE, chords=[(0,2),(2,4),(4,0)], chord_w=1.35,
                        knockout=13.2, fill=fill, f=f_path(**FF), uid="k1")

def c_hex(fill=NAVY):
    return wheel_masked(**BASE, chords=[(0,2),(2,4),(4,0),(1,3),(3,5),(5,1)],
                        chord_w=1.1, knockout=13.2, fill=fill, f=f_path(**FF), uid="k2")

for nm, fn in {"cand-none": c_none, "cand-tri": c_tri, "cand-hex": c_hex}.items():
    (HERE / "svg" / f"{nm}.svg").write_text(fn(NAVY))
    (HERE / "svg" / f"{nm}-dark.svg").write_text(fn(WHITE))
print("candidates written")
