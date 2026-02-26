"""
Inline SVG renderer for the traffic flow diagram.

Produces a self-contained SVG string that can be embedded directly in the
HTML report.  No external assets or JavaScript required.

When multiple requests are aggregated, latency values show averages and
each node/segment has an SVG ``<title>`` tooltip with full detail
(unique IPs, FQDNs, min/max latency, sample count).
"""

from __future__ import annotations

from html import escape

from ..traffic_flow import FlowPath, FlowNode, FlowSegment

__all__ = ["render_traffic_flow_svg"]


# ---------------------------------------------------------------------------
# Icon SVG fragments (16x16 viewBox, rendered at the node center)
# ---------------------------------------------------------------------------

_ICONS: dict[str, str] = {
    # Globe — internet user
    "internet": (
        '<circle cx="8" cy="8" r="7" fill="none" stroke="{color}" stroke-width="1.2"/>'
        '<ellipse cx="8" cy="8" rx="3.5" ry="7" fill="none" stroke="{color}" stroke-width="1"/>'
        '<line x1="1" y1="8" x2="15" y2="8" stroke="{color}" stroke-width="0.8"/>'
        '<path d="M2.5 4.5 Q8 3.5 13.5 4.5" fill="none" stroke="{color}" stroke-width="0.7"/>'
        '<path d="M2.5 11.5 Q8 12.5 13.5 11.5" fill="none" stroke="{color}" stroke-width="0.7"/>'
    ),
    # Building — internal user / app
    "internal": (
        '<rect x="3" y="3" width="10" height="11" rx="1" fill="none" stroke="{color}" stroke-width="1.2"/>'
        '<line x1="5.5" y1="5.5" x2="5.5" y2="5.5" stroke="{color}" stroke-width="1.5" stroke-linecap="round"/>'
        '<line x1="8" y1="5.5" x2="8" y2="5.5" stroke="{color}" stroke-width="1.5" stroke-linecap="round"/>'
        '<line x1="10.5" y1="5.5" x2="10.5" y2="5.5" stroke="{color}" stroke-width="1.5" stroke-linecap="round"/>'
        '<line x1="5.5" y1="8" x2="5.5" y2="8" stroke="{color}" stroke-width="1.5" stroke-linecap="round"/>'
        '<line x1="8" y1="8" x2="8" y2="8" stroke="{color}" stroke-width="1.5" stroke-linecap="round"/>'
        '<line x1="10.5" y1="8" x2="10.5" y2="8" stroke="{color}" stroke-width="1.5" stroke-linecap="round"/>'
        '<rect x="6.5" y="10.5" width="3" height="3.5" fill="none" stroke="{color}" stroke-width="1"/>'
    ),
    # Cloud — Regional Edge
    "re": (
        '<path d="M4.5 12 C1 12 1 8 4 7.5 C3.5 4 7 2.5 9 4.5 C10 3 13 3 13.5 5.5 '
        'C15.5 5.5 16 8 14 9.5 C15 11.5 13 12.5 11.5 12 Z" '
        'fill="none" stroke="{color}" stroke-width="1.2" stroke-linejoin="round"/>'
    ),
    # Box — Customer Edge
    "ce": (
        '<rect x="2" y="4" width="12" height="9" rx="1.5" fill="none" stroke="{color}" stroke-width="1.2"/>'
        '<line x1="2" y1="7" x2="14" y2="7" stroke="{color}" stroke-width="0.8"/>'
        '<circle cx="4.5" cy="5.5" r="0.6" fill="{color}"/>'
        '<circle cx="6.5" cy="5.5" r="0.6" fill="{color}"/>'
        '<line x1="5" y1="10" x2="11" y2="10" stroke="{color}" stroke-width="1" stroke-linecap="round"/>'
    ),
    # Server — application
    "app": (
        '<rect x="3" y="2" width="10" height="12" rx="1.5" fill="none" stroke="{color}" stroke-width="1.2"/>'
        '<line x1="3" y1="6" x2="13" y2="6" stroke="{color}" stroke-width="0.8"/>'
        '<line x1="3" y1="10" x2="13" y2="10" stroke="{color}" stroke-width="0.8"/>'
        '<circle cx="10.5" cy="4" r="0.7" fill="{color}"/>'
        '<circle cx="10.5" cy="8" r="0.7" fill="{color}"/>'
        '<circle cx="10.5" cy="12" r="0.7" fill="{color}"/>'
    ),
    # Server blocked (X overlay)
    "app_blocked": (
        '<rect x="3" y="2" width="10" height="12" rx="1.5" fill="none" stroke="{color}" stroke-width="1.2"/>'
        '<line x1="3" y1="6" x2="13" y2="6" stroke="{color}" stroke-width="0.8"/>'
        '<line x1="3" y1="10" x2="13" y2="10" stroke="{color}" stroke-width="0.8"/>'
        '<line x1="5" y1="3" x2="11" y2="13" stroke="#dc3545" stroke-width="1.8" stroke-linecap="round"/>'
        '<line x1="11" y1="3" x2="5" y2="13" stroke="#dc3545" stroke-width="1.8" stroke-linecap="round"/>'
    ),
}


# ---------------------------------------------------------------------------
# Node colors
# ---------------------------------------------------------------------------

_NODE_COLORS: dict[str, tuple[str, str, str]] = {
    # icon:         (fill,      stroke,    text_color)
    "internet":     ("#e8f4fd", "#3498db", "#2471a3"),
    "internal":     ("#fef9e7", "#f39c12", "#b7950b"),
    "re":           ("#eafaf1", "#27ae60", "#1e8449"),
    "ce":           ("#f4ecf7", "#8e44ad", "#6c3483"),
    "app":          ("#fdebd0", "#e67e22", "#ca6f1e"),
    "app_blocked":  ("#fdedec", "#e74c3c", "#c0392b"),
}


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

_NODE_W = 200
_NODE_H = 120
_ICON_SIZE = 40
_GAP = 120          # horizontal gap between node boxes
_PAD_X = 40         # left/right padding
_PAD_Y = 28         # top padding


def _fmt_latency(ms: float | None) -> str:
    if ms is None:
        return ""
    if ms < 1:
        return f"{ms * 1000:.0f} \u00b5s"
    if ms < 1000:
        return f"{ms:.1f} ms"
    return f"{ms / 1000:.2f} s"


def _tooltip(text: str) -> str:
    """Wrap text in an SVG <title> element (native browser tooltip)."""
    if not text:
        return ""
    return f"<title>{escape(text)}</title>"


def render_traffic_flow_svg(flow: FlowPath) -> str:
    """Return an inline SVG string for the given FlowPath."""
    n = len(flow.nodes)
    if n < 2:
        return ""

    total_w = _PAD_X * 2 + n * _NODE_W + (n - 1) * _GAP
    # Extra vertical space: remark banner (if aggregated) + nodes + detail below
    is_aggregated = flow.request_count > 1
    remark_h = 28 if is_aggregated else 0
    total_h = _PAD_Y + remark_h + _NODE_H + 100

    parts: list[str] = []
    # Use a generous min-width so the diagram doesn't shrink too small
    display_w = max(total_w, 800)
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_w} {total_h}" '
        f'width="100%" style="min-width:{display_w}px;max-width:{total_w}px;'
        f'font-family:-apple-system,BlinkMacSystemFont,'
        f'\'Segoe UI\',Roboto,sans-serif;margin:0 auto;display:block">'
    )

    y_cursor = _PAD_Y

    # Title
    parts.append(
        f'<text x="{total_w / 2}" y="{y_cursor + 14}" text-anchor="middle" '
        f'font-size="14" fill="#666" font-weight="600">{escape(flow.path_label)}</text>'
    )
    y_cursor += 24

    # Aggregation remark
    if is_aggregated:
        remark = f"Aggregated from {flow.request_count} requests \u2014 hover for details"
        # Background pill
        pill_w = min(total_w - 40, 420)
        pill_x = (total_w - pill_w) / 2
        parts.append(
            f'<rect x="{pill_x}" y="{y_cursor}" width="{pill_w}" height="22" rx="11" '
            f'fill="#fff3cd" stroke="#ffc107" stroke-width="0.8"/>'
            f'<text x="{total_w / 2}" y="{y_cursor + 15}" text-anchor="middle" '
            f'font-size="11" fill="#856404">{escape(remark)}</text>'
        )
        y_cursor += remark_h

    y_cursor += 10   # small gap before nodes
    y_center = y_cursor + _NODE_H // 2

    # --- Draw segments (arrows) first so they sit behind nodes ---
    for i, seg in enumerate(flow.segments):
        x1 = _PAD_X + i * (_NODE_W + _GAP) + _NODE_W
        x2 = _PAD_X + (i + 1) * (_NODE_W + _GAP)
        mid_x = (x1 + x2) / 2
        arrow_y = y_center

        # Determine color
        is_blocked_seg = seg.label and "block" in seg.label.lower()
        if is_blocked_seg:
            line_color = "#dc3545"
            dash = 'stroke-dasharray="6 3"'
        else:
            line_color = "#adb5bd"
            dash = ""

        # Clickable/hoverable group for the segment
        parts.append("<g>")
        if seg.tooltip:
            parts.append(_tooltip(seg.tooltip))

        # Arrow line
        parts.append(
            f'<line x1="{x1}" y1="{arrow_y}" x2="{x2 - 6}" y2="{arrow_y}" '
            f'stroke="{line_color}" stroke-width="2" {dash}/>'
        )
        # Arrowhead
        parts.append(
            f'<polygon points="{x2 - 6},{arrow_y - 5} {x2},{arrow_y} {x2 - 6},{arrow_y + 5}" '
            f'fill="{line_color}"/>'
        )

        # Segment label (above arrow)
        if seg.label:
            parts.append(
                f'<text x="{mid_x}" y="{arrow_y - 14}" text-anchor="middle" '
                f'font-size="11" fill="#666">{escape(seg.label)}</text>'
            )

        # Latency pill (below arrow) — always shown; "n/a" when no data
        lat_str = _fmt_latency(seg.latency_ms)
        if lat_str:
            avg_prefix = "~ " if is_aggregated and seg.sample_count > 1 else ""
            pill_text = f"{avg_prefix}{lat_str}"
            pill_fill = "#f8f9fa"
            pill_stroke = "#dee2e6"
            pill_text_fill = "#495057"
        else:
            pill_text = "latency n/a"
            pill_fill = "#f8f9fa"
            pill_stroke = "#dee2e6"
            pill_text_fill = "#adb5bd"
        pill_half_w = 42
        parts.append(
            f'<rect x="{mid_x - pill_half_w}" y="{arrow_y + 6}" width="{pill_half_w * 2}" height="20" rx="10" '
            f'fill="{pill_fill}" stroke="{pill_stroke}" stroke-width="0.8"/>'
            f'<text x="{mid_x}" y="{arrow_y + 19}" text-anchor="middle" '
            f'font-size="10.5" fill="{pill_text_fill}" font-weight="500">{escape(pill_text)}</text>'
        )

        parts.append("</g>")

    # --- Draw nodes ---
    for i, node in enumerate(flow.nodes):
        x = _PAD_X + i * (_NODE_W + _GAP)
        y = y_cursor

        fill, stroke, text_color = _NODE_COLORS.get(node.icon, ("#f8f9fa", "#adb5bd", "#495057"))

        # Hoverable group for the entire node
        parts.append("<g>")
        if node.tooltip:
            parts.append(_tooltip(node.tooltip))

        # Node box
        parts.append(
            f'<rect x="{x}" y="{y}" width="{_NODE_W}" height="{_NODE_H}" rx="10" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
        )

        cx = x + _NODE_W // 2

        # Icon (centered in upper part)
        icon_x = cx - _ICON_SIZE // 2
        icon_y = y + 10
        icon_svg = _ICONS.get(node.icon, _ICONS["app"])
        parts.append(
            f'<svg x="{icon_x}" y="{icon_y}" width="{_ICON_SIZE}" height="{_ICON_SIZE}" viewBox="0 0 16 16">'
            f'{icon_svg.format(color=stroke)}</svg>'
        )

        # Label (bold, below icon)
        parts.append(
            f'<text x="{cx}" y="{y + 10 + _ICON_SIZE + 18}" text-anchor="middle" '
            f'font-size="15" font-weight="700" fill="{text_color}">{escape(node.label)}</text>'
        )

        # Sublabel (below label, inside box)
        if node.sublabel:
            sub = node.sublabel if len(node.sublabel) <= 28 else node.sublabel[:26] + "\u2026"
            parts.append(
                f'<text x="{cx}" y="{y + 10 + _ICON_SIZE + 34}" text-anchor="middle" '
                f'font-size="11" fill="#666">{escape(sub)}</text>'
            )

        parts.append("</g>")  # close node group

        # Detail (below box, outside — not part of the hover group so it
        # doesn't compete with the node tooltip)
        if node.detail:
            det = node.detail if len(node.detail) <= 42 else node.detail[:40] + "\u2026"
            parts.append(
                f'<text x="{cx}" y="{y + _NODE_H + 16}" text-anchor="middle" '
                f'font-size="10" fill="#999">{escape(det)}</text>'
            )

    parts.append("</svg>")
    return "\n".join(parts)
