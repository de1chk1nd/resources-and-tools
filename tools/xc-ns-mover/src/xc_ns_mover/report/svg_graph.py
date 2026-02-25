"""
SVG dependency graph renderer for the mover report.

Renders batch dependency graphs as inline SVGs with two modes:
  - **Simple chain**: single-LB batches with no shared deps — compact
    vertical flow with arrows.
  - **Full graph**: multi-LB or shared-dep batches — multi-column
    layout with colour-coded shared/external dependency indicators.
"""

from __future__ import annotations

from .base import esc
from ..models import FRIENDLY_TYPE_NAMES, BatchGraphData


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _dep_label(dep_key: tuple[str, str]) -> str:
    """Build a short display label for a dependency node."""
    friendly = FRIENDLY_TYPE_NAMES.get(dep_key[0], dep_key[0])
    type_short = {
        "Origin Pool": "OP",
        "Health Check": "HC",
        "TLS Certificate": "Cert",
        "App Firewall": "FW",
        "Service Policy": "SP",
        "API Definition": "API",
        "IP Prefix Set": "IP",
        "Rate Limiter": "RL",
        "User Identification": "UID",
    }.get(friendly, friendly[:4])
    name = dep_key[1]
    label = f"{type_short}: {name}"
    max_len = 24
    if len(label) > max_len:
        label = f"{type_short}: {name[:max_len - len(type_short) - 4]}..."
    return label


# ------------------------------------------------------------------
# Simple chain renderer (single-LB, no shared deps)
# ------------------------------------------------------------------

def _render_chain_svg(
    lb_name: str,
    deps: list[tuple[str, str]],
    dep_children: dict[tuple[str, str], list[tuple[str, str]]],
    external_deps: set[tuple[str, str]] | None = None,
) -> str:
    """Render a simple 1:N chain as a compact vertical SVG.

    Used for single-LB batches with no shared deps.  Produces a clean
    top-to-bottom flow: LB -> direct deps -> sub-deps, with arrows
    showing the direction of dependency.

    Deps in *external_deps* are drawn with a red thick border to
    indicate they are referenced by objects outside the move list.
    """
    ext = external_deps or set()

    # Build ordered chain: LB at top, then for each direct dep any sub-deps below it
    # Each item: (label, node_type, indent_level, dep_key_or_None)
    chain: list[tuple[str, str, int, tuple[str, str] | None]] = []
    chain.append((lb_name, "lb", 0, None))
    for dep_key in deps:
        chain.append((_dep_label(dep_key), "dep", 1, dep_key))
        for child_key in dep_children.get(dep_key, []):
            chain.append((_dep_label(child_key), "leaf", 2, child_key))

    # Layout
    box_w = 200
    box_h = 34
    v_gap = 16
    pad_x = 20
    pad_y = 16
    has_ext = any(dk in ext for _, _, _, dk in chain if dk is not None)
    legend_h = 24 if has_ext else 0

    svg_w = box_w + 2 * pad_x
    n = len(chain)
    svg_h = n * box_h + (n - 1) * v_gap + 2 * pad_y + legend_h

    parts: list[str] = []

    # Colors
    ext_fill = "#fdecea"
    ext_border = "#dc3545"
    colors = {
        "lb":   {"fill": "#0d6efd", "text": "#ffffff", "border": "none"},
        "dep":  {"fill": "#e0f2f1", "text": "#1a1a1a", "border": "#26a69a"},
        "leaf": {"fill": "#f5f5f5", "text": "#1a1a1a", "border": "#9e9e9e"},
    }

    # Arrow marker definition
    parts.append(
        '<defs>'
        '<marker id="arrow" markerWidth="8" markerHeight="6" '
        'refX="8" refY="3" orient="auto" markerUnits="strokeWidth">'
        '<path d="M0,0 L8,3 L0,6" fill="#90a4ae" />'
        '</marker>'
        '</defs>'
    )

    prev_bottom_y = None
    for i, (label, ntype, _, dep_key) in enumerate(chain):
        cx = pad_x + box_w / 2
        y = pad_y + i * (box_h + v_gap)
        is_ext = dep_key is not None and dep_key in ext

        if is_ext:
            fill = ext_fill
            border = ext_border
            stroke_w = "2.5"
        else:
            c = colors[ntype]
            fill = c["fill"]
            border = c["border"]
            stroke_w = "1.5"

        # Draw arrow from previous node
        if prev_bottom_y is not None:
            mid_x = cx
            parts.append(
                f'<line x1="{mid_x}" y1="{prev_bottom_y}" '
                f'x2="{mid_x}" y2="{y}" '
                f'stroke="#90a4ae" stroke-width="1.5" marker-end="url(#arrow)" />'
            )

        # Truncate label
        display = label if len(label) <= 26 else label[:24] + "..."
        border_attr = (
            f' stroke="{border}" stroke-width="{stroke_w}"'
            if border != "none" else ""
        )
        text_color = colors[ntype]["text"] if not is_ext else "#1a1a1a"
        font_w = ' font-weight="600"' if ntype == "lb" else ""
        font_s = "12" if ntype == "lb" else "11"
        parts.append(
            f'<rect x="{pad_x}" y="{y}" width="{box_w}" height="{box_h}" '
            f'rx="6" fill="{fill}"{border_attr} />'
            f'<text x="{cx}" y="{y + box_h/2 + 4}" text-anchor="middle" '
            f'fill="{text_color}" font-size="{font_s}"{font_w}>'
            f'{esc(display)}</text>'
        )
        prev_bottom_y = y + box_h

    # Legend
    legend = ""
    if has_ext:
        ly = pad_y + n * box_h + (n - 1) * v_gap + 8
        legend = (
            f'<g transform="translate(10, {ly})">'
            f'<rect x="0" y="0" width="14" height="14" rx="3" '
            f'fill="{ext_fill}" stroke="{ext_border}" stroke-width="2.5" />'
            f'<text x="20" y="11" font-size="10" fill="#666">'
            f'used by external object (not in move list)</text>'
            f'</g>'
        )

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{svg_w}" height="{svg_h}" '
        f'style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; '
        f'background: #fff; border: 1px solid #dee2e6; border-radius: 6px; '
        f'margin-bottom: 1rem;">'
        + "\n".join(parts)
        + legend
        + "</svg>"
    )


# ------------------------------------------------------------------
# Full graph renderer (multi-LB / shared-dep batches)
# ------------------------------------------------------------------

def render_batch_svg(batch: BatchGraphData) -> str:
    """Render a batch dependency graph as an inline SVG.

    Two rendering modes:
      - **Simple chain** (single LB, no shared deps): compact vertical
        flow with arrows.  Easy to read for straightforward 1:1:1 chains
        like LB -> Origin Pool -> Health Check.
      - **Full graph** (multiple LBs or shared deps): multi-column
        layout showing how LBs fan out to shared and independent deps.
        Shared dependencies are highlighted with orange borders and lines
        so the admin can immediately see what is interconnected.

    Layout for the full graph (top to bottom):
      Row 0: HTTP LBs (blue boxes)
      Row 1: Direct deps — origin pools, certs, firewalls, ... (teal boxes)
      Row 2: Leaf deps — health checks, ... (grey boxes)
    """
    # Collect unique dep nodes by tier:
    # tier 1 = directly referenced by an LB
    # tier 2 = referenced by a tier-1 dep (sub-dep)
    tier1_deps: list[tuple[str, str]] = []  # ordered, unique
    tier2_deps: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for lb_name in batch.lb_names:
        for dep_key in batch.lb_to_deps.get(lb_name, []):
            if dep_key not in seen:
                seen.add(dep_key)
                tier1_deps.append(dep_key)

    for parent_key in tier1_deps:
        for child_key in batch.dep_children.get(parent_key, []):
            if child_key not in seen:
                seen.add(child_key)
                tier2_deps.append(child_key)

    # ---- Simple chain mode for single-LB, no shared deps ----
    if len(batch.lb_names) == 1 and not batch.shared_deps:
        return _render_chain_svg(
            batch.lb_names[0],
            batch.lb_to_deps.get(batch.lb_names[0], []),
            batch.dep_children,
            external_deps=batch.external_deps,
        )

    # ---- Full graph mode for multi-LB / shared-dep batches ----

    # Layout constants
    box_w = 180
    box_h = 36
    h_gap = 24
    v_gap = 60
    pad_x = 20
    pad_y = 20
    has_shared = bool(batch.shared_deps)
    has_ext = bool(batch.external_deps)
    legend_lines = int(has_shared) + int(has_ext)
    legend_h = legend_lines * 20 + (8 if legend_lines else 0)

    # Calculate row widths to center each row
    n_lbs = len(batch.lb_names)
    n_t1 = len(tier1_deps)
    n_t2 = len(tier2_deps)

    row_counts = [n_lbs]
    if tier1_deps:
        row_counts.append(n_t1)
    if tier2_deps:
        row_counts.append(n_t2)
    n_rows = len(row_counts)

    max_items = max(row_counts) if row_counts else 1
    svg_w = max(max_items * (box_w + h_gap) - h_gap + 2 * pad_x, 300)
    content_h = n_rows * (box_h + v_gap) - v_gap + 2 * pad_y
    svg_h = content_h + legend_h

    def row_x_start(n_items: int) -> float:
        row_width = n_items * (box_w + h_gap) - h_gap
        return (svg_w - row_width) / 2

    # Compute positions: node_id -> (cx, cy)
    positions: dict[str, tuple[float, float]] = {}

    # Row 0: LBs
    x0 = row_x_start(n_lbs)
    for i, lb_name in enumerate(batch.lb_names):
        cx = x0 + i * (box_w + h_gap) + box_w / 2
        cy = pad_y + box_h / 2
        positions[f"lb:{lb_name}"] = (cx, cy)

    # Row 1: tier-1 deps
    if tier1_deps:
        x1 = row_x_start(n_t1)
        for i, dep_key in enumerate(tier1_deps):
            cx = x1 + i * (box_w + h_gap) + box_w / 2
            cy = pad_y + (box_h + v_gap) + box_h / 2
            positions[f"dep:{dep_key[0]}:{dep_key[1]}"] = (cx, cy)

    # Row 2: tier-2 deps
    if tier2_deps:
        row_idx = 2 if tier1_deps else 1
        x2 = row_x_start(n_t2)
        for i, dep_key in enumerate(tier2_deps):
            cx = x2 + i * (box_w + h_gap) + box_w / 2
            cy = pad_y + row_idx * (box_h + v_gap) + box_h / 2
            positions[f"dep:{dep_key[0]}:{dep_key[1]}"] = (cx, cy)

    # Build SVG elements
    parts: list[str] = []

    # Colors
    lb_fill = "#0d6efd"
    lb_text = "#ffffff"
    dep_fill = "#e0f2f1"
    dep_border = "#26a69a"
    dep_text = "#1a1a1a"
    leaf_fill = "#f5f5f5"
    leaf_border = "#9e9e9e"
    shared_border = "#e67e22"
    shared_fill = "#fef3e8"
    ext_border = "#dc3545"
    ext_fill = "#fdecea"
    line_color = "#90a4ae"
    shared_line_color = "#e67e22"

    # Arrow marker definitions
    parts.append(
        '<defs>'
        '<marker id="arr" markerWidth="8" markerHeight="6" '
        'refX="8" refY="3" orient="auto" markerUnits="strokeWidth">'
        f'<path d="M0,0 L8,3 L0,6" fill="{line_color}" />'
        '</marker>'
        '<marker id="arr-shared" markerWidth="8" markerHeight="6" '
        'refX="8" refY="3" orient="auto" markerUnits="strokeWidth">'
        f'<path d="M0,0 L8,3 L0,6" fill="{shared_line_color}" />'
        '</marker>'
        '</defs>'
    )

    # Draw connecting lines (behind boxes)
    # LB -> tier1 deps
    for lb_name in batch.lb_names:
        lb_id = f"lb:{lb_name}"
        for dep_key in batch.lb_to_deps.get(lb_name, []):
            dep_id = f"dep:{dep_key[0]}:{dep_key[1]}"
            if lb_id in positions and dep_id in positions:
                x1, y1 = positions[lb_id]
                x2, y2 = positions[dep_id]
                is_shared = dep_key in batch.shared_deps
                color = shared_line_color if is_shared else line_color
                width = "2.5" if is_shared else "1.5"
                marker = "url(#arr-shared)" if is_shared else "url(#arr)"
                parts.append(
                    f'<line x1="{x1}" y1="{y1 + box_h/2}" '
                    f'x2="{x2}" y2="{y2 - box_h/2}" '
                    f'stroke="{color}" stroke-width="{width}" '
                    f'marker-end="{marker}" />'
                )

    # tier1 dep -> tier2 dep (sub-deps)
    for parent_key in tier1_deps:
        parent_id = f"dep:{parent_key[0]}:{parent_key[1]}"
        for child_key in batch.dep_children.get(parent_key, []):
            child_id = f"dep:{child_key[0]}:{child_key[1]}"
            if parent_id in positions and child_id in positions:
                x1, y1 = positions[parent_id]
                x2, y2 = positions[child_id]
                is_shared = child_key in batch.shared_deps
                color = shared_line_color if is_shared else line_color
                width = "2.5" if is_shared else "1.5"
                marker = "url(#arr-shared)" if is_shared else "url(#arr)"
                parts.append(
                    f'<line x1="{x1}" y1="{y1 + box_h/2}" '
                    f'x2="{x2}" y2="{y2 - box_h/2}" '
                    f'stroke="{color}" stroke-width="{width}" '
                    f'marker-end="{marker}" />'
                )

    # Draw LB boxes
    for lb_name in batch.lb_names:
        node_id = f"lb:{lb_name}"
        cx, cy = positions[node_id]
        x = cx - box_w / 2
        y = cy - box_h / 2
        # Truncate name for display
        display = lb_name if len(lb_name) <= 22 else lb_name[:20] + "..."
        parts.append(
            f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" '
            f'rx="6" fill="{lb_fill}" />'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" '
            f'fill="{lb_text}" font-size="12" font-weight="600">'
            f'{esc(display)}</text>'
        )

    # Draw dep boxes
    def _draw_dep_box(dep_key: tuple[str, str], is_leaf: bool) -> None:
        node_id = f"dep:{dep_key[0]}:{dep_key[1]}"
        if node_id not in positions:
            return
        cx, cy = positions[node_id]
        x = cx - box_w / 2
        y = cy - box_h / 2
        is_ext_d = dep_key in batch.external_deps
        is_shared_d = dep_key in batch.shared_deps
        if is_ext_d:
            # External ref takes visual priority — red thick border
            fill_d = ext_fill
            border_d = ext_border
        elif is_shared_d:
            fill_d = shared_fill
            border_d = shared_border
        elif is_leaf:
            fill_d = leaf_fill
            border_d = leaf_border
        else:
            fill_d = dep_fill
            border_d = dep_border
        stroke_w_d = "2.5" if (is_ext_d or is_shared_d) else "1.5"
        label = _dep_label(dep_key)
        parts.append(
            f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" '
            f'rx="6" fill="{fill_d}" stroke="{border_d}" stroke-width="{stroke_w_d}" />'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" '
            f'fill="{dep_text}" font-size="11">'
            f'{esc(label)}</text>'
        )

    for dep_key in tier1_deps:
        _draw_dep_box(dep_key, is_leaf=False)
    for dep_key in tier2_deps:
        _draw_dep_box(dep_key, is_leaf=True)

    # Legend
    legend_parts: list[str] = []
    legend_y = content_h + 4
    if has_ext:
        legend_parts.append(
            f'<g transform="translate(10, {legend_y})">'
            f'<rect x="0" y="0" width="14" height="14" rx="3" '
            f'fill="{ext_fill}" stroke="{ext_border}" stroke-width="2.5" />'
            f'<text x="20" y="11" font-size="10" fill="#666">'
            f'used by external object (not in move list)</text>'
            f'</g>'
        )
        legend_y += 20
    if has_shared:
        legend_parts.append(
            f'<g transform="translate(10, {legend_y})">'
            f'<rect x="0" y="0" width="14" height="14" rx="3" '
            f'fill="{shared_fill}" stroke="{shared_border}" stroke-width="2" />'
            f'<text x="20" y="11" font-size="10" fill="#666">shared dependency '
            f'(used by multiple LBs in this batch)</text>'
            f'</g>'
        )
    legend = "\n".join(legend_parts)

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{svg_w}" height="{svg_h}" '
        f'style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; '
        f'background: #fff; border: 1px solid #dee2e6; border-radius: 6px; '
        f'margin-bottom: 1rem;">'
        + "\n".join(parts)
        + legend
        + "</svg>"
    )
