"""
Inline SVG renderer for the HTTP LB security services pipeline diagram.

Renders a top-down service flow showing the request path through the HTTP
Load Balancer's security pipeline:

  User → Domains (with cert state) → Security Pipeline → WAF → Routes → Pools → Origins

The flow-based approach is inspired by Mike Coleman's ``xcshowmap`` tool
(https://github.com/Mikej81/xcshowmap), which generates Mermaid-based
service flow diagrams from F5 XC configuration. Props to Mike for the
original concept of visualising the XC service chain as a directed graph.
"""

from __future__ import annotations

from html import escape

from ..lb_config import LBConfig, SecurityService

__all__ = ["render_services_svg"]


# ---------------------------------------------------------------------------
# Colors & constants
# ---------------------------------------------------------------------------

# General palette
_BG = "#fff"
_BORDER = "#dee2e6"
_TEXT = "#1a1a1a"
_TEXT_DIM = "#666"
_TEXT_MUTED = "#999"
_LINK_COLOR = "#adb5bd"

# Feature badges
_ON_FILL = "#d4edda"
_ON_STROKE = "#28a745"
_ON_TEXT = "#155724"
_OFF_FILL = "#f8f9fa"
_OFF_STROKE = "#ced4da"
_OFF_TEXT = "#868e96"

# LB header
_LB_FILL = "#d1ecf1"
_LB_STROKE = "#0d6efd"
_LB_TEXT = "#0c5460"

# Domain box
_DOMAIN_FILL = "#e8f4fd"
_DOMAIN_STROKE = "#3498db"

# Cert states
_CERT_VALID_STROKE = "#28a745"
_CERT_WARN_STROKE = "#ffc107"
_CERT_ERR_STROKE = "#dc3545"

# Security pipeline
_SEC_FILL = "#f0f4ff"
_SEC_STROKE = "#0d6efd"

# WAF
_WAF_FILL = "#fdebd0"
_WAF_STROKE = "#e67e22"

# Routes
_ROUTE_FILL = "#f4ecf7"
_ROUTE_STROKE = "#8e44ad"

# Pool / origin
_POOL_FILL = "#eafaf1"
_POOL_STROKE = "#27ae60"


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

_W = 720             # total SVG width
_PAD = 30            # outer padding
_COL_W = _W - _PAD * 2
_ROW_GAP = 16        # vertical gap between rows
_BOX_RX = 8          # border radius
_ARROW_GAP = 8       # gap for arrow


def _arrow_down(parts: list[str], cx: float, y_start: float, y_end: float,
                label: str = "", color: str = _LINK_COLOR) -> None:
    """Draw a vertical arrow between two y-coordinates."""
    y1 = y_start + _ARROW_GAP
    y2 = y_end - _ARROW_GAP - 4
    parts.append(
        f'<line x1="{cx}" y1="{y1}" x2="{cx}" y2="{y2}" '
        f'stroke="{color}" stroke-width="1.5"/>'
    )
    # Arrowhead
    parts.append(
        f'<polygon points="{cx - 4},{y2} {cx},{y2 + 5} {cx + 4},{y2}" fill="{color}"/>'
    )
    if label:
        parts.append(
            f'<text x="{cx + 8}" y="{(y1 + y2) / 2 + 4}" font-size="9" '
            f'fill="{_TEXT_MUTED}">{escape(label)}</text>'
        )


def _box(parts: list[str], x: float, y: float, w: float, h: float,
         fill: str, stroke: str, rx: float = _BOX_RX) -> None:
    parts.append(
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="1.2"/>'
    )


def _text(parts: list[str], x: float, y: float, text: str,
          size: float = 11, weight: str = "400", fill: str = _TEXT,
          anchor: str = "start") -> None:
    parts.append(
        f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" '
        f'fill="{fill}" text-anchor="{anchor}">{escape(text)}</text>'
    )


def _badge(parts: list[str], x: float, y: float, label: str,
           bg: str, fg: str) -> None:
    """Small inline badge."""
    bw = max(len(label) * 5.5 + 10, 28)
    parts.append(
        f'<rect x="{x}" y="{y}" width="{bw}" height="16" rx="8" fill="{bg}"/>'
        f'<text x="{x + bw / 2}" y="{y + 11.5}" text-anchor="middle" '
        f'font-size="8.5" font-weight="700" fill="{fg}">{escape(label)}</text>'
    )


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def render_services_svg(cfg: LBConfig) -> str:
    """Render an inline SVG showing the LB service flow pipeline."""
    if not cfg.services and not cfg.lb_name:
        return ""

    enabled = [s for s in cfg.services if s.enabled]
    disabled = [s for s in cfg.services if not s.enabled]

    parts: list[str] = []
    cx = _W / 2  # center x for arrows

    # Build user identification sub-line for the pipeline
    uid_line = ""
    if cfg.user_identification and cfg.user_identification.rules:
        uid_line = "Identifiers: " + ", ".join(cfg.user_identification.rules)
    elif cfg.user_id_ref and cfg.user_id_ref.get("name"):
        uid_line = f"User ID policy: {cfg.user_id_ref['name']}"
    # Check which service gets the sub-line (Malicious User Detection)
    has_uid_sub = bool(uid_line) and any(
        s.short == "Mal. User" and s.enabled for s in cfg.services
    )

    # --- Pre-calculate total height ---
    y = _PAD
    # Title
    y += 20
    # User box
    user_h = 30
    y += user_h + _ROW_GAP
    # LB header box
    lb_h = 54
    y += lb_h + _ROW_GAP
    # Domains row (if any)
    if cfg.domains:
        domain_h = 24 + 20 * min(len(cfg.domains), 4)
        y += domain_h + _ROW_GAP
    # Security pipeline (enabled services)
    if enabled:
        sec_h = 28 + 22 * len(enabled)
        if has_uid_sub:
            sec_h += 16  # extra line for user identifier
        y += sec_h + _ROW_GAP
    # Disabled note
    if disabled:
        y += 22 + _ROW_GAP
    # Origin pools
    if cfg.origin_pools:
        pool_h = 24 + 18 * min(len(cfg.origin_pools), 6)
        y += pool_h + _ROW_GAP
    # Attribution
    y += 16
    y += _PAD

    total_h = y

    # --- SVG open ---
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_W} {total_h}" '
        f'width="100%" style="min-width:600px;max-width:{_W}px;'
        f"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
        f'margin:0 auto;display:block">'
    )

    y = _PAD

    # --- Title ---
    _text(parts, cx, y + 14, f"{cfg.lb_name or 'HTTP Load Balancer'} — Service Flow",
          size=13, weight="700", fill=_TEXT, anchor="middle")
    y += 20

    # --- User box ---
    _box(parts, _PAD, y, _COL_W, user_h, "#e8f4fd", "#3498db")
    _text(parts, cx, y + 19, "User / Client", size=12, weight="600",
          fill="#2471a3", anchor="middle")
    user_bottom = y + user_h
    y += user_h + _ROW_GAP

    # Arrow: User → LB
    _arrow_down(parts, cx, user_bottom, y)

    # --- LB header box ---
    _box(parts, _PAD, y, _COL_W, lb_h, _LB_FILL, _LB_STROKE)
    info_parts = [cfg.lb_type] if cfg.lb_type else []
    if cfg.advertise_policy:
        info_parts.append(cfg.advertise_policy)
    _text(parts, _PAD + 14, y + 22, cfg.lb_name or "HTTP Load Balancer",
          size=13, weight="700", fill=_LB_TEXT)
    if info_parts:
        _text(parts, _PAD + 14, y + 38, " · ".join(info_parts),
              size=10, fill=_TEXT_DIM)
    # Namespace on right
    if cfg.namespace:
        _text(parts, _PAD + _COL_W - 14, y + 22, f"ns: {cfg.namespace}",
              size=9.5, fill=_TEXT_MUTED, anchor="end")
    lb_bottom = y + lb_h
    y += lb_h + _ROW_GAP

    # --- Domains row ---
    if cfg.domains:
        _arrow_down(parts, cx, lb_bottom, y, label="SNI")
        domain_h = 24 + 20 * min(len(cfg.domains), 4)
        _box(parts, _PAD, y, _COL_W, domain_h, _DOMAIN_FILL, _DOMAIN_STROKE)
        _text(parts, _PAD + 14, y + 16, "Domains", size=11, weight="600", fill="#2471a3")
        for i, domain in enumerate(cfg.domains[:4]):
            dy = y + 32 + i * 20
            _text(parts, _PAD + 24, dy, domain, size=10.5, fill=_TEXT)
        if len(cfg.domains) > 4:
            dy = y + 32 + 4 * 20
            _text(parts, _PAD + 24, dy, f"(+{len(cfg.domains) - 4} more)",
                  size=9.5, fill=_TEXT_MUTED)
        domain_bottom = y + domain_h
        y += domain_h + _ROW_GAP
    else:
        domain_bottom = lb_bottom

    # --- Security pipeline (enabled services) ---
    if enabled:
        _arrow_down(parts, cx, domain_bottom, y)
        sec_h = 28 + 22 * len(enabled)
        if has_uid_sub:
            sec_h += 16  # extra line for user identifier
        _box(parts, _PAD, y, _COL_W, sec_h, _SEC_FILL, _SEC_STROKE)
        _text(parts, _PAD + 14, y + 18, "Security Pipeline",
              size=11, weight="700", fill="#0d6efd")

        row_y = y + 30
        for svc in enabled:
            sy = row_y
            # ON badge
            _badge(parts, _PAD + 18, sy - 6, "ON", _ON_STROKE, "#fff")
            # Service name
            _text(parts, _PAD + 54, sy + 5, svc.name, size=10.5, weight="600", fill=_ON_TEXT)
            # Mode / detail on right
            detail = svc.mode or svc.detail or ""
            if len(detail) > 40:
                detail = detail[:38] + "\u2026"
            if detail:
                _text(parts, _PAD + _COL_W - 14, sy + 5, detail,
                      size=9.5, fill=_TEXT_DIM, anchor="end")
            row_y += 22

            # Sub-line: User Identification under Malicious User Detection
            if svc.short == "Mal. User" and has_uid_sub:
                uid_display = uid_line
                if len(uid_display) > 70:
                    uid_display = uid_display[:68] + "\u2026"
                _text(parts, _PAD + 56, row_y + 3, uid_display,
                      size=9, fill="#6c757d")
                row_y += 16

        sec_bottom = y + sec_h
        y += sec_h + _ROW_GAP
    else:
        sec_bottom = domain_bottom

    # --- Disabled services (compact line) ---
    # Track where the arrow to origin pools should start from
    arrow_source_bottom = sec_bottom
    if disabled:
        names = ", ".join(s.short for s in disabled)
        if len(names) > 80:
            names = names[:78] + "\u2026"
        _text(parts, _PAD + 4, y + 12,
              f"Not enabled: {names}",
              size=9.5, fill=_OFF_TEXT)
        arrow_source_bottom = y + 22   # arrow starts below the text
        y += 22 + _ROW_GAP

    # --- Origin pools ---
    if cfg.origin_pools:
        _arrow_down(parts, cx, arrow_source_bottom, y, label="route")
        pool_h = 24 + 18 * min(len(cfg.origin_pools), 6)
        _box(parts, _PAD, y, _COL_W, pool_h, _POOL_FILL, _POOL_STROKE)
        _text(parts, _PAD + 14, y + 16, "Origin Pools",
              size=11, weight="600", fill="#1e8449")
        for i, pool in enumerate(cfg.origin_pools[:6]):
            py = y + 32 + i * 18
            _text(parts, _PAD + 24, py, pool, size=10.5, fill=_TEXT)
        if len(cfg.origin_pools) > 6:
            py = y + 32 + 6 * 18
            _text(parts, _PAD + 24, py, f"(+{len(cfg.origin_pools) - 6} more)",
                  size=9.5, fill=_TEXT_MUTED)
        y += pool_h + _ROW_GAP

    # --- Attribution ---
    _text(parts, cx, y + 10,
          "Service flow concept inspired by Mike Coleman's xcshowmap (github.com/Mikej81/xcshowmap)",
          size=8, fill="#adb5bd", anchor="middle")

    parts.append("</svg>")
    return "\n".join(parts)
