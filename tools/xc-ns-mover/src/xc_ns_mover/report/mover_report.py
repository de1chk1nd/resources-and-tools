"""
Mover HTML report generator.

Produces the pre-migration (dry-run) or post-migration HTML report with:
  - Health indicator (traffic-light)
  - LB summary table with issue chips
  - DNS changes section
  - TLS certificate pre-flight section
  - Dependency check section (with dep graph SVGs)
  - Planned configuration & backup sections
"""

from __future__ import annotations

from datetime import datetime

from .base import esc, render_html_page
from .svg_graph import render_batch_svg
from ..models import (
    FRIENDLY_TYPE_NAMES,
    BatchGraphData,
    DepMoveResult,
    ManualReworkItem,
    MoveResult,
)


# ------------------------------------------------------------------
# Mover-specific CSS (appended to base CSS via render_html_page)
# ------------------------------------------------------------------

_MOVER_CSS = """\
  h2 { margin-top: 2rem; }
  .mode-badge { display: inline-block; background: #ffc107; color: #000; font-weight: 700;
                 padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.85rem; margin-left: 0.5rem; }
  .warning-banner { background: #fff3cd; border: 1px solid #ffc107; border-left: 5px solid #ffc107;
                     border-radius: 6px; padding: 1rem 1.25rem; margin-bottom: 1.5rem; font-size: 0.9rem; }
  .warning-banner strong { color: #856404; }
  .warning-banner p { margin: 0.5rem 0; }
  .warning-banner ul { margin: 0.25rem 0 0 1.25rem; padding: 0; }
  .warning-banner li { margin-bottom: 0.25rem; }
  .summary { display: flex; gap: 1.5rem; margin-bottom: 1.5rem; }
  .summary .card { background: #fff; border: 1px solid #dee2e6; border-radius: 6px;
                    padding: 0.75rem 1.25rem; min-width: 100px; text-align: center; }
  .summary .card .num { font-size: 1.5rem; font-weight: 700; }
  .summary .card .label { font-size: 0.8rem; color: #666; text-transform: uppercase; }
  .card-moved .num { color: #198754; }
  .card-dryrun .num { color: #0d6efd; }
  .card-failed .num { color: #dc3545; }
  .card-reverted .num { color: #e67e22; }
  .card-blocked .num { color: #9b59b6; }
  .card-skipped .num { color: #6c757d; }
  td a { color: #0d6efd; text-decoration: none; }
  td a:hover { text-decoration: underline; }
  .backup-link { font-size: 0.75rem; color: #6c757d !important; }
  .status-moved { color: #198754; font-weight: 600; }
  .status-dryrun { color: #0d6efd; font-weight: 600; }
  .status-failed { color: #dc3545; font-weight: 600; }
  .status-reverted { color: #e67e22; font-weight: 600; }
  .status-blocked { color: #9b59b6; font-weight: 600; }
  .status-skipped { color: #6c757d; font-weight: 600; }
  .status-manual-rework { color: #e67e22; font-weight: 600; }

  .dns-table { border-collapse: collapse; width: 100%; background: #fff;
                border: 1px solid #dee2e6; border-radius: 6px; overflow: hidden;
                margin-bottom: 2rem; }
  .dns-table th { background: #e67e22; font-size: 0.8rem; }
  .dns-table td { font-size: 0.82rem; }
  .dns-table td strong { color: #c0392b; }
  .dns-lb-cell { font-weight: 600; vertical-align: top; border-right: 3px solid #e67e22;
                   background: #fff8f0 !important; }
  .dns-lb-tls { font-weight: 400; font-size: 0.72rem; color: #888; }
  .dns-table tr.dns-group-first td { border-top: 2px solid #ccc; }
  .dns-advice { background: #fff8f0; border: 1px solid #f5c78e; border-left: 5px solid #e67e22;
                  border-radius: 6px; padding: 1rem 1.25rem; margin-bottom: 1.25rem;
                  font-size: 0.88rem; line-height: 1.5; }
  .dns-advice p { margin: 0.4rem 0; }
  .dns-advice ol { margin: 0.25rem 0 0.5rem 1.25rem; padding: 0; }
  .dns-advice li { margin-bottom: 0.3rem; }

  /* --- DNS status banner --- */
  .dns-status-banner {
      display: flex; align-items: flex-start; gap: 1.25rem;
      padding: 1.25rem 1.5rem; border-radius: 10px;
      margin-bottom: 1.5rem; border: 1px solid;
      box-shadow: 0 2px 8px rgba(0,0,0,0.06);
  }
  .dns-status-icon {
      flex-shrink: 0; width: 52px; height: 52px; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-size: 1.5rem;
      box-shadow: 0 0 0 4px rgba(255,255,255,0.6), 0 0 10px rgba(0,0,0,0.1);
  }
  .dns-status-body { flex: 1; min-width: 0; }
  .dns-status-headline { font-size: 1.1rem; font-weight: 700; margin: 0 0 0.3rem 0; }
  .dns-status-detail { font-size: 0.88rem; line-height: 1.5; opacity: 0.9; }
  .dns-action-needed {
      background: #fce4cc; color: #7c4a03; border-color: #f5c89a;
  }
  .dns-action-needed .dns-status-icon {
      background: #e67e22; color: #fff;
  }
  .dns-no-action {
      background: #d4edda; color: #155724; border-color: #b7dfb9;
  }
  .dns-no-action .dns-status-icon {
      background: #28a745; color: #fff;
  }
  .dns-auto-managed {
      background: #d4edda; color: #155724; border-color: #b7dfb9;
  }
  .dns-auto-managed .dns-status-icon {
      background: #28a745; color: #fff;
  }

  .error { color: #dc3545; font-size: 0.8rem; word-break: break-word; }
  .rework-banner { background: #fff3cd; border: 1px solid #ffc107;
                    border-left: 5px solid #e67e22; border-radius: 6px;
                    padding: 1rem 1.25rem; margin-bottom: 1.5rem; font-size: 0.9rem; }
  .rework-banner strong { color: #856404; }
  .rework-banner p { margin: 0.5rem 0; }
  .rework-instructions { background: #f8f9fa; border: 1px solid #dee2e6;
                          border-radius: 6px; padding: 1rem 1.25rem;
                          margin-bottom: 1.5rem; font-size: 0.9rem; }
  .rework-instructions ol { margin: 0.5rem 0 0.5rem 1.5rem; padding: 0; }
  .rework-instructions li { margin-bottom: 0.5rem; }
  .rework-matched { background: #d4edda; border: 1px solid #c3e6cb;
                     border-radius: 6px; padding: 0.5rem 0.75rem;
                     margin-bottom: 0.5rem; font-size: 0.85rem; }
  .rework-unmatched { background: #f8d7da; border: 1px solid #f5c6cb;
                       border-radius: 6px; padding: 0.5rem 0.75rem;
                       margin-bottom: 0.5rem; font-size: 0.85rem; }
  .card-rework .num { color: #e67e22; }

  /* --- Rework status banner (certificate pre-flight) --- */
  .rework-status-banner {
      display: flex; align-items: flex-start; gap: 1.25rem;
      padding: 1.25rem 1.5rem; border-radius: 10px;
      margin-bottom: 1.5rem; border: 1px solid;
      box-shadow: 0 2px 8px rgba(0,0,0,0.06);
  }
  .rework-status-icon {
      flex-shrink: 0; width: 52px; height: 52px; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-size: 1.5rem;
      box-shadow: 0 0 0 4px rgba(255,255,255,0.6), 0 0 10px rgba(0,0,0,0.1);
  }
  .rework-status-body { flex: 1; min-width: 0; }
  .rework-status-headline { font-size: 1.1rem; font-weight: 700; margin: 0 0 0.3rem 0; }
  .rework-status-detail { font-size: 0.88rem; line-height: 1.5; opacity: 0.9; }
  .rework-ok {
      background: #d4edda; color: #155724; border-color: #b7dfb9;
  }
  .rework-ok .rework-status-icon {
      background: #28a745; color: #fff;
  }
  .rework-blocked {
      background: #fce4cc; color: #7c4a03; border-color: #f5c89a;
  }
  .rework-blocked .rework-status-icon {
      background: #e67e22; color: #fff;
  }

  /* --- Health indicator (traffic-light style) --- */
  .health-banner {
      display: flex; align-items: flex-start; gap: 1.25rem;
      padding: 1.25rem 1.5rem; border-radius: 10px;
      margin-bottom: 1.75rem; border: 1px solid;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
  }
  .health-light {
      flex-shrink: 0; width: 56px; height: 56px; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-size: 1.6rem; color: #fff;
      box-shadow: 0 0 0 4px rgba(255,255,255,0.6), 0 0 12px rgba(0,0,0,0.15);
  }
  .health-body { flex: 1; min-width: 0; }
  .health-headline { font-size: 1.15rem; font-weight: 700; margin: 0 0 0.35rem 0; }
  .health-stats { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 0.5rem; }
  .health-pill {
      display: inline-block; padding: 0.15rem 0.55rem; border-radius: 10px;
      font-size: 0.78rem; font-weight: 600; background: rgba(255,255,255,0.65);
      border: 1px solid rgba(0,0,0,0.1);
  }
  .health-findings { margin: 0; padding: 0; list-style: none; }
  .health-findings li {
      font-size: 0.82rem; padding: 0.2rem 0; line-height: 1.4;
      border-bottom: 1px dashed rgba(0,0,0,0.08);
  }
  .health-findings li:last-child { border-bottom: none; }
  .health-findings .hf-icon { margin-right: 0.35rem; }

  .health-green  { background: #d4edda; color: #155724; border-color: #b7dfb9; }
  .health-green  .health-light { background: #28a745; }
  .health-green  .health-pill  { color: #155724; }
  .health-yellow { background: #fff3cd; color: #664d03; border-color: #ffe69c; }
  .health-yellow .health-light { background: #ffc107; color: #664d03; }
  .health-yellow .health-pill  { color: #664d03; }
  .health-orange { background: #fce4cc; color: #7c4a03; border-color: #f5c89a; }
  .health-orange .health-light { background: #e67e22; }
  .health-orange .health-pill  { color: #7c4a03; }
  .health-red    { background: #f8d7da; color: #721c24; border-color: #f1aeb5; }
  .health-red    .health-light { background: #dc3545; }
  .health-red    .health-pill  { color: #721c24; }
  .rename-badge { display: inline-block; background: #e0f2f1; color: #00695c; font-weight: 600;
                   padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.78rem; margin-left: 0.3rem;
                   border: 1px solid #26a69a; }
  details { margin-bottom: 0.75rem; }
  summary { cursor: pointer; padding: 0.5rem 0.75rem; background: #fff;
             border: 1px solid #dee2e6; border-radius: 6px; font-weight: 600;
             font-size: 0.9rem; }
  summary:hover { background: #f0f4ff; }
  summary .meta { font-weight: 400; margin: 0; display: inline; }
  .dep-subsection > summary { background: #e9ecef; font-size: 0.95rem;
                               padding: 0.6rem 1rem; margin-bottom: 0; }
  .dep-subsection { margin-bottom: 1rem; }
  .dep-subsection-body { padding: 0.75rem 0 0 0; }

  /* --- Dependency status banner --- */
  .dep-status-banner {
      display: flex; align-items: flex-start; gap: 1.25rem;
      padding: 1.25rem 1.5rem; border-radius: 10px;
      margin-bottom: 1.5rem; border: 1px solid;
      box-shadow: 0 2px 8px rgba(0,0,0,0.06);
  }
  .dep-status-icon {
      flex-shrink: 0; width: 52px; height: 52px; border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      font-size: 1.5rem;
      box-shadow: 0 0 0 4px rgba(255,255,255,0.6), 0 0 10px rgba(0,0,0,0.1);
  }
  .dep-status-body { flex: 1; min-width: 0; }
  .dep-status-headline { font-size: 1.1rem; font-weight: 700; margin: 0 0 0.3rem 0; }
  .dep-status-detail { font-size: 0.88rem; line-height: 1.5; opacity: 0.9; }
  .dep-ok {
      background: #d4edda; color: #155724; border-color: #b7dfb9;
  }
  .dep-ok .dep-status-icon {
      background: #28a745; color: #fff;
  }
  .dep-issues {
      background: #fce4cc; color: #7c4a03; border-color: #f5c89a;
  }
  .dep-issues .dep-status-icon {
      background: #e67e22; color: #fff;
  }
  .dep-issue-list {
      margin: 0.6rem 0 0 0; padding: 0; list-style: none;
  }
  .dep-issue-list li {
      padding: 0.3rem 0; border-bottom: 1px solid rgba(0,0,0,0.08);
      font-size: 0.84rem; line-height: 1.4;
  }
  .dep-issue-list li:last-child { border-bottom: none; }
  .lb-issues {
      display: flex; flex-wrap: wrap; gap: 0.3rem; margin: 0; padding: 0;
  }
  .lb-chip {
      display: inline-flex; align-items: center; gap: 0.25rem;
      padding: 0.15rem 0.5rem; border-radius: 4px;
      font-size: 0.75rem; line-height: 1.3; white-space: nowrap;
  }
  .lb-chip-blocked {
      background: #fdecea; color: #943030;
  }
  .lb-chip-rework {
      background: #fef3e2; color: #7c4a03;
  }
  .lb-chip-failed {
      background: #fdecea; color: #943030;
  }
  .lb-chip-reverted {
      background: #fef3e2; color: #7c4a03;
  }
  .lb-chip-ok {
      background: #d4edda; color: #155724;
  }
  .lb-chip-note {
      background: #d6eaf8; color: #1a5276;
  }
  .lb-chip-link {
      text-decoration: none; color: inherit;
  }
  .lb-chip-link:hover .lb-chip {
      filter: brightness(0.92); cursor: pointer;
  }
  tr.lb-row-blocked td { background: #fdf2f2; }
  tr.lb-row-failed td { background: #fdf2f2; }
  tr.lb-row-reverted td { background: #fef9ef; }
  tr.lb-row-ok td { }
  tbody tr { border-bottom: 1px solid #e9ecef; }
  tbody tr:last-child { border-bottom: none; }

  .backup-group > summary { background: #e9ecef; font-size: 0.95rem; }
  .backup-group-inner { padding: 0.5rem 0 0.5rem 1.25rem;
                         border-left: 3px solid #dee2e6; margin-left: 0.5rem; }
  .backup-inner { font-size: 0.85rem; background: #f8f9fa; }
  .backup-dep { padding-left: 1rem; }
  .backup-xref { font-size: 0.83rem; color: #6c757d; padding: 0.35rem 0.75rem 0.35rem 1.75rem;
                  border-left: 2px dashed #ced4da; margin: 0.25rem 0; }
  .backup-xref a { color: #0d6efd; text-decoration: none; }
  .backup-xref a:hover { text-decoration: underline; }
"""


# ------------------------------------------------------------------
# Section builders
# ------------------------------------------------------------------

def _build_lb_rows(results: list[MoveResult], dry_run: bool) -> str:
    """Build the HTML rows for the LB summary table."""
    _FRIENDLY = FRIENDLY_TYPE_NAMES

    lb_rows_html: list[str] = []
    for idx, r in enumerate(results):
        status_class = {
            "moved": "status-moved", "dry-run": "status-dryrun",
            "failed": "status-failed", "skipped": "status-skipped",
            "reverted": "status-reverted", "blocked": "status-blocked",
        }.get(r.status, "")

        # Build per-LB details cell as a structured issue list
        _chip_cls = {
            "blocked": "lb-chip-blocked", "failed": "lb-chip-failed",
            "reverted": "lb-chip-reverted", "manual-rework": "lb-chip-rework",
        }
        _chip_icon = {
            "blocked": "&#128683;", "failed": "&#10060;",
            "reverted": "&#8634;", "manual-rework": "&#128295;",
            "skipped": "&#9898;",
        }
        _chips: list[str] = []
        _dep_chips: list[tuple[int, str]] = []

        # LB-level issue chip
        _lb_chip = ""
        if r.error:
            cls = _chip_cls.get(r.status, "lb-chip-blocked")
            icon = _chip_icon.get(r.status, "&#9888;")
            href = "#cert-preflight"
            if "non-portable private key" in r.error:
                label = "Unmatched TLS cert"
            elif "shares dependencies" in r.error or "Batch blocked" in r.error:
                label = "Batch cert blocked"
            elif "name conflict" in r.error:
                label = "Name conflict"
                cls = "lb-chip-reverted"
                href = ""
            elif "external" in r.error.lower() and "reference" in r.error.lower():
                label = "External refs"
                href = "#dep-check"
            else:
                _dot = r.error.find(". ")
                label = r.error[:_dot] if 0 < _dot < 60 else r.error[:50]
                if len(label) < len(r.error):
                    label += "\u2026"
                href = "#dep-check"
            if href:
                _lb_chip = (
                    f'<a href="{href}" class="lb-chip-link">'
                    f'<span class="lb-chip {cls}" title="{esc(r.error)}">{icon} {esc(label)}</span></a>'
                )
            else:
                _lb_chip = f'<span class="lb-chip {cls}" title="{esc(r.error)}">{icon} {esc(label)}</span>'

        # Dep-level issue chips
        _severity_order = {"manual-rework": 0, "failed": 1, "blocked": 2, "reverted": 3, "note": 4}
        for d in r.dependencies:
            if d.status in ("blocked", "failed", "reverted", "manual-rework"):
                friendly_type = _FRIENDLY.get(d.resource_type, d.resource_type)
                dep_display = d.new_name if d.new_name else d.name
                cls = _chip_cls.get(d.status, "lb-chip-blocked")
                icon = _chip_icon.get(d.status, "&#8226;")

                _cert_matched = (
                    d.status == "manual-rework"
                    and d.resource_type == "certificates"
                    and d.error
                    and ("rewritten" in d.error.lower() or "matched" in d.error.lower())
                )
                if _cert_matched:
                    cls = "lb-chip-note"
                    icon = "&#128204;"
                    _sort_key = _severity_order.get("note", 9)
                else:
                    _sort_key = _severity_order.get(d.status, 9)

                if d.resource_type == "certificates":
                    dep_href = "#cert-preflight"
                else:
                    dep_href = "#dep-check"
                chip_html = (
                    f'<a href="{dep_href}" class="lb-chip-link">'
                    f'<span class="lb-chip {cls}" title="{esc(d.error)}">'
                    f'{icon} {esc(friendly_type)}: {esc(dep_display)}</span></a>'
                )
                _dep_chips.append((_sort_key, chip_html))

        _dep_chips.sort(key=lambda x: x[0])
        if _lb_chip:
            _chips.append(_lb_chip)
        _chips.extend(html for _, html in _dep_chips)

        # DNS chip for successful LE LBs
        if not _chips and r.status in ("moved", "dry-run") and "encrypt" in r.tls_mode.lower():
            _dns_href = "#dns-changes"
            if r.dns_managed:
                _dns_chip = (
                    f'<a href="{_dns_href}" class="lb-chip-link">'
                    f'<span class="lb-chip lb-chip-note" title="DNS is managed by XC — records will be updated automatically. Review the DNS section for details.">'
                    f'&#128204; DNS (auto-managed)</span></a>'
                )
            else:
                _dns_chip = (
                    f'<a href="{_dns_href}" class="lb-chip-link">'
                    f'<span class="lb-chip lb-chip-rework" title="CNAME and ACME challenge records will change after move — manual DNS update required. Review the DNS section below.">'
                    f'&#128295; DNS update required</span></a>'
                )
            _chips.append(_dns_chip)

        if _chips:
            error_cell = '<div class="lb-issues">' + "\n".join(_chips) + '</div>'
        elif r.status in ("moved", "dry-run"):
            error_cell = '<span class="lb-chip lb-chip-ok">&#10004; OK</span>'
        else:
            error_cell = ""

        _row_class = {
            "blocked": "lb-row-blocked", "failed": "lb-row-failed",
            "reverted": "lb-row-reverted",
        }.get(r.status, "lb-row-ok")

        name_cell = esc(r.lb_name)
        if r.planned_config_json:
            anchor = f"config-{idx}"
            name_cell = f'<a href="#{anchor}">{esc(r.lb_name)}</a>'

        rename_badge = ""
        if r.new_lb_name:
            rename_badge = (
                f' <span class="rename-badge" title="Renamed due to name conflict">'
                f'&rarr; {esc(r.new_lb_name)}</span>'
            )

        backup_link = ""
        if r.backup_json:
            backup_anchor = f"backup-{idx}"
            backup_link = f' <a href="#{backup_anchor}" class="backup-link" title="View original config">[backup]</a>'

        tls_cell = esc(r.tls_mode)

        lb_rows_html.append(
            f'<tr class="{_row_class}">'
            f"<td>{name_cell}{rename_badge}{backup_link}</td>"
            f"<td>{esc(r.src_namespace)}</td>"
            f"<td>{esc(r.dst_namespace)}</td>"
            f"<td>{tls_cell}</td>"
            f'<td class="{status_class}">{esc(r.status.upper())}</td>'
            f"<td>{error_cell}</td>"
            f"</tr>"
        )

    return "\n".join(lb_rows_html)


def _build_dns_section(results: list[MoveResult]) -> tuple[str, int, int]:
    """Build the DNS Changes HTML section."""
    dns_rows: list[str] = []
    dns_lb_count = 0
    dns_managed_count = 0
    dns_manual_count = 0
    cname_only_rows: list[str] = []

    for r in results:
        has_cname_change = (
            r.status in ("moved", "reverted")
            and r.cname_new
            and r.cname_old != r.cname_new
            and r.cname_new not in ("", "-", "(fetch failed)")
        )
        is_letsencrypt = "encrypt" in r.tls_mode.lower()
        is_letsencrypt_dryrun = r.status == "dry-run" and is_letsencrypt

        if has_cname_change and not is_letsencrypt:
            lb_display = esc(r.new_lb_name) if r.new_lb_name else esc(r.lb_name)
            cname_only_rows.append(
                f"<tr>"
                f"<td>{lb_display}</td>"
                f"<td>{esc(r.tls_mode)}</td>"
                f"<td>{esc(r.cname_old) or '-'}</td>"
                f"<td><strong>{esc(r.cname_new)}</strong></td>"
                f"</tr>"
            )
            continue

        if not has_cname_change and not is_letsencrypt_dryrun:
            continue

        dns_lb_count += 1
        if r.dns_managed:
            dns_managed_count += 1
        else:
            dns_manual_count += 1

        lb_display = esc(r.new_lb_name) if r.new_lb_name else esc(r.lb_name)
        lb_anchor = f"dns-lb-{dns_lb_count}"
        domains = r.domains or ["(unknown)"]

        if r.dns_managed:
            old_host = esc(r.cname_old) or "-"
            if has_cname_change:
                new_host = f'<strong>{esc(r.cname_new)}</strong>'
                old_acme = esc(r.acme_cname_old) if r.acme_cname_old else "<em>n/a</em>"
                new_acme = (
                    f'<strong>{esc(r.acme_cname_new)}</strong>'
                    if r.acme_cname_new and r.acme_cname_new not in ("", "(fetch failed)")
                    else "<em>auto-managed by XC</em>"
                )
            else:
                new_host = "<em>auto-managed by XC</em>"
                old_acme = esc(r.acme_cname_old) if r.acme_cname_old else "<em>n/a</em>"
                new_acme = "<em>auto-managed by XC</em>"
            status_label = "AUTO-MANAGED"
            status_cls = "status-moved"
        elif has_cname_change:
            old_host = esc(r.cname_old) or "<em>none</em>"
            new_host = f'<strong>{esc(r.cname_new)}</strong>'
            old_acme = esc(r.acme_cname_old) if r.acme_cname_old else "<em>n/a</em>"
            new_acme = (
                f'<strong>{esc(r.acme_cname_new)}</strong>'
                if r.acme_cname_new and r.acme_cname_new not in ("", "(fetch failed)")
                else "<em>check XC Console after move</em>"
            )
            status_label = "UPDATE"
            status_cls = "status-moved"
        else:
            old_host = esc(r.cname_old) or "-"
            new_host = "<em>assigned after move</em>"
            old_acme = esc(r.acme_cname_old) if r.acme_cname_old else "<em>n/a</em>"
            new_acme = "<em>assigned after move</em>"
            status_label = "WILL CHANGE"
            status_cls = "status-dryrun"

        for i, domain in enumerate(domains):
            safe_domain = esc(domain)
            lb_cell = ""
            group_cls = ' class="dns-group-first"' if i == 0 else ""
            if i == 0:
                rowspan = len(domains) * 2
                lb_cell = (
                    f'<td id="{lb_anchor}" rowspan="{rowspan}" '
                    f'class="dns-lb-cell">{lb_display}</td>'
                )
            dns_rows.append(
                f"<tr{group_cls}>"
                f"{lb_cell}"
                f"<td><code>{safe_domain}</code></td>"
                f"<td>A / CNAME</td>"
                f"<td>{old_host}</td>"
                f"<td>{new_host}</td>"
                f'<td class="{status_cls}">{status_label}</td>'
                f"</tr>"
            )
            dns_rows.append(
                f"<tr>"
                f"<td><code>_acme-challenge.{safe_domain}</code></td>"
                f"<td>CNAME</td>"
                f"<td>{old_acme}</td>"
                f"<td>{new_acme}</td>"
                f'<td class="{status_cls}">{status_label}</td>'
                f"</tr>"
            )

    dns_changes_html = ""
    if dns_rows:
        dns_advice_block = (
            '<div class="dns-advice">'
            '<strong>&#9888; Let&rsquo;s Encrypt &amp; DNS challenge</strong>'
            '<p>When the HTTP LB is re-created, F5 XC issues a new ACME challenge with a '
            '<strong>new CNAME</strong>. If the old challenge record still resolves, '
            'the validation may stall and time out (there is no way to manually re-trigger it).</p>'
            '<p><strong>Before migration:</strong></p>'
            '<ol>'
            '<li><strong>Lower the TTL</strong> of all affected DNS records '
            '(A/CNAME for the domain <em>and</em> the <code>_acme-challenge</code> CNAME) '
            'to the minimum your provider allows (e.g.&nbsp;60&nbsp;s). '
            'Do this well in advance so caches expire before the move.</li>'
            '<li>Alternatively, <strong>delete the <code>_acme-challenge</code> CNAME</strong> '
            'before running the migration. This forces a clean lookup for the new challenge value.</li>'
            '</ol>'
            '<p><strong>After migration:</strong></p>'
            '<ol>'
            '<li>Update the <strong>A / CNAME record</strong> for each domain to point to the new CNAME shown below.</li>'
            '<li>Create or update the <strong><code>_acme-challenge</code> CNAME</strong> with the new value '
            '(visible in the F5 XC Console under the LB&rsquo;s DNS info).</li>'
            '<li>Once the certificate is issued, restore the original TTL.</li>'
            '</ol>'
            '</div>'
        )

        dns_table = (
            '<table class="dns-table">'
            '<thead><tr>'
            '<th>HTTP LB</th>'
            '<th>DNS Record</th>'
            '<th>Type</th>'
            '<th>Old Value</th>'
            '<th>New Value</th>'
            '<th>Action</th>'
            '</tr></thead>'
            '<tbody>'
            + "\n".join(dns_rows)
            + '</tbody></table>'
        )

        if dns_manual_count == 0 and dns_managed_count > 0:
            dns_changes_html = (
                '<h2 id="dns-changes">DNS Update Check</h2>'
                '<div class="dns-status-banner dns-auto-managed">'
                '<div class="dns-status-icon">&#127760;</div>'
                '<div class="dns-status-body">'
                '<div class="dns-status-headline">DNS Auto-Managed</div>'
                f'<div class="dns-status-detail">All {dns_lb_count} LB(s) use XC-managed DNS zones. '
                'Records will be created automatically &mdash; verify in the F5 XC Console after migration.</div>'
                '</div></div>'
                '<details class="dep-subsection">'
                '<summary>Managed Records (informational)</summary>'
                '<div class="dep-subsection-body">'
                + dns_table
                + '</div></details>'
            )
        elif dns_managed_count > 0 and dns_manual_count > 0:
            dns_changes_html = (
                '<h2 id="dns-changes">DNS Update Check</h2>'
                '<div class="dns-status-banner dns-action-needed">'
                '<div class="dns-status-icon">&#127760;</div>'
                '<div class="dns-status-body">'
                '<div class="dns-status-headline">DNS Updates Partially Required</div>'
                f'<div class="dns-status-detail">{dns_managed_count} of {dns_lb_count} LB(s) use '
                f'XC-managed DNS (no action needed). {dns_manual_count} require(s) manual DNS updates.</div>'
                '</div></div>'
                '<details class="dep-subsection" open>'
                '<summary>Affected Records &amp; Instructions</summary>'
                '<div class="dep-subsection-body">'
                + dns_advice_block
                + dns_table
                + '</div></details>'
            )
        else:
            dns_changes_html = (
                '<h2 id="dns-changes">DNS Update Check</h2>'
                '<div class="dns-status-banner dns-action-needed">'
                '<div class="dns-status-icon">&#127760;</div>'
                '<div class="dns-status-body">'
                '<div class="dns-status-headline">DNS Updates Required</div>'
                f'<div class="dns-status-detail">{dns_lb_count} load balancer(s) use '
                'Let&rsquo;s Encrypt auto-cert. CNAME and ACME challenge records '
                '<strong>must</strong> be updated before or after migration.</div>'
                '</div></div>'
                '<details class="dep-subsection" open>'
                '<summary>Affected Records &amp; Instructions</summary>'
                '<div class="dep-subsection-body">'
                + dns_advice_block
                + dns_table
                + '</div></details>'
            )
    elif results:
        dns_changes_html = (
            '<h2 id="dns-changes">DNS Update Check</h2>'
            '<div class="dns-status-banner dns-no-action">'
            '<div class="dns-status-icon">&#127760;</div>'
            '<div class="dns-status-body">'
            '<div class="dns-status-headline">No DNS Changes</div>'
            '<div class="dns-status-detail">None of the load balancers in this run '
            'use Let&rsquo;s Encrypt auto-cert. No CNAME or ACME challenge records '
            'need to be updated.</div>'
            '</div></div>'
        )

    if cname_only_rows:
        cname_summary_table = (
            '<details class="dep-subsection">'
            f'<summary>CNAME Changes &mdash; non-Let&rsquo;s Encrypt ({len(cname_only_rows)} LB(s))</summary>'
            '<div class="dep-subsection-body">'
            '<p class="meta">These load balancers do not use Let&rsquo;s Encrypt, '
            'so no ACME challenge records need updating. '
            'The host CNAME changed as part of the move &mdash; update external '
            'DNS records if they point to the old value.</p>'
            '<table><thead><tr>'
            '<th>HTTP LB</th><th>TLS</th><th>Old CNAME</th><th>New CNAME</th>'
            '</tr></thead><tbody>'
            + "\n".join(cname_only_rows)
            + '</tbody></table>'
            '</div></details>'
        )
        dns_changes_html += cname_summary_table

    return dns_changes_html, dns_managed_count, dns_manual_count


def _build_rework_section(
    rework_items: list[ManualReworkItem],
    target_ns: str,
) -> str:
    """Build the TLS Certificate Pre-Flight section."""
    if not rework_items:
        return ""

    matched_items = [i for i in rework_items if i.matched_cert_name]
    unmatched_items = [i for i in rework_items if not i.matched_cert_name]
    all_matched = len(unmatched_items) == 0

    rework_parts: list[str] = []

    if all_matched:
        rework_parts.append('<h2 id="cert-preflight">TLS Certificate Pre-Flight</h2>')
        rework_parts.append(
            '<div class="rework-status-banner rework-ok">'
            '<div class="rework-status-icon">&#128077;</div>'
            '<div class="rework-status-body">'
            '<div class="rework-status-headline">All Certificates Resolved</div>'
            f'<div class="rework-status-detail">{len(matched_items)} non-portable certificate(s) '
            'were automatically matched to existing certificates in the target or shared namespace. '
            'No manual action required.</div>'
            '</div></div>'
        )
    else:
        rework_parts.append('<h2 id="cert-preflight">TLS Certificate Pre-Flight</h2>')
        rework_parts.append(
            '<div class="rework-status-banner rework-blocked">'
            '<div class="rework-status-icon">&#128557;</div>'
            '<div class="rework-status-body">'
            '<div class="rework-status-headline">Manual Rework Needed</div>'
            f'<div class="rework-status-detail">{len(unmatched_items)} certificate(s) could not be matched '
            '&mdash; the affected load balancers are <strong>blocked</strong> until the certificates '
            'are available in the target or shared namespace.'
            f'{"  " + str(len(matched_items)) + " other certificate(s) were matched automatically." if matched_items else ""}'
            '</div>'
            '</div></div>'
        )

    if matched_items:
        _matched_open = "" if all_matched else " open"
        rework_parts.append(
            f'<details class="dep-subsection"{_matched_open}>'
            '<summary>Matched Certificates (auto-rewritten)</summary>'
            '<div class="dep-subsection-body">'
            '<p class="meta">These certificates were matched to an existing '
            'certificate in the target or shared namespace. The load balancer '
            'references were automatically rewritten.</p>'
            '<table><thead><tr>'
            '<th>Original Cert</th>'
            '<th>Matched To</th>'
            '<th>Namespace</th>'
            '<th>Domains (matched cert)</th>'
            '<th>Affected LBs</th>'
            '<th>Status</th>'
            '</tr></thead><tbody>'
        )
        for mi in matched_items:
            rework_parts.append(
                f'<tr>'
                f'<td>{esc(mi.cert_name)}</td>'
                f'<td>{esc(mi.matched_cert_name)}</td>'
                f'<td>{esc(mi.matched_cert_ns)}</td>'
                f'<td>{esc(", ".join(mi.matched_cert_domains[:5]))}'
                f'{"..." if len(mi.matched_cert_domains) > 5 else ""}</td>'
                f'<td>{esc(", ".join(mi.lb_names))}</td>'
                f'<td class="status-moved">AUTO-REWRITTEN</td>'
                f'</tr>'
            )
        rework_parts.append('</tbody></table></div></details>')

    if unmatched_items:
        rework_parts.append(
            '<details class="dep-subsection" open>'
            '<summary>Unmatched Certificates — Action Required</summary>'
            '<div class="dep-subsection-body">'
            '<p class="meta">No matching certificate was found in the target or '
            'shared namespace. The affected load balancers were <strong>blocked'
            '</strong> and not moved.</p>'
            '<table><thead><tr>'
            '<th>Certificate Name</th>'
            '<th>Required Domains</th>'
            '<th>Secret Type</th>'
            '<th>Affected LBs</th>'
            '<th>Status</th>'
            '</tr></thead><tbody>'
        )
        for mi in unmatched_items:
            rework_parts.append(
                f'<tr>'
                f'<td>{esc(mi.cert_name)}</td>'
                f'<td>{esc(", ".join(mi.cert_domains) if mi.cert_domains else "(unknown)")}</td>'
                f'<td>{esc(mi.secret_type)}</td>'
                f'<td>{esc(", ".join(mi.lb_names))}</td>'
                f'<td class="status-blocked">BLOCKED</td>'
                f'</tr>'
            )
        rework_parts.append('</tbody></table>')

        rework_parts.append(
            '<div class="rework-instructions">'
            '<h3>Steps to Resolve</h3>'
            '<ol>'
            '<li>Create the missing TLS certificate(s) in the <strong>target namespace</strong> '
            f'(<code>{esc(target_ns)}</code>) or in the <strong>shared</strong> namespace, '
            'covering the required domains listed above.</li>'
            '<li>Upload the private key and certificate chain.</li>'
            '<li>Re-run the mover &mdash; the pre-flight check will automatically '
            'detect the new certificate and rewrite the LB references.</li>'
            '</ol>'
            '<p>&#128214; <strong>Documentation:</strong> '
            '<a href="https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect" '
            'target="_blank" rel="noopener">'
            'F5 XC Multi-Cloud App Connect Docs</a> '
            '&mdash; see the TLS / Certificate management section for detailed '
            'instructions on creating certificates.</p>'
            '<p><em>Note: The original certificate remains in the source namespace '
            'and is not affected by the mover.</em></p>'
            '</div>'
        )
        rework_parts.append('</div></details>')

    # Collapsible: original cert configs
    cert_config_parts: list[str] = []
    for mi in rework_items:
        if mi.original_config_json:
            cert_config_parts.append(
                f'<details>'
                f'<summary class="backup-inner">{esc(mi.cert_name)}</summary>'
                f'<div class="json-block-wrapper">'
                f'<button class="copy-btn" onclick="copyJson(this)">Copy JSON</button>'
                f'<pre class="json-block">{esc(mi.original_config_json)}</pre>'
                f'</div></details>'
            )
    if cert_config_parts:
        rework_parts.append(
            '<details class="dep-subsection">'
            '<summary>Original Certificate Configurations (reference)</summary>'
            '<div class="dep-subsection-body">'
            + "\n".join(cert_config_parts)
            + '</div></details>'
        )

    return "\n".join(rework_parts)


def _build_dep_section(
    results: list[MoveResult],
    dry_run: bool,
    batch_graphs: list[BatchGraphData] | None,
) -> tuple[str, int, int]:
    """Build the Dependency Check section (table + graph)."""
    _FRIENDLY = FRIENDLY_TYPE_NAMES

    total_deps = sum(len(r.dependencies) for r in results)
    deps_moved = sum(
        1 for r in results for d in r.dependencies if d.status in ("moved", "dry-run")
    )
    deps_failed = sum(
        1 for r in results for d in r.dependencies if d.status == "failed"
    )
    deps_reverted = sum(
        1 for r in results for d in r.dependencies if d.status == "reverted"
    )
    deps_blocked = sum(
        1 for r in results for d in r.dependencies if d.status == "blocked"
    )

    # Dependency rows
    dep_rows_html: list[str] = []
    for r in results:
        for d in r.dependencies:
            dep_status_class = {
                "moved": "status-moved", "dry-run": "status-dryrun",
                "failed": "status-failed", "skipped": "status-skipped",
                "reverted": "status-reverted", "blocked": "status-blocked",
                "manual-rework": "status-manual-rework",
            }.get(d.status, "")
            friendly = _FRIENDLY.get(d.resource_type, d.resource_type)
            dep_error = (
                f'<span class="error" title="{esc(d.error)}">{esc(d.error)}</span>'
                if d.error else ""
            )
            dep_rename_badge = ""
            if d.new_name:
                dep_rename_badge = (
                    f' <span class="rename-badge" title="Renamed due to name conflict">'
                    f'&rarr; {esc(d.new_name)}</span>'
                )
            dep_rows_html.append(
                f"<tr>"
                f"<td>{esc(r.lb_name)}</td>"
                f"<td>{esc(friendly)}</td>"
                f"<td>{esc(d.name)}{dep_rename_badge}</td>"
                f"<td>{esc(r.src_namespace)}</td>"
                f"<td>{esc(r.dst_namespace)}</td>"
                f'<td class="{dep_status_class}">{esc(d.status.upper())}</td>'
                f"<td>{dep_error}</td>"
                f"</tr>"
            )

    # Dependent Objects sub-section
    dep_objects_html = ""
    if dep_rows_html:
        dep_objects_html = (
            f'<details class="dep-subsection">'
            f'<summary>Dependent Objects</summary>'
            f'<div class="dep-subsection-body">'
            f'<p class="meta">Objects moved alongside the load balancers (origin pools, health checks, TLS certificates, etc.). '
            f'<strong>Objects in the <code>system</code> and <code>shared</code> namespaces are '
            f'<span style="color:#dc3545;text-decoration:underline">never</span> moved.</strong></p>'
            f'<div class="summary">'
            f'  <div class="card card-moved"><div class="num">{deps_moved}</div><div class="label">{"Planned" if dry_run else "Moved"}</div></div>'
            f'  <div class="card card-failed"><div class="num">{deps_failed}</div><div class="label">Failed</div></div>'
            f'  <div class="card card-blocked"><div class="num">{deps_blocked}</div><div class="label">Blocked</div></div>'
            f'  <div class="card card-reverted"><div class="num">{deps_reverted}</div><div class="label">Reverted</div></div>'
            f'  <div class="card"><div class="num">{total_deps}</div><div class="label">Total</div></div>'
            f'</div>'
            f'<table>'
            f'<thead>'
            f'<tr>'
            f'  <th>Parent LB</th>'
            f'  <th>Object Type</th>'
            f'  <th>Object Name</th>'
            f'  <th>Namespace (old)</th>'
            f'  <th>Namespace (new)</th>'
            f'  <th>Status</th>'
            f'  <th>Error</th>'
            f'</tr>'
            f'</thead>'
            f'<tbody>'
            f'{"".join(dep_rows_html)}'
            f'</tbody>'
            f'</table>'
            f'</div></details>'
        )

    # Dependency Graph sub-section
    dep_graph_html = ""
    if batch_graphs:
        graph_blocks: list[str] = []
        for bg in batch_graphs:
            bg_total_deps = sum(len(v) for v in bg.lb_to_deps.values())
            bg_total_subdeps = sum(len(v) for v in bg.dep_children.values())
            if bg_total_deps == 0 and bg_total_subdeps == 0:
                continue
            svg = render_batch_svg(bg)
            label = ", ".join(bg.lb_names)
            if len(bg.lb_names) > 1:
                tag = f"Batch {bg.batch_index} (atomic)"
            elif bg.shared_deps:
                tag = f"Batch {bg.batch_index} (shared deps)"
            else:
                tag = f"Batch {bg.batch_index}"
            graph_blocks.append(
                f'<details>'
                f'<summary>{esc(tag)}: {esc(label)}</summary>'
                f'<div style="overflow-x:auto; padding: 0.5rem 0;">{svg}</div>'
                f'</details>'
            )
        if graph_blocks:
            dep_graph_html = (
                '<details class="dep-subsection">'
                '<summary>Dependency Graph</summary>'
                '<div class="dep-subsection-body">'
                '<p class="meta">Visual dependency tree per batch. '
                'Simple chains show the linear dependency flow for independent LBs. '
                '<span style="color:#dc3545;font-weight:600">Red</span> borders indicate '
                'objects referenced by external objects not in the move list (cannot be moved). '
                '<span style="color:#e67e22;font-weight:600">Orange</span> borders indicate '
                'shared dependencies (used by multiple LBs in the same batch). '
                'Click to expand individual batches.</p>'
                + "\n".join(graph_blocks)
                + '</div></details>'
            )

    # Combined Dependencies section
    has_dep_problems = deps_failed > 0 or deps_blocked > 0 or deps_reverted > 0
    dep_section = ""
    if dep_objects_html or dep_graph_html:
        if has_dep_problems:
            problem_parts: list[str] = []
            if deps_failed:
                problem_parts.append(f"{deps_failed} failed")
            if deps_blocked:
                problem_parts.append(f"{deps_blocked} blocked")
            if deps_reverted:
                problem_parts.append(f"{deps_reverted} reverted")

            dep_issue_items: list[str] = []
            for r in results:
                for d in r.dependencies:
                    if d.status in ("blocked", "failed", "reverted", "manual-rework"):
                        friendly_type = _FRIENDLY.get(d.resource_type, d.resource_type)
                        dep_display_name = d.new_name if d.new_name else d.name
                        if d.status == "failed":
                            icon = "&#10060;"
                        elif d.status == "manual-rework":
                            icon = "&#128295;"
                        elif d.status == "reverted":
                            icon = "&#8634;"
                        else:
                            icon = "&#128683;"
                        short_err = d.error
                        if short_err and len(short_err) > 120:
                            short_err = short_err[:117] + "..."
                        dep_issue_items.append(
                            f'<li>{icon} <strong>{esc(friendly_type)}: {esc(dep_display_name)}</strong>'
                            f' <span style="opacity:0.7">({esc(d.status.upper())})</span>'
                            + (f' &mdash; {esc(short_err)}' if short_err else '')
                            + '</li>'
                        )
            dep_issues_html = ""
            if dep_issue_items:
                dep_issues_html = (
                    '<ul class="dep-issue-list">'
                    + "\n".join(dep_issue_items)
                    + '</ul>'
                )

            dep_banner = (
                '<div class="dep-status-banner dep-issues">'
                '<div class="dep-status-icon">&#128279;</div>'
                '<div class="dep-status-body">'
                '<div class="dep-status-headline">Dependency Issues</div>'
                f'<div class="dep-status-detail">{total_deps} dependent object(s) discovered &mdash; '
                f'{", ".join(problem_parts)}. '
                'Review the table below for details.</div>'
                + dep_issues_html
                + '</div></div>'
            )
        elif total_deps > 0:
            dep_banner = (
                '<div class="dep-status-banner dep-ok">'
                '<div class="dep-status-icon">&#128279;</div>'
                '<div class="dep-status-body">'
                '<div class="dep-status-headline">All Dependencies Resolved</div>'
                f'<div class="dep-status-detail">{total_deps} dependent object(s) '
                f'{"will be" if dry_run else "were"} '
                f'{"migrated" if dry_run else "moved"} alongside the load balancers. '
                'No issues detected.</div>'
                '</div></div>'
            )
        else:
            dep_banner = (
                '<div class="dep-status-banner dep-ok">'
                '<div class="dep-status-icon">&#128279;</div>'
                '<div class="dep-status-body">'
                '<div class="dep-status-headline">No Dependencies</div>'
                '<div class="dep-status-detail">No dependent objects (origin pools, '
                'health checks, certificates, etc.) were found for the selected '
                'load balancers.</div>'
                '</div></div>'
            )
        dep_section = (
            '<h2 id="dep-check">Dependency Check</h2>'
            + dep_banner
            + dep_objects_html
            + dep_graph_html
        )
    elif results:
        dep_section = (
            '<h2 id="dep-check">Dependency Check</h2>'
            '<div class="dep-status-banner dep-ok">'
            '<div class="dep-status-icon">&#128279;</div>'
            '<div class="dep-status-body">'
            '<div class="dep-status-headline">No Dependencies</div>'
            '<div class="dep-status-detail">No dependent objects (origin pools, '
            'health checks, certificates, etc.) were found for the selected '
            'load balancers.</div>'
            '</div></div>'
        )

    return dep_section, deps_failed, deps_blocked


def _build_config_sections(results: list[MoveResult]) -> str:
    """Build the Planned Configurations section (dry-run)."""
    _FRIENDLY = FRIENDLY_TYPE_NAMES

    configs_with_data = [
        (idx, r) for idx, r in enumerate(results)
        if r.planned_config_json or any(d.planned_config_json for d in r.dependencies)
    ]
    if not configs_with_data:
        return ""

    rendered_dep_planned: dict[tuple[str, str], str] = {}
    config_blocks: list[str] = []

    for idx, r in configs_with_data:
        inner_parts: list[str] = []

        if r.planned_config_json:
            anchor = f"config-{idx}"
            lb_label = "HTTP LB Config"
            if r.new_lb_name:
                lb_label += f" (as {esc(r.new_lb_name)})"
            inner_parts.append(
                f'<details id="{anchor}">'
                f'<summary class="backup-inner">{lb_label}</summary>'
                f'<div class="json-block-wrapper">'
                f'<button class="copy-btn" onclick="copyJson(this)">Copy JSON</button>'
                f'<pre class="json-block">{esc(r.planned_config_json)}</pre>'
                f'</div></details>'
            )

        for d in r.dependencies:
            dep_key = (d.resource_type, d.name)
            friendly = _FRIENDLY.get(d.resource_type, d.resource_type)

            if d.planned_config_json and dep_key not in rendered_dep_planned:
                dep_anchor = f"config-dep-{d.resource_type}-{d.name}".replace(" ", "-")
                rendered_dep_planned[dep_key] = dep_anchor
                dep_label = f"{friendly}: {d.name}"
                if d.new_name:
                    dep_label += f" (as {esc(d.new_name)})"
                inner_parts.append(
                    f'<details id="{esc(dep_anchor)}">'
                    f'<summary class="backup-inner backup-dep">{esc(dep_label)}</summary>'
                    f'<div class="json-block-wrapper">'
                    f'<button class="copy-btn" onclick="copyJson(this)">Copy JSON</button>'
                    f'<pre class="json-block">{esc(d.planned_config_json)}</pre>'
                    f'</div></details>'
                )
            elif dep_key in rendered_dep_planned:
                ref_anchor = rendered_dep_planned[dep_key]
                first_lb = ""
                for prev_idx, prev_r in configs_with_data:
                    if prev_idx >= idx:
                        break
                    for prev_d in prev_r.dependencies:
                        if (prev_d.resource_type, prev_d.name) == dep_key and prev_d.planned_config_json:
                            first_lb = prev_r.lb_name
                            break
                    if first_lb:
                        break
                ref_note = (
                    f' (shared \u2014 see <a href="#{esc(ref_anchor)}">{esc(first_lb)}</a>)'
                    if first_lb
                    else " (shared \u2014 see above)"
                )
                inner_parts.append(
                    f'<div class="backup-xref">'
                    f'{esc(friendly)}: {esc(d.name)}{ref_note}'
                    f'</div>'
                )

        if inner_parts:
            dep_count = sum(
                1 for d in r.dependencies
                if d.planned_config_json or (d.resource_type, d.name) in rendered_dep_planned
            )
            dep_label = f" + {dep_count} dep(s)" if dep_count else ""
            config_blocks.append(
                f'<details class="backup-group">'
                f'<summary>{esc(r.lb_name)}{dep_label} '
                f'<span class="meta">({esc(r.src_namespace)} &rarr; {esc(r.dst_namespace)})</span></summary>'
                f'<div class="backup-group-inner">'
                + "\n".join(inner_parts)
                + f'</div></details>'
            )

    if not config_blocks:
        return ""

    return (
        "<h2>Planned Configurations</h2>"
        '<p class="meta">The JSON bodies that would be sent to the XC API to create each object '
        "in the target namespace. Grouped by HTTP LB with dependencies nested below. "
        "Shared dependencies appear once with cross-references from other LBs. "
        "Use the <strong>Copy JSON</strong> button to copy any config to your clipboard for manual import. "
        "Click to expand.</p>"
        + "\n".join(config_blocks)
    )


def _build_backup_sections(results: list[MoveResult]) -> str:
    """Build the Original Configuration Backups section."""
    _FRIENDLY = FRIENDLY_TYPE_NAMES

    backups_with_data = [
        (idx, r) for idx, r in enumerate(results)
        if r.backup_json or any(d.backup_json for d in r.dependencies)
    ]
    if not backups_with_data:
        return ""

    rendered_dep_backups: dict[tuple[str, str], str] = {}
    backup_blocks: list[str] = []

    for idx, r in backups_with_data:
        inner_parts: list[str] = []

        if r.backup_json:
            inner_parts.append(
                f'<details>'
                f'<summary class="backup-inner">HTTP LB Config</summary>'
                f'<div class="json-block-wrapper">'
                f'<button class="copy-btn" onclick="copyJson(this)">Copy JSON</button>'
                f'<pre class="json-block">{esc(r.backup_json)}</pre>'
                f'</div></details>'
            )

        for d in r.dependencies:
            dep_key = (d.resource_type, d.name)
            friendly = _FRIENDLY.get(d.resource_type, d.resource_type)

            if d.backup_json and dep_key not in rendered_dep_backups:
                dep_anchor = f"backup-dep-{d.resource_type}-{d.name}".replace(" ", "-")
                rendered_dep_backups[dep_key] = dep_anchor
                inner_parts.append(
                    f'<details id="{esc(dep_anchor)}">'
                    f'<summary class="backup-inner backup-dep">'
                    f'{esc(friendly)}: {esc(d.name)}</summary>'
                    f'<div class="json-block-wrapper">'
                    f'<button class="copy-btn" onclick="copyJson(this)">Copy JSON</button>'
                    f'<pre class="json-block">{esc(d.backup_json)}</pre>'
                    f'</div></details>'
                )
            elif dep_key in rendered_dep_backups:
                ref_anchor = rendered_dep_backups[dep_key]
                first_lb = ""
                for prev_idx, prev_r in backups_with_data:
                    if prev_idx >= idx:
                        break
                    for prev_d in prev_r.dependencies:
                        if (prev_d.resource_type, prev_d.name) == dep_key and prev_d.backup_json:
                            first_lb = prev_r.lb_name
                            break
                    if first_lb:
                        break
                ref_note = (
                    f' (shared \u2014 see <a href="#{esc(ref_anchor)}">{esc(first_lb)}</a>)'
                    if first_lb
                    else " (shared \u2014 see above)"
                )
                inner_parts.append(
                    f'<div class="backup-xref">'
                    f'{esc(friendly)}: {esc(d.name)}{ref_note}'
                    f'</div>'
                )

        if inner_parts:
            anchor = f"backup-{idx}"
            dep_count = sum(
                1 for d in r.dependencies
                if d.backup_json or (d.resource_type, d.name) in rendered_dep_backups
            )
            dep_label = f" + {dep_count} dep(s)" if dep_count else ""
            backup_blocks.append(
                f'<details id="{anchor}" class="backup-group">'
                f'<summary>{esc(r.lb_name)}{dep_label} '
                f'<span class="meta">({esc(r.src_namespace)})</span></summary>'
                f'<div class="backup-group-inner">'
                + "\n".join(inner_parts)
                + f'</div></details>'
            )

    if not backup_blocks:
        return ""

    return (
        "<h2>Original Configuration Backups</h2>"
        '<p class="meta">Full GET responses captured <strong>before</strong> any changes were made. '
        "Grouped by HTTP LB with dependencies nested below. "
        "Shared dependencies appear once with cross-references from other LBs. "
        "Click to expand.</p>"
        + "\n".join(backup_blocks)
    )


def _build_health_banner(
    results: list[MoveResult],
    dry_run: bool,
    rework_items: list[ManualReworkItem],
    dns_managed_count: int,
    dns_manual_count: int,
    deps_failed: int,
    deps_blocked: int,
) -> str:
    """Build the traffic-light health banner."""
    moved = sum(1 for r in results if r.status == "moved")
    dryrun_count = sum(1 for r in results if r.status == "dry-run")
    failed = sum(1 for r in results if r.status == "failed")
    skipped = sum(1 for r in results if r.status == "skipped")
    reverted = sum(1 for r in results if r.status == "reverted")
    blocked = sum(1 for r in results if r.status == "blocked")
    rework_total = len(rework_items)

    has_hard_failure = any(r.status == "failed" for r in results) or any(
        r.status == "reverted" and "ROLLBACK FAILED" in (r.error or "")
        for r in results
    )
    has_reverted = any(r.status == "reverted" for r in results)
    has_unmatched_certs = any(not i.matched_cert_name for i in rework_items)
    has_matched_certs_only = len(rework_items) > 0 and not has_unmatched_certs
    has_skipped_or_blocked = any(r.status in ("skipped", "blocked") for r in results)
    has_dep_problems = deps_failed > 0 or deps_blocked > 0
    has_dns_changes = dns_manual_count > 0
    has_dns_managed = dns_managed_count > 0

    if has_hard_failure or has_unmatched_certs or has_dep_problems:
        health_level = "red"
    elif has_dns_changes or has_matched_certs_only or has_reverted or has_skipped_or_blocked:
        health_level = "yellow"
    else:
        health_level = "green"

    health_light_symbols = {
        "green": "&#10004;", "yellow": "&#9888;", "red": "&#10008;",
    }
    health_headlines_run = {
        "green": "Migration Successful",
        "yellow": "Completed \u2014 Action Required",
        "red": "Migration Blocked",
    }
    health_headlines_dry = {
        "green": "Ready to Migrate",
        "yellow": "Ready \u2014 External Action Required",
        "red": "Migration Blocked",
    }

    _health_subtext_parts: list[str] = []
    if has_hard_failure:
        _health_subtext_parts.append(
            "One or more migrations failed. Check rollback status and error details below."
            if not dry_run else
            "Critical issues were found during the dry run."
        )
    if has_unmatched_certs:
        _health_subtext_parts.append(
            "TLS certificates with non-portable private keys could not be matched \u2014 affected LBs are blocked."
        )
    if has_dep_problems:
        _health_subtext_parts.append(
            f"Dependency issues: {deps_failed} failed, {deps_blocked} blocked."
            if deps_failed and deps_blocked else
            f"Dependency issues: {deps_failed} failed." if deps_failed else
            f"Dependency issues: {deps_blocked} blocked."
        )
    if has_dns_changes:
        _health_subtext_parts.append(
            f"{dns_manual_count} LB(s) require DNS record updates (CNAME / ACME challenge)."
        )
    if has_dns_managed and not has_dns_changes:
        _health_subtext_parts.append(
            f"{dns_managed_count} LB(s) use XC-managed DNS \u2014 records will be updated automatically."
        )
    elif has_dns_managed and has_dns_changes:
        _health_subtext_parts.append(
            f"{dns_managed_count} LB(s) use XC-managed DNS (no action needed)."
        )
    if has_matched_certs_only:
        _health_subtext_parts.append(
            f"{len(rework_items)} certificate(s) auto-rewritten \u2014 verify after migration."
        )
    if has_reverted:
        _health_subtext_parts.append("Some load balancers were reverted to the source namespace.")
    if has_skipped_or_blocked and not has_unmatched_certs:
        _health_subtext_parts.append("Some load balancers were skipped or blocked.")
    if not _health_subtext_parts:
        if dry_run:
            _health_subtext_parts.append("All pre-flight checks passed. No issues detected.")
        else:
            _health_subtext_parts.append("All load balancers were moved successfully. No issues detected.")
    health_subtext = " ".join(_health_subtext_parts)
    health_headlines = health_headlines_dry if dry_run else health_headlines_run

    # Stat pills
    stat_pills: list[str] = []
    if dry_run:
        if dryrun_count:
            stat_pills.append(f'<span class="health-pill">&#128230; {dryrun_count} Planned</span>')
    else:
        if moved:
            stat_pills.append(f'<span class="health-pill">&#9989; {moved} Moved</span>')
    if failed:
        stat_pills.append(f'<span class="health-pill">&#10060; {failed} Failed</span>')
    if blocked:
        stat_pills.append(f'<span class="health-pill">&#128683; {blocked} Blocked</span>')
    if reverted:
        stat_pills.append(f'<span class="health-pill">&#8634; {reverted} Reverted</span>')
    if skipped:
        stat_pills.append(f'<span class="health-pill">&#9723; {skipped} Skipped</span>')
    if rework_total:
        stat_pills.append(f'<span class="health-pill">&#128295; {rework_total} Cert Rework</span>')

    # Top findings
    findings_html = ""
    if health_level != "green":
        finding_items: list[str] = []
        _lb_status_icons = {
            "failed": "&#10060;", "reverted": "&#8634;",
            "blocked": "&#128683;", "skipped": "&#9898;",
        }
        problem_results = [r for r in results if r.status in ("failed", "reverted", "blocked")]
        for pr in problem_results:
            icon = _lb_status_icons.get(pr.status, "&#8226;")
            finding_items.append(
                f'<li><span class="hf-icon">{icon}</span>'
                f'<strong>{esc(pr.lb_name)}</strong> '
                f'<span style="opacity:0.7">({pr.status.upper()})</span></li>'
            )
        _max_findings = 10
        if len(finding_items) > _max_findings:
            shown = finding_items[:_max_findings]
            remaining = len(finding_items) - _max_findings
            shown.append(
                f'<li style="opacity:0.6"><span class="hf-icon">&#8230;</span>'
                f'+{remaining} more</li>'
            )
            finding_items = shown
        if finding_items:
            findings_html = (
                '<ul class="health-findings">'
                + "\n".join(finding_items)
                + '</ul>'
            )

    health_banner_html = (
        f'<div class="health-banner health-{health_level}">'
        f'<div class="health-light">{health_light_symbols[health_level]}</div>'
        f'<div class="health-body">'
        f'<div class="health-headline">{esc(health_headlines[health_level])}</div>'
        f'<div style="font-size:0.88rem;margin-bottom:0.4rem;opacity:0.85;">'
        f'{health_subtext}</div>'
    )
    if stat_pills:
        health_banner_html += (
            '<div class="health-stats">'
            + " ".join(stat_pills)
            + '</div>'
        )
    if findings_html:
        health_banner_html += findings_html
    health_banner_html += '</div></div>'

    return health_banner_html


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def generate_mover_report(
    results: list[MoveResult],
    tenant: str,
    target_ns: str,
    report_path: str,
    dry_run: bool = False,
    batch_graphs: list[BatchGraphData] | None = None,
    manual_rework_items: list[ManualReworkItem] | None = None,
) -> None:
    """Write the mover HTML report to *report_path*."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rework_items = manual_rework_items or []

    moved = sum(1 for r in results if r.status == "moved")
    dryrun_count = sum(1 for r in results if r.status == "dry-run")
    failed = sum(1 for r in results if r.status == "failed")
    skipped = sum(1 for r in results if r.status == "skipped")
    reverted = sum(1 for r in results if r.status == "reverted")
    blocked = sum(1 for r in results if r.status == "blocked")

    has_moved_or_reverted = any(r.status in ("moved", "reverted") for r in results)

    # --- CNAME / ACME warning banner ---
    warning_banner = ""
    if has_moved_or_reverted:
        warning_banner = """\
<div class="warning-banner">
  <strong>&#9888; Important — CNAME &amp; ACME / Let's Encrypt Warning</strong>
  <p>When a load balancer is moved to a new namespace (or reverted back), F5 XC assigns a
  <strong>new CNAME (host_name)</strong>. If you are using <strong>Let's Encrypt (auto-cert)</strong>,
  the ACME challenge domain will also change.</p>
  <ul>
    <li>Update your DNS records to point to the <strong>new CNAME</strong> — see the
        <a href="#dns-changes">DNS Changes</a> section below for a full list.</li>
    <li>If the LB was <strong>reverted</strong> after a failed move, the CNAME in the source namespace
        may differ from the original — check the value carefully.</li>
    <li>Let's Encrypt certificates will be re-issued automatically once DNS propagates,
        but there may be a brief period without a valid certificate.</li>
  </ul>
</div>
"""

    # --- Build sub-sections ---
    lb_rows_html = _build_lb_rows(results, dry_run)
    dns_changes_html, dns_managed_count, dns_manual_count = _build_dns_section(results)
    rework_section = _build_rework_section(rework_items, target_ns)
    dep_section, deps_failed, deps_blocked = _build_dep_section(results, dry_run, batch_graphs)
    config_sections_html = _build_config_sections(results)
    backup_sections_html = _build_backup_sections(results)

    # --- Summary cards ---
    rework_matched = sum(1 for i in rework_items if i.matched_cert_name)
    rework_unmatched = sum(1 for i in rework_items if not i.matched_cert_name)
    rework_total = len(rework_items)
    rework_card = ""
    if rework_total:
        rework_card = (
            f'  <div class="card card-rework"><div class="num">{rework_total}</div>'
            f'<div class="label">Cert Rework</div></div>\n'
        )

    if dry_run:
        summary_cards = f"""\
  <div class="card card-dryrun"><div class="num">{dryrun_count}</div><div class="label">Planned</div></div>
  <div class="card card-blocked"><div class="num">{blocked}</div><div class="label">Blocked</div></div>
  <div class="card card-skipped"><div class="num">{skipped}</div><div class="label">Skipped</div></div>
{rework_card}  <div class="card"><div class="num">{len(results)}</div><div class="label">Total</div></div>
"""
    else:
        summary_cards = f"""\
  <div class="card card-moved"><div class="num">{moved}</div><div class="label">Moved</div></div>
  <div class="card card-failed"><div class="num">{failed}</div><div class="label">Failed</div></div>
  <div class="card card-blocked"><div class="num">{blocked}</div><div class="label">Blocked</div></div>
  <div class="card card-reverted"><div class="num">{reverted}</div><div class="label">Reverted</div></div>
  <div class="card card-skipped"><div class="num">{skipped}</div><div class="label">Skipped</div></div>
{rework_card}  <div class="card"><div class="num">{len(results)}</div><div class="label">Total</div></div>
"""

    # --- Health banner ---
    health_banner_html = _build_health_banner(
        results, dry_run, rework_items,
        dns_managed_count, dns_manual_count,
        deps_failed, deps_blocked,
    )

    # --- Assemble body ---
    body_html = f"""\
{health_banner_html}

{warning_banner}

<h2>Load Balancers</h2>
<div class="summary">
{summary_cards}
</div>

<div class="meta" style="margin:0.8rem 0 0.5rem; display:flex; flex-wrap:wrap; align-items:center; gap:0.6rem 1.2rem;"><strong>Details:</strong> <span style="white-space:nowrap;"><span class="lb-chip lb-chip-ok">&#10004;</span> no action needed</span> <span style="white-space:nowrap;"><span class="lb-chip lb-chip-note">&#128204;</span> informational</span> <span style="white-space:nowrap;"><span class="lb-chip lb-chip-rework">&#128295;</span> manual action required</span> <span style="white-space:nowrap;"><span class="lb-chip lb-chip-blocked">&#128683;</span> blocked</span></div>

<table>
<thead>
<tr>
  <th>HTTP LB Name</th>
  <th>Namespace (old)</th>
  <th>Namespace (new)</th>
  <th>TLS</th>
  <th>Status</th>
  <th>Details</th>
</tr>
</thead>
<tbody>
{lb_rows_html}
</tbody>
</table>

{dns_changes_html}

{rework_section}

{dep_section}

{config_sections_html}

{backup_sections_html}
"""

    title = "Pre-Migration Report" if dry_run else "LB Mover Report"
    meta_line = (
        f'Tenant: <strong>{esc(tenant)}</strong> &nbsp;|&nbsp; '
        f'Target namespace: <strong>{esc(target_ns)}</strong> &nbsp;|&nbsp; '
        f'{esc(timestamp)}'
    )

    html = render_html_page(
        title=f"{title} &mdash; {esc(tenant)}",
        meta_line=meta_line,
        body_html=body_html,
        extra_css=_MOVER_CSS,
    )

    with open(report_path, "w") as f:
        f.write(html)
