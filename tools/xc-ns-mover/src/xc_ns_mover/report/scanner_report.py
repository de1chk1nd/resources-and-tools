"""
Scanner HTML report generator.

Produces a visual HTML report of namespace scan results including
summary cards, namespace bar charts, an LB table, and a copy-paste
CSV block.
"""

from __future__ import annotations

from collections import Counter

from .base import esc, render_html_page


# ------------------------------------------------------------------
# Scanner-specific CSS
# ------------------------------------------------------------------

_SCANNER_CSS = """\
  .card-primary { border-left: 4px solid #0d6efd !important; }
  .card-primary .num { color: #0d6efd; }
  .card-ns .num { color: #6f42c1; }
  .card-ns-active .num { color: #198754; }
  .card-ns-empty .num { color: #6c757d; }
  .card-type .num { color: #0dcaf0; }

  /* --- Bar chart --- */
  .bar-chart { background: #fff; border: 1px solid #dee2e6; border-radius: 8px;
                padding: 1.25rem; margin-bottom: 2rem;
                box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
  .bar-row { display: flex; align-items: center; gap: 0.75rem;
              padding: 0.3rem 0; }
  .bar-label { width: 200px; flex-shrink: 0; font-size: 0.85rem; font-weight: 500;
                text-align: right; overflow: hidden; text-overflow: ellipsis;
                white-space: nowrap; color: #333; }
  .bar-track { flex: 1; height: 22px; background: #e9ecef; border-radius: 4px;
                overflow: hidden; }
  .bar-fill { height: 100%; background: linear-gradient(90deg, #0d6efd, #6ea8fe);
                border-radius: 4px; min-width: 4px;
                transition: width 0.3s ease; }
  .bar-count { width: 36px; flex-shrink: 0; font-size: 0.85rem; font-weight: 700;
                color: #0d6efd; }

  .td-lb-name { font-weight: 500; }
  .ns-group-row td { background: #e9ecef; padding: 0.4rem 0.75rem;
                      font-size: 0.8rem; border-top: 2px solid #dee2e6; }
  .ns-group-count { margin-left: 0.75rem; color: #6c757d; font-weight: 400;
                     font-size: 0.78rem; }
  .type-badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 10px;
                 font-size: 0.75rem; font-weight: 600; }
  .badge-http { background: #e0f2f1; color: #00695c; border: 1px solid #80cbc4; }
  .badge-https { background: #e8eaf6; color: #283593; border: 1px solid #9fa8da; }

  /* --- CSV copy block --- */
  .csv-section { margin-bottom: 2rem; }
  .csv-header { display: flex; align-items: center; justify-content: space-between;
                 background: #343a40; color: #fff; padding: 0.5rem 0.75rem;
                 border-radius: 6px 6px 0 0; font-size: 0.85rem; }
  .csv-header .csv-title { font-weight: 600; }
  .csv-header .csv-hint { font-size: 0.78rem; opacity: 0.7; }
  .csv-block { background: #1e1e1e; color: #d4d4d4; padding: 1rem;
                border-radius: 0 0 6px 6px; overflow-x: auto; font-size: 0.8rem;
                line-height: 1.5; margin: 0; white-space: pre;
                font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
                border: 1px solid #495057; border-top: none;
                max-height: 400px; overflow-y: auto; }

  /* --- Scan configuration --- */
  .cfg-details { margin-bottom: 1.5rem; }
  .cfg-details > summary { cursor: pointer; padding: 0.6rem 1rem; background: #fff;
                            border: 1px solid #dee2e6; border-radius: 8px;
                            font-weight: 600; font-size: 0.9rem; color: #333;
                            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
                            list-style: none; }
  .cfg-details > summary::-webkit-details-marker { display: none; }
  .cfg-details > summary::before { content: "\\25B6"; margin-right: 0.5rem;
                                    font-size: 0.7rem; display: inline-block;
                                    transition: transform 0.15s; }
  .cfg-details[open] > summary::before { transform: rotate(90deg); }
  .cfg-details > summary:hover { background: #f0f4ff; }
  .cfg-details[open] > summary { border-radius: 8px 8px 0 0;
                                  border-bottom: 1px solid #e9ecef; }
  .cfg-body { background: #fff; border: 1px solid #dee2e6; border-top: none;
               border-radius: 0 0 8px 8px; padding: 1rem 1.25rem;
               box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
  .cfg-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
               gap: 0.75rem 1.5rem; margin-bottom: 0.75rem; }
  .cfg-item { display: flex; flex-direction: column; gap: 0.1rem; }
  .cfg-item .cfg-label { font-size: 0.72rem; text-transform: uppercase;
                          letter-spacing: 0.04em; color: #888; font-weight: 600; }
  .cfg-item .cfg-value { font-size: 0.9rem; font-weight: 500; color: #1a1a1a; }
  .cfg-desc { font-size: 0.85rem; color: #555; margin-bottom: 0.5rem; }
  .cfg-row { margin-bottom: 0.4rem; }
  .cfg-row > .cfg-label { font-size: 0.78rem; font-weight: 600; color: #555;
                           margin-right: 0.4rem; }
  .cfg-tag { display: inline-block; padding: 0.12rem 0.5rem; border-radius: 10px;
              font-size: 0.75rem; font-weight: 600; margin: 0.1rem 0.15rem; }
  .cfg-tag-include { background: #d4edda; color: #155724; border: 1px solid #b7dfb9; }
  .cfg-tag-exclude { background: #f8d7da; color: #721c24; border: 1px solid #f1aeb5; }
"""


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def generate_scanner_report(
    report_path: str,
    tenant_name: str,
    scan_time: str,
    ns_count: int,
    ns_scanned: list[str],
    rows: list[tuple[str, str, str]],
    total_ns_on_tenant: int,
    ns_include: list[str],
    ns_exclude: list[str],
) -> None:
    """Generate a visual HTML report of the scanner results."""

    lb_count = len(rows)

    # --- Build CSV text for the copy-paste block ---
    csv_lines = ["namespace,lb_name"]
    for ns, lb_name, _ in sorted(rows):
        csv_lines.append(f"{ns},{lb_name}")
    csv_text = "\n".join(csv_lines)

    # --- Stats for the summary cards ---
    ns_with_lbs: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    for ns, _, lb_type in rows:
        ns_with_lbs[ns] += 1
        type_counts[lb_type] += 1

    ns_with_lbs_count = len(ns_with_lbs)
    ns_empty_count = ns_count - ns_with_lbs_count

    # --- Scan configuration section ---
    has_include = len(ns_include) > 0
    has_exclude = len(ns_exclude) > 0

    if has_include and has_exclude:
        filter_mode = "Include + Exclude"
        filter_desc = (
            f"Started from <strong>{len(ns_include)}</strong> included namespace(s), "
            f"then removed <strong>{len(ns_exclude)}</strong> excluded namespace(s)."
        )
    elif has_include:
        filter_mode = "Include list"
        filter_desc = (
            f"Only the <strong>{len(ns_include)}</strong> listed namespace(s) were scanned."
        )
    elif has_exclude:
        filter_mode = "Exclude list"
        filter_desc = (
            f"All namespaces were scanned <strong>except</strong> "
            f"<strong>{len(ns_exclude)}</strong> excluded namespace(s)."
        )
    else:
        filter_mode = "No filter"
        filter_desc = "All namespaces accessible by the API token were scanned."

    include_tags = ""
    if ns_include:
        tags = " ".join(
            f'<span class="cfg-tag cfg-tag-include">{esc(n)}</span>'
            for n in sorted(ns_include)
        )
        include_tags = f'<div class="cfg-row"><span class="cfg-label">Include:</span> {tags}</div>'

    exclude_tags = ""
    if ns_exclude:
        tags = " ".join(
            f'<span class="cfg-tag cfg-tag-exclude">{esc(n)}</span>'
            for n in sorted(ns_exclude)
        )
        exclude_tags = f'<div class="cfg-row"><span class="cfg-label">Exclude:</span> {tags}</div>'

    config_section = f"""\
<details class="cfg-details" open>
<summary>Scan Configuration</summary>
<div class="cfg-body">
  <div class="cfg-grid">
    <div class="cfg-item">
      <span class="cfg-label">Tenant</span>
      <span class="cfg-value">{esc(tenant_name)}</span>
    </div>
    <div class="cfg-item">
      <span class="cfg-label">Namespaces on tenant</span>
      <span class="cfg-value">{total_ns_on_tenant}</span>
    </div>
    <div class="cfg-item">
      <span class="cfg-label">Namespaces scanned</span>
      <span class="cfg-value">{ns_count}</span>
    </div>
    <div class="cfg-item">
      <span class="cfg-label">Filter mode</span>
      <span class="cfg-value">{filter_mode}</span>
    </div>
  </div>
  <div class="cfg-desc">{filter_desc}</div>
  {include_tags}
  {exclude_tags}
</div>
</details>
"""

    # --- Summary cards ---
    summary_cards = (
        '<div class="summary">'
        f'<div class="card card-primary"><div class="num">{lb_count}</div>'
        f'<div class="label">Load Balancers</div></div>'
        f'<div class="card card-ns"><div class="num">{ns_count}</div>'
        f'<div class="label">Namespaces Scanned</div></div>'
        f'<div class="card card-ns-active"><div class="num">{ns_with_lbs_count}</div>'
        f'<div class="label">With LBs</div></div>'
        f'<div class="card card-ns-empty"><div class="num">{ns_empty_count}</div>'
        f'<div class="label">Empty</div></div>'
    )
    for lt, cnt in sorted(type_counts.items()):
        friendly = lt.replace("_", " ").title()
        summary_cards += (
            f'<div class="card card-type"><div class="num">{cnt}</div>'
            f'<div class="label">{esc(friendly)}</div></div>'
        )
    summary_cards += '</div>'

    # --- Namespace breakdown chart (horizontal bars) ---
    max_lb_in_ns = max(ns_with_lbs.values()) if ns_with_lbs else 1
    ns_bar_rows = ""
    for ns_name in sorted(ns_with_lbs, key=lambda n: (-ns_with_lbs[n], n)):
        count = ns_with_lbs[ns_name]
        pct = (count / max_lb_in_ns) * 100
        ns_bar_rows += (
            f'<div class="bar-row">'
            f'<div class="bar-label">{esc(ns_name)}</div>'
            f'<div class="bar-track">'
            f'<div class="bar-fill" style="width:{pct:.0f}%"></div>'
            f'</div>'
            f'<div class="bar-count">{count}</div>'
            f'</div>\n'
        )

    ns_chart_html = ""
    if ns_with_lbs:
        ns_chart_html = (
            '<h2>Load Balancers per Namespace</h2>'
            f'<div class="bar-chart">\n{ns_bar_rows}</div>'
        )

    # --- Main LB table ---
    table_rows_html = ""
    prev_ns = None
    for ns, lb_name, lb_type in sorted(rows):
        friendly_type = lb_type.replace("_", " ").title()
        type_badge_class = "badge-https" if "https" in lb_type else "badge-http"

        # Visual grouping: add separator row when namespace changes
        if ns != prev_ns:
            ns_lb_count = ns_with_lbs[ns]
            table_rows_html += (
                f'<tr class="ns-group-row">'
                f'<td colspan="3">'
                f'<strong>{esc(ns)}</strong>'
                f'<span class="ns-group-count">{ns_lb_count} LB(s)</span>'
                f'</td></tr>\n'
            )
            prev_ns = ns

        table_rows_html += (
            f'<tr>'
            f'<td class="td-lb-name">{esc(lb_name)}</td>'
            f'<td>{esc(ns)}</td>'
            f'<td><span class="type-badge {type_badge_class}">{esc(friendly_type)}</span></td>'
            f'</tr>\n'
        )

    # --- Assemble body ---
    body_html = f"""\
{config_section}

{summary_cards}

{ns_chart_html}

<h2>All Load Balancers</h2>

<table>
<thead>
<tr>
  <th>LB Name</th>
  <th>Namespace</th>
  <th>Type</th>
</tr>
</thead>
<tbody>
{table_rows_html}
</tbody>
</table>

<h2>CSV for Mover</h2>
<p style="font-size:0.88rem;color:#555;">
  Copy this into <code>config/xc-mover.csv</code> and remove the rows you don't need.
</p>
<div class="csv-section">
  <div class="csv-header">
    <span>
      <span class="csv-title">xc-mover.csv</span>
      <span class="csv-hint">&nbsp;&mdash; {lb_count} row(s), ready to paste</span>
    </span>
    <button class="copy-btn" onclick="copyCsv(this)">Copy CSV</button>
  </div>
  <pre class="csv-block" id="csv-content">{esc(csv_text)}</pre>
</div>
"""

    meta_line = (
        f'Tenant: <strong>{esc(tenant_name)}</strong> &nbsp;|&nbsp; '
        f'{esc(scan_time)} &nbsp;|&nbsp; '
        f'{ns_count} namespace(s) scanned &nbsp;|&nbsp; '
        f'{lb_count} load balancer(s) found'
    )

    html = render_html_page(
        title=f"Scanner Report &mdash; {esc(tenant_name)}",
        meta_line=meta_line,
        body_html=body_html,
        extra_css=_SCANNER_CSS,
    )

    with open(report_path, "w") as f:
        f.write(html)
