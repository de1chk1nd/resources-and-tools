"""
HTML report renderer.

Consumes a ReportData instance and renders a self-contained HTML file.
Field iteration is driven by the schema — no per-field code.
"""

from __future__ import annotations

import json
from html import escape

from ..models import FieldDef
from ._css import CSS
from .base import ReportData

__all__ = ["generate_html_report"]


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _esc(val) -> str:
    if val is None:
        return "N/A"
    return escape(str(val))


def _action_badge(action: str) -> str:
    a = action.lower()
    if "block" in a or "deny" in a:
        return f'<span class="badge block">{_esc(action)}</span>'
    if "report" in a:
        return f'<span class="badge report">{_esc(action)}</span>'
    if "allow" in a:
        return f'<span class="badge allow">{_esc(action)}</span>'
    return _esc(action)


def _code_badge(code) -> str:
    s = str(code)
    cls = {"2": "code-2xx", "3": "code-3xx", "4": "code-4xx", "5": "code-5xx"}.get(s[:1])
    return f'<span class="badge {cls}">{_esc(s)}</span>' if cls else _esc(s)


def _detail_table(entry: dict, fields: list[FieldDef]) -> str:
    """Build an HTML detail table from a dict + field schema."""
    rows: list[str] = []
    for f in fields:
        if f.key == "rule_hits":
            continue
        val = entry.get(f.key, "N/A")
        # Apply badges for action / response_code
        if f.key == "action":
            rendered = _action_badge(str(val))
        elif f.key == "response_code":
            rendered = _code_badge(val)
        else:
            rendered = _esc(val)
        rows.append(
            f'<tr><td style="font-weight:600;width:200px">{_esc(f.label)}</td>'
            f'<td class="mono">{rendered}</td></tr>'
        )
    return f"<table>{''.join(rows)}</table>"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_html_report(data: ReportData) -> str:
    """Generate a self-contained HTML troubleshooting report."""
    d = data
    m = d.metrics
    v = d.verdict
    h: list[str] = []  # accumulator

    # Head + header
    h.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>F5 XC WAAP Report — {_esc(d.tenant)}</title>
<style>{CSS}</style>
</head>
<body>
<header><div class="container">
  <div><h1>F5 XC WAAP — Troubleshooting Report</h1></div>
  <div class="meta">
    <div><strong>Tenant:</strong> {_esc(d.tenant)}</div>
    <div><strong>Namespace:</strong> {_esc(d.namespace)}</div>
    <div><strong>Generated:</strong> {_esc(d.generated_at)}</div>
  </div>
</div></header>
<div class="container">
<div class="info-grid">
  <div class="item"><span class="label">Search Mode</span><span class="value">{_esc(d.mode_label)}</span></div>
  <div class="item"><span class="label">Time Window</span><span class="value">{d.search_window_hours}h</span></div>""")

    for label, val in [("Request ID", d.req_id), ("Source IP", d.src_ip),
                        ("FQDN", d.fqdn), ("Load Balancer", d.load_balancer)]:
        if val:
            h.append(f'  <div class="item"><span class="label">{label}</span><span class="value">{_esc(val)}</span></div>')
    h.append("</div>")

    # Verdict
    h.append(f'<div class="verdict {v.css_class}"><strong>{v.label}</strong> — {_esc(v.detail)}</div>')

    # Metrics
    h.append(f"""<h2>Overview</h2>
<div class="metrics">
  <div class="metric-card"><div class="number">{m.total_sec}</div><div class="label">Security Events</div></div>
  <div class="metric-card"><div class="number">{m.blocked_count}</div><div class="label">Blocked</div></div>
  <div class="metric-card"><div class="number">{m.reported_count}</div><div class="label">Reported</div></div>
  <div class="metric-card"><div class="number">{m.total_access}</div><div class="label">Access Logs</div></div>
  <div class="metric-card"><div class="number">{len(m.unique_ips)}</div><div class="label">Unique IPs</div></div>
  <div class="metric-card"><div class="number">{len(m.unique_req_ids)}</div><div class="label">Unique Requests</div></div>
</div>""")

    # Response codes + event type breakdown
    if m.rsp_codes or m.event_types:
        h.append('<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:20px">')
        if m.rsp_codes:
            h.append("<div><h3>Response Codes</h3><table><tr><th>Code</th><th>Count</th></tr>")
            for code in sorted(m.rsp_codes):
                h.append(f"<tr><td>{_code_badge(code)}</td><td>{m.rsp_codes[code]}</td></tr>")
            h.append("</table></div>")
        if m.event_types:
            h.append("<div><h3>Security Event Breakdown</h3><table><tr><th>Event</th><th>Count</th><th>Action</th></tr>")
            for name, count in sorted(m.event_types.items(), key=lambda x: -x[1]):
                actions = ", ".join(sorted(set(
                    e.get("action", "?") for e in d.sec_events if e.get("sec_event_name") == name
                )))
                h.append(f"<tr><td>{_esc(name)}</td><td>{count}</td><td>{_action_badge(actions)}</td></tr>")
            h.append("</table></div>")
        h.append("</div>")

    # Key Findings — summary table + grouped cards
    if d.findings:
        severity_icon = {"error": "&#x2716;", "warning": "&#x26A0;", "info": "&#x2139;"}
        severity_label = {"error": "Error", "warning": "Warning", "info": "Info"}

        # Summary table
        h.append('<h2>Key Findings</h2>')
        h.append('<table><tr><th></th><th>Finding</th><th>Summary</th><th>Severity</th></tr>')
        for i, f in enumerate(d.findings, 1):
            badge_cls = {"error": "block", "warning": "report", "info": "code-3xx"}.get(f.severity, "")
            h.append(
                f'<tr><td>{i}</td>'
                f'<td style="font-weight:600">{_esc(f.title)}</td>'
                f'<td>{_esc(f.summary)}</td>'
                f'<td><span class="badge {badge_cls}">{severity_label.get(f.severity, f.severity)}</span></td></tr>'
            )
        h.append('</table>')

        # Detail cards
        h.append('<div class="hints">')
        for i, f in enumerate(d.findings, 1):
            css = {"error": "error", "warning": "warn", "info": ""}.get(f.severity, "")
            icon = severity_icon.get(f.severity, "")
            h.append(f'<details class="finding-card"><summary class="hint {css}">'
                     f'{icon} &nbsp;<strong>{_esc(f.title)}</strong> — {_esc(f.summary)}</summary>')
            h.append('<div class="detail-content">')
            if f.details:
                h.append('<div style="margin-bottom:8px"><strong>Details</strong></div><ul>')
                for d_line in f.details:
                    h.append(f'<li>{_esc(d_line)}</li>')
                h.append('</ul>')
            if f.recommendations:
                h.append('<div style="margin-bottom:8px;margin-top:12px"><strong>Recommendations</strong></div><ul>')
                for r_line in f.recommendations:
                    h.append(f'<li>{_esc(r_line)}</li>')
                h.append('</ul>')
            if not f.details and not f.recommendations:
                h.append('<p style="color:#666">No additional details.</p>')
            h.append('</div></details>')
        h.append("</div>")

    # Security Events — schema-driven detail tables
    h.append(f'<h2>Security Events ({m.total_sec})</h2>')
    if not d.sec_events:
        h.append("<p>No security events found for this search in the given time window.</p>")
    else:
        for i, evt in enumerate(d.sec_events, 1):
            label = f"Event {i}: {_esc(evt['sec_event_name'])} — {_esc(evt['method'])} {_esc(evt['authority'])}{_esc(evt['path'])}"
            h.append(
                f'<details><summary>{_action_badge(evt["action"])} &nbsp; {_code_badge(evt["response_code"])} '
                f'&nbsp; {label} &nbsp; <small>{_esc(evt["time"])}</small></summary>'
                f'<div class="detail-content">{_detail_table(evt, d.sec_field_defs)}'
            )
            if evt.get("rule_hits") and evt["rule_hits"] != "N/A":
                h.append(f"<h3>WAF Rule Hits</h3><pre>{escape(json.dumps(evt['rule_hits'], indent=2))}</pre>")
            h.append("</div></details>")

    # Access Logs — schema-driven
    h.append(f'<h2>Access Logs ({m.total_access})</h2>')
    if not d.access_logs:
        h.append("<p>No access logs found for this search in the given time window.</p>")
    else:
        for i, log in enumerate(d.access_logs, 1):
            label = f"Log {i}: {_esc(log['method'])} {_esc(log['authority'])}{_esc(log['path'])}"
            h.append(
                f'<details><summary>{_code_badge(log["response_code"])} &nbsp; {label} '
                f'&nbsp; <small>{_esc(log["time"])}</small></summary>'
                f'<div class="detail-content">{_detail_table(log, d.log_field_defs)}</div></details>'
            )

    # Research
    if d.research_results is not None:
        h.append(f'<h2>Public Research ({len(d.research_results)} results)</h2>')
        if not d.research_results:
            h.append("<p>No relevant public articles found.</p>")
        else:
            by_query: dict[str, list[dict]] = {}
            for r in d.research_results:
                by_query.setdefault(r.get("query", "General"), []).append(r)
            for q, items in by_query.items():
                h.append(f'<h3>Search: {_esc(q)}</h3>')
                for r in items:
                    url, title = r.get("url", ""), r.get("title", "Untitled")
                    snippet = r.get("snippet", "")
                    h.append('<div class="research-item">')
                    h.append(f'<a href="{_esc(url)}" target="_blank">{_esc(title)}</a>' if url else f'<strong>{_esc(title)}</strong>')
                    if snippet:
                        h.append(f'<div class="snippet">{_esc(snippet[:200])}</div>')
                    h.append("</div>")

    # Raw Data
    h.append('<h2>Raw Data</h2>')
    h.append(f'<details><summary>Raw Security Event Data (JSON)</summary><div class="detail-content">'
             f'<pre>{escape(json.dumps(d.raw_sec, indent=2, default=str))}</pre></div></details>')
    h.append(f'<details><summary>Raw Access Log Data (JSON)</summary><div class="detail-content">'
             f'<pre>{escape(json.dumps(d.raw_access, indent=2, default=str))}</pre></div></details>')

    # Footer
    h.append(f"""<footer>
  F5 Distributed Cloud — WAAP Troubleshooting Report &middot;
  Tenant: {_esc(d.tenant)} &middot; Namespace: {_esc(d.namespace)} &middot;
  Generated: {_esc(d.generated_at)}
</footer>
</div></body></html>""")

    return "\n".join(h)
