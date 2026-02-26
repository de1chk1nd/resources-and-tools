"""
HTML report renderer — aligned with xc-ns-mover design language.

Consumes a ReportData instance and renders a self-contained HTML file.
Field iteration is driven by the schema — no per-field code.
"""

from __future__ import annotations

import json
from html import escape

from ..models import FieldDef
from ._css import CSS
from .base import ReportData
from ._traffic_svg import render_traffic_flow_svg
from ._services_svg import render_services_svg

__all__ = ["generate_html_report"]


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _esc(val) -> str:
    if val is None:
        return "N/A"
    return escape(str(val))


import re as _re

def _md_inline(text: str) -> str:
    """Convert minimal inline markdown to HTML (bold + code spans).

    Escapes the text first, then converts ``**bold**`` and `` `code` ``
    so that finding detail lines render nicely in the HTML report.
    """
    s = escape(str(text))
    s = _re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', s)
    s = _re.sub(r'`(.+?)`', r'<code>\1</code>', s)
    return s


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
    # Fields rendered separately (JSON block, finding details, etc.)
    _SKIP_TABLE_KEYS = {"rule_hits", "signatures", "threat_campaigns", "attack_types", "req_risk_reasons"}
    rows: list[str] = []
    for f in fields:
        if f.key in _SKIP_TABLE_KEYS:
            continue
        val = entry.get(f.key, "N/A")
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


_CLIPBOARD_JS = """\
<script>
function _doCopy(btn, text, labelOk, labelFail) {
  navigator.clipboard.writeText(text).then(function() {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(function() {
      btn.textContent = labelOk;
      btn.classList.remove('copied');
    }, 2000);
  }, function() {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(function() {
        btn.textContent = labelOk;
        btn.classList.remove('copied');
      }, 2000);
    } catch(e) {
      btn.textContent = labelFail;
      setTimeout(function() { btn.textContent = labelOk; }, 2000);
    }
    document.body.removeChild(ta);
  });
}
function copyJson(btn) {
  var pre = btn.parentElement.querySelector('pre.json-block');
  if (!pre) return;
  _doCopy(btn, pre.textContent || pre.innerText, 'Copy JSON', 'Failed');
}
</script>"""


# ---------------------------------------------------------------------------
# Verdict → traffic-light mapping
# ---------------------------------------------------------------------------

_VERDICT_MAP = {
    "blocked":   ("health-red",    "&#10008;"),
    "monitored": ("health-yellow", "&#9888;"),
    "allowed":   ("health-green",  "&#10004;"),
    "nodata":    ("health-grey",   "&#8212;"),
    "info":      ("health-blue",   "&#8505;"),
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_html_report(data: ReportData) -> str:
    """Generate a self-contained HTML troubleshooting report."""
    d = data
    m = d.metrics
    v = d.verdict
    h: list[str] = []

    # --- Head + header ---
    h.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>F5 XC WAAP Report &mdash; {_esc(d.tenant)}</title>
<style>{CSS}</style>
</head>
<body>
<header><div class="container">
  <div><h1>F5 XC WAAP &mdash; Troubleshooting Report</h1></div>
  <div class="meta">
    <div><strong>Tenant:</strong> {_esc(d.tenant)}</div>
    <div><strong>Namespace:</strong> {_esc(d.namespace)}{'  (all namespaces)' if d.namespace == 'system' else ''}</div>
    <div><strong>Generated:</strong> {_esc(d.generated_at)}</div>
  </div>
</div></header>
<div class="body-container">""")

    # --- Search parameters grid ---
    h.append("""<div class="info-grid">""")
    h.append(f'  <div class="item"><span class="label">Search Mode</span><span class="value">{_esc(d.mode_label)}</span></div>')
    h.append(f'  <div class="item"><span class="label">Time Window</span><span class="value">{d.search_window_hours}h</span></div>')
    for label, val in [("Request ID", d.req_id), ("Source IP", d.src_ip),
                        ("FQDN", d.fqdn), ("Load Balancer", d.load_balancer)]:
        if val:
            h.append(f'  <div class="item"><span class="label">{label}</span><span class="value">{_esc(val)}</span></div>')
    h.append("</div>")

    # --- Traffic flow diagram ---
    if d.traffic_flow:
        flow_svg = render_traffic_flow_svg(d.traffic_flow)
        if flow_svg:
            h.append(
                '<div class="section">'
                '<h2 style="margin-top:0">Traffic Flow</h2>'
                f'<div style="overflow-x:auto">{flow_svg}</div>'
                '</div>'
            )

    # --- API errors banner ---
    if d.api_errors:
        h.append('<div class="warning-banner"><strong>&#9888; Warning</strong> &mdash; '
                 'Some API queries failed. The report below may be incomplete.<ul>')
        for err in d.api_errors:
            h.append(f'<li>{_esc(err)}</li>')
        h.append('</ul></div>')

    # --- Verdict banner (traffic-light) ---
    banner_cls, banner_icon = _VERDICT_MAP.get(v.css_class, ("health-grey", "&#8212;"))

    stat_pills: list[str] = []
    if m.total_sec:
        stat_pills.append(f'<span class="health-pill">&#128721; {m.total_sec} Security Events</span>')
    if m.blocked_count:
        stat_pills.append(f'<span class="health-pill">&#10060; {m.blocked_count} Blocked</span>')
    if m.reported_count:
        stat_pills.append(f'<span class="health-pill">&#9888; {m.reported_count} Reported</span>')
    if m.total_access:
        stat_pills.append(f'<span class="health-pill">&#128196; {m.total_access} Access Logs</span>')
    if len(m.unique_ips) > 1:
        stat_pills.append(f'<span class="health-pill">&#127760; {len(m.unique_ips)} Unique IPs</span>')

    pills_html = ""
    if stat_pills:
        pills_html = '<div class="health-stats">' + " ".join(stat_pills) + '</div>'

    h.append(
        f'<div class="health-banner {banner_cls}">'
        f'<div class="health-light">{banner_icon}</div>'
        f'<div class="health-body">'
        f'<div class="health-headline">{_esc(v.label)}</div>'
        f'<div style="font-size:0.92rem;margin-bottom:0.35rem;opacity:0.85;">{_esc(v.detail)}</div>'
        f'{pills_html}'
        f'</div></div>'
    )

    # =====================================================================
    # OVERVIEW SECTION
    # =====================================================================
    h.append('<div class="section">')
    h.append('<h2 style="margin-top:0">Overview</h2>')

    # --- Summary cards ---
    h.append(f"""<div class="summary">
  <div class="card card-primary"><div class="num">{m.total_sec}</div><div class="label">Security Events</div></div>
  <div class="card card-blocked"><div class="num">{m.blocked_count}</div><div class="label">Blocked</div></div>
  <div class="card card-reported"><div class="num">{m.reported_count}</div><div class="label">Reported</div></div>
  <div class="card card-access"><div class="num">{m.total_access}</div><div class="label">Access Logs</div></div>
  <div class="card card-ips"><div class="num">{len(m.unique_ips)}</div><div class="label">Unique IPs</div></div>
  <div class="card card-reqs"><div class="num">{len(m.unique_req_ids)}</div><div class="label">Unique Requests</div></div>
</div>""")

    # --- Response codes + event type breakdown ---
    if m.rsp_codes or m.event_types:
        h.append('<div class="breakdown-grid">')
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

    h.append('</div>')  # end overview section

    # =====================================================================
    # KEY FINDINGS SECTION
    # =====================================================================
    if d.findings:
        severity_icon = {"error": "&#x2716;", "warning": "&#x26A0;", "info": "&#x2139;"}
        severity_label = {"error": "Error", "warning": "Warning", "info": "Info"}

        h.append('<div class="section">')
        h.append('<h2 style="margin-top:0">Key Findings</h2>')
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

        h.append('<div class="hints">')
        for i, f in enumerate(d.findings, 1):
            css = {"error": "error", "warning": "warn", "info": ""}.get(f.severity, "")
            icon = severity_icon.get(f.severity, "")
            h.append(f'<details class="finding-card"><summary class="hint {css}">'
                     f'{icon} &nbsp;<strong>{_esc(f.title)}</strong> &mdash; {_esc(f.summary)}</summary>')
            h.append('<div class="detail-content">')
            if f.details:
                h.append('<div style="margin-bottom:8px"><strong>Details</strong></div><ul>')
                for d_line in f.details:
                    h.append(f'<li>{_md_inline(d_line)}</li>')
                h.append('</ul>')
            if f.recommendations:
                h.append('<div style="margin-bottom:8px;margin-top:12px"><strong>Recommendations</strong></div><ul>')
                for r_line in f.recommendations:
                    h.append(f'<li>{_md_inline(r_line)}</li>')
                h.append('</ul>')
            if not f.details and not f.recommendations:
                h.append('<p style="color:#666">No additional details.</p>')
            h.append('</div></details>')
        h.append("</div>")
        h.append('</div>')  # end findings section

    # =====================================================================
    # SERVICES ENABLED SECTION
    # =====================================================================
    if d.lb_config and not d.lb_config.error:
        lb = d.lb_config
        h.append('<div class="section">')
        h.append('<h2 style="margin-top:0">Services Enabled</h2>')
        h.append(
            '<p style="font-size:0.8rem;color:#888;margin-top:-0.6rem;margin-bottom:1rem">'
            'Service flow visualisation inspired by '
            '<a href="https://github.com/Mikej81/xcshowmap" target="_blank" '
            'rel="noopener" style="color:#0d6efd">xcshowmap</a> by Mike Coleman.'
            '</p>'
        )

        # Graphical SVG diagram (always visible)
        svc_svg = render_services_svg(lb)
        if svc_svg:
            h.append(
                f'<div style="overflow-x:auto;margin-bottom:1.25rem">{svc_svg}</div>'
            )

        # --- Collapsible detail tables ---
        enabled_svcs = [s for s in lb.services if s.enabled]
        disabled_svcs = [s for s in lb.services if not s.enabled]

        # LB config table — collapsed by default
        h.append('<details class="sub-section"><summary>Load Balancer Configuration</summary>')
        h.append('<div class="detail-content">')
        h.append('<table><tr><th>Property</th><th>Value</th></tr>')
        h.append(f'<tr><td style="font-weight:600;width:200px">Name</td><td class="mono">{_esc(lb.lb_name)}</td></tr>')
        h.append(f'<tr><td style="font-weight:600">Namespace</td><td class="mono">{_esc(lb.namespace)}</td></tr>')
        h.append(f'<tr><td style="font-weight:600">Type</td><td>{_esc(lb.lb_type)}</td></tr>')
        h.append(f'<tr><td style="font-weight:600">Advertise</td><td>{_esc(lb.advertise_policy)}</td></tr>')
        if lb.domains:
            h.append(f'<tr><td style="font-weight:600">Domains</td><td class="mono">{_esc(", ".join(lb.domains))}</td></tr>')
        if lb.origin_pools:
            h.append(f'<tr><td style="font-weight:600">Origin Pools</td><td class="mono">{_esc(", ".join(lb.origin_pools))}</td></tr>')
        h.append('</table>')
        h.append('</div></details>')

        # Enabled services table — collapsed by default
        if enabled_svcs:
            h.append(f'<details class="sub-section"><summary>Enabled Security Services ({len(enabled_svcs)})</summary>')
            h.append('<div class="detail-content">')
            h.append('<table><tr><th>Service</th><th>Status / Mode</th><th>Detail</th></tr>')
            for svc in enabled_svcs:
                # For MUD, enrich the detail column with resolved identifiers
                detail_html = _esc(svc.detail) if svc.detail else "&mdash;"
                if svc.name == "Malicious User Detection" and lb.user_identification and lb.user_identification.rules:
                    uid = lb.user_identification
                    uid_rules = ", ".join(uid.rules)
                    detail_html = _esc(svc.detail) if svc.detail else ""
                    if detail_html:
                        detail_html += f'<br><span style="font-size:0.82rem;color:#495057">Identifiers: {_esc(uid_rules)}</span>'
                    else:
                        detail_html = f'Identifiers: {_esc(uid_rules)}'

                h.append(
                    f'<tr><td style="font-weight:600">{_esc(svc.name)}</td>'
                    f'<td><span class="badge allow">{_esc(svc.mode or "Enabled")}</span></td>'
                    f'<td class="mono">{detail_html}</td></tr>'
                )
                # User Identification sub-row for Malicious User Detection
                if svc.name == "Malicious User Detection" and lb.user_identification:
                    uid = lb.user_identification
                    uid_label = f"{uid.namespace}/{uid.name}" if uid.namespace else uid.name
                    uid_rules = ", ".join(uid.rules) if uid.rules else "no identifiers resolved"
                    h.append(
                        f'<tr style="background:#f8f9fa"><td style="padding-left:2rem;color:#666">'
                        f'&raquo; User Identification Policy</td>'
                        f'<td class="mono" style="font-size:0.8rem">{_esc(uid_label)}</td>'
                        f'<td class="mono" style="font-size:0.8rem">{_esc(uid_rules)}</td></tr>'
                    )
                elif svc.name == "Malicious User Detection" and lb.user_id_ref and lb.user_id_ref.get("name"):
                    # Have the reference but no resolved details
                    ref = lb.user_id_ref
                    ref_label = f"{ref.get('namespace', '')}/{ref['name']}" if ref.get("namespace") else ref["name"]
                    h.append(
                        f'<tr style="background:#f8f9fa"><td style="padding-left:2rem;color:#666">'
                        f'&raquo; User Identification Policy</td>'
                        f'<td class="mono" style="font-size:0.8rem">{_esc(ref_label)}</td>'
                        f'<td class="mono" style="font-size:0.8rem;color:#999">(details not resolved)</td></tr>'
                    )
            h.append('</table>')
            h.append('</div></details>')

        # Disabled services table — collapsed by default
        if disabled_svcs:
            h.append(f'<details class="sub-section"><summary>Disabled / Not Configured ({len(disabled_svcs)})</summary>')
            h.append('<div class="detail-content">')
            h.append('<table><tr><th>Service</th><th>Status</th></tr>')
            for svc in disabled_svcs:
                h.append(
                    f'<tr><td>{_esc(svc.name)}</td>'
                    f'<td><span class="badge" style="background:#e9ecef;color:#495057">{_esc(svc.mode or "Disabled")}</span></td></tr>'
                )
            h.append('</table></div></details>')

        h.append('</div>')  # end services section

    # =====================================================================
    # SECURITY EVENTS SECTION
    # =====================================================================
    h.append('<div class="section">')
    h.append(f'<h2 style="margin-top:0">Security Events ({m.total_sec})</h2>')
    if not d.sec_events:
        h.append("<p>No security events found for this search in the given time window.</p>")
    else:
        for i, evt in enumerate(d.sec_events, 1):
            label = f"Event {i}: {_esc(evt['sec_event_name'])} &mdash; {_esc(evt['method'])} {_esc(evt['authority'])}{_esc(evt['path'])}"
            h.append(
                f'<details><summary>{_action_badge(evt["action"])} &nbsp; {_code_badge(evt["response_code"])} '
                f'&nbsp; {label} &nbsp; <small>{_esc(evt["time"])}</small></summary>'
                f'<div class="detail-content">{_detail_table(evt, d.sec_field_defs)}'
            )
            if evt.get("rule_hits") and evt["rule_hits"] != "N/A":
                h.append(f'<h3>WAF Rule Hits</h3><pre class="legacy">{escape(json.dumps(evt["rule_hits"], indent=2))}</pre>')
            h.append("</div></details>")
    h.append('</div>')  # end security events section

    # =====================================================================
    # ACCESS LOGS SECTION
    # =====================================================================
    h.append('<div class="section">')
    h.append(f'<h2 style="margin-top:0">Access Logs ({m.total_access})</h2>')
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
    h.append('</div>')  # end access logs section

    # =====================================================================
    # RESEARCH SECTION
    # =====================================================================
    if d.research_results is not None:
        h.append('<div class="section">')
        h.append(f'<h2 style="margin-top:0">Public Research ({len(d.research_results)} results)</h2>')
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
                    h.append(f'<a href="{_esc(url)}" target="_blank" rel="noopener">{_esc(title)}</a>' if url else f'<strong>{_esc(title)}</strong>')
                    if snippet:
                        h.append(f'<div class="snippet">{_esc(snippet[:200])}</div>')
                    h.append("</div>")
        h.append('</div>')  # end research section

    # =====================================================================
    # RAW DATA SECTION
    # =====================================================================
    h.append('<div class="section">')
    h.append('<h2 style="margin-top:0">Raw Data</h2>')
    raw_sec_json = escape(json.dumps(d.raw_sec, indent=2, default=str))
    raw_access_json = escape(json.dumps(d.raw_access, indent=2, default=str))
    h.append(
        f'<details><summary>Raw Security Event Data (JSON)</summary>'
        f'<div class="detail-content"><div class="json-block-wrapper">'
        f'<button class="copy-btn" onclick="copyJson(this)">Copy JSON</button>'
        f'<pre class="json-block">{raw_sec_json}</pre>'
        f'</div></div></details>'
    )
    h.append(
        f'<details><summary>Raw Access Log Data (JSON)</summary>'
        f'<div class="detail-content"><div class="json-block-wrapper">'
        f'<button class="copy-btn" onclick="copyJson(this)">Copy JSON</button>'
        f'<pre class="json-block">{raw_access_json}</pre>'
        f'</div></div></details>'
    )
    h.append('</div>')  # end raw data section

    # --- Footer + script ---
    h.append(f"""<footer>
  Generated by xc-troubleshoot &middot;
  Tenant: {_esc(d.tenant)} &middot; Namespace: {_esc(d.namespace)} &middot;
  {_esc(d.generated_at)}
</footer>
</div>
{_CLIPBOARD_JS}
</body></html>""")

    return "\n".join(h)
