"""
Markdown report renderer.

Consumes a ReportData instance and renders to Markdown string.
Field iteration is driven by the schema — no per-field code.
"""

from __future__ import annotations

import json

from ..research import generate_research_report_section
from ..models import FieldDef
from .base import ReportData

__all__ = ["generate_markdown_report"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _field_rows(entry: dict, fields: list[FieldDef]) -> list[str]:
    """Render a list of FieldDefs as Markdown table rows for a single entry."""
    rows: list[str] = []
    for f in fields:
        val = entry.get(f.key, "N/A")
        # Skip rule_hits in the table — rendered separately
        if f.key == "rule_hits":
            continue
        rows.append(f"| **{f.label}** | {val} |")
    return rows


# ---------------------------------------------------------------------------
# Management Summary
# ---------------------------------------------------------------------------

def _management_summary(d: ReportData) -> list[str]:
    """Generate the management summary section."""
    lines: list[str] = []
    m = d.metrics
    v = d.verdict

    lines += ["## Management Summary", "", f"**Verdict: {v.label}** — {v.detail}", ""]

    lines += [
        "| Metric | Value |", "|--------|-------|",
        f"| Security Events | {m.total_sec} ({m.blocked_count} blocked, {m.reported_count} reported) |",
        f"| Access Log Entries | {m.total_access} |",
        f"| Unique Source IPs | {len(m.unique_ips)} |",
        f"| Unique Request IDs | {len(m.unique_req_ids)} |",
        f"| Target Host(s) | {', '.join(m.unique_hosts) or 'N/A'} |",
        f"| Path(s) | {', '.join(f'`{p}`' for p in m.unique_paths) or 'N/A'} |",
        "",
    ]

    if m.rsp_codes:
        lines += ["**Response Codes:**", ""]
        for code in sorted(m.rsp_codes):
            lines.append(f"- `{code}`: {m.rsp_codes[code]}x")
        lines.append("")

    if m.event_types:
        lines += ["**Security Event Breakdown:**", ""]
        for name, count in sorted(m.event_types.items(), key=lambda x: -x[1]):
            actions = ", ".join(sorted(set(
                e.get("action", "?") for e in d.sec_events if e.get("sec_event_name") == name
            )))
            lines.append(f"- **{name}**: {count}x (action: {actions})")
        lines.append("")

    if len(m.unique_ips) > 1:
        lines += ["**Source IPs:**", ""]
        all_entries = d.sec_events + d.access_logs
        for ip in m.unique_ips:
            ip_count = sum(1 for e in all_entries if e.get("src_ip") == ip)
            country = next((e.get("country", "?") for e in all_entries if e.get("src_ip") == ip), "?")
            lines.append(f"- `{ip}` ({country}): {ip_count} events")
        lines.append("")

    lines += ["**Key Findings:**", ""] + d.hints_markdown + [""]
    return lines


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_markdown_report(data: ReportData) -> str:
    """Generate a complete Markdown troubleshooting report."""
    d = data
    lines = [
        "# F5 XC WAAP Troubleshooting Report", "",
        "| Field | Value |", "|-------|-------|",
        f"| **Search Mode** | {d.mode_label} |",
    ]
    if d.req_id:
        lines.append(f"| **Request ID** | `{d.req_id}` |")
    if d.src_ip:
        lines.append(f"| **Source IP** | `{d.src_ip}` |")
    if d.fqdn:
        lines.append(f"| **FQDN** | `{d.fqdn}` |")
    if d.load_balancer:
        lines.append(f"| **Load Balancer** | `{d.load_balancer}` |")
    lines += [
        f"| **Tenant** | `{d.tenant}` |",
        f"| **Namespace** | `{d.namespace}` |",
        f"| **Generated** | {d.generated_at} |",
        f"| **Search Window** | {d.search_window_hours}h |",
        "",
    ]

    # Management Summary
    lines += _management_summary(d)

    # Security Events
    lines += [f"## Detailed Security Events ({len(d.sec_events)} found)", ""]
    if not d.sec_events:
        lines += ["No security events found for this search in the given time window.", ""]
    else:
        for i, evt in enumerate(d.sec_events, 1):
            lines += [
                "<details>",
                f"<summary><strong>Event {i}: {evt['sec_event_name']}</strong> — "
                f"{evt['action']} | {evt['method']} {evt['authority']}{evt['path']} | "
                f"{evt['response_code']} | {evt['time']}</summary>",
                "", "| Field | Value |", "|-------|-------|",
            ]
            lines += _field_rows(evt, d.sec_field_defs)
            lines.append("")
            if evt.get("rule_hits") and evt["rule_hits"] != "N/A":
                lines += ["**WAF Rule Hits / Violations:**", "```json",
                           json.dumps(evt["rule_hits"], indent=2), "```", ""]
            lines += ["</details>", ""]

    # Access Logs
    lines += [f"## Detailed Access Logs ({len(d.access_logs)} found)", ""]
    if not d.access_logs:
        lines += ["No access logs found for this search in the given time window.", ""]
    else:
        for i, log in enumerate(d.access_logs, 1):
            lines += [
                "<details>",
                f"<summary><strong>Log Entry {i}</strong> — {log['method']} "
                f"{log['authority']}{log['path']} | {log['response_code']} | {log['time']}</summary>",
                "", "| Field | Value |", "|-------|-------|",
            ]
            lines += _field_rows(log, d.log_field_defs)
            lines += ["", "</details>", ""]

    # Research
    if d.research_results is not None:
        lines += generate_research_report_section(d.research_results, d.research_queries or [])

    # Raw Data
    lines += [
        "<details>",
        "<summary><strong>Raw Security Event Data (JSON)</strong></summary>", "",
        "```json", json.dumps(d.raw_sec, indent=2, default=str), "```",
        "</details>", "",
        "<details>",
        "<summary><strong>Raw Access Log Data (JSON)</strong></summary>", "",
        "```json", json.dumps(d.raw_access, indent=2, default=str), "```",
        "</details>", "",
    ]

    return "\n".join(lines)
