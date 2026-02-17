"""
Shared analysis logic — verdict computation, metrics, and label helpers.

Used by both Markdown and HTML report generators to avoid duplication.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Verdict", "ReportMetrics", "compute_verdict", "compute_metrics", "search_mode_label"]


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Verdict:
    label: str          # BLOCKED | MONITORED | ALLOWED | NO DATA | INFO
    detail: str         # human-readable explanation
    css_class: str      # for HTML rendering


def compute_verdict(sec_events: list[dict], access_logs: list[dict]) -> Verdict:
    """Compute a single verdict from event data."""
    blocked = [
        e for e in sec_events
        if "block" in str(e.get("action", "")).lower()
        or "deny" in str(e.get("action", "")).lower()
    ]
    reported = [
        e for e in sec_events
        if "report" in str(e.get("action", "")).lower() and e not in blocked
    ]

    if blocked:
        return Verdict("BLOCKED", f"{len(blocked)} request(s) blocked by security policy", "blocked")
    if reported:
        return Verdict("MONITORED", f"{len(reported)} security event(s) reported (not blocked)", "monitored")
    if not sec_events and not access_logs:
        return Verdict("NO DATA", "No events found for the given search criteria", "nodata")
    if not sec_events and access_logs:
        return Verdict("ALLOWED", "No security events — request(s) passed without violations", "allowed")
    return Verdict("INFO", "Events found — review details below", "info")


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class ReportMetrics:
    total_sec: int = 0
    total_access: int = 0
    blocked_count: int = 0
    reported_count: int = 0
    unique_ips: list[str] = field(default_factory=list)
    unique_hosts: list[str] = field(default_factory=list)
    unique_paths: list[str] = field(default_factory=list)
    unique_req_ids: list[str] = field(default_factory=list)
    rsp_codes: dict[str, int] = field(default_factory=dict)
    event_types: dict[str, int] = field(default_factory=dict)


def compute_metrics(sec_events: list[dict], access_logs: list[dict]) -> ReportMetrics:
    """Compute aggregate metrics from parsed events and logs."""
    m = ReportMetrics()
    m.total_sec = len(sec_events)
    m.total_access = len(access_logs)

    m.blocked_count = sum(
        1 for e in sec_events
        if "block" in str(e.get("action", "")).lower()
        or "deny" in str(e.get("action", "")).lower()
    )
    m.reported_count = sum(
        1 for e in sec_events
        if "report" in str(e.get("action", "")).lower()
    )

    all_entries = sec_events + access_logs

    def _unique_sorted(key: str) -> list[str]:
        return sorted(set(
            e.get(key, "N/A") for e in all_entries if e.get(key, "N/A") != "N/A"
        ))

    m.unique_ips = _unique_sorted("src_ip")
    m.unique_hosts = _unique_sorted("authority")
    m.unique_paths = _unique_sorted("path")
    m.unique_req_ids = _unique_sorted("req_id")

    for e in all_entries:
        code = str(e.get("response_code", e.get("rsp_code", "N/A")))
        if code != "N/A":
            m.rsp_codes[code] = m.rsp_codes.get(code, 0) + 1

    for e in sec_events:
        name = e.get("sec_event_name", "Unknown")
        m.event_types[name] = m.event_types.get(name, 0) + 1

    return m


# ---------------------------------------------------------------------------
# Label helpers
# ---------------------------------------------------------------------------

def search_mode_label(
    req_id: str = "",
    src_ip: str = "",
    fqdn: str = "",
    load_balancer: str = "",
) -> str:
    """Return a human-readable label for the search mode used."""
    parts = []
    if req_id:
        parts.append("Request ID")
    if src_ip:
        parts.append("Source IP")
    if fqdn:
        parts.append("FQDN")
    if load_balancer:
        parts.append("Load Balancer")
    return " + ".join(parts) if parts else "N/A"
