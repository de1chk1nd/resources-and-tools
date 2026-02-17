"""
Report data container — holds everything the renderers need.

The CLI builds a ReportData instance once; each renderer (markdown, html, json)
consumes it without recomputing anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..analysis import Verdict, ReportMetrics, compute_verdict, compute_metrics, search_mode_label
from ..hints import Finding, generate_findings, findings_to_markdown
from ..models import SECURITY_EVENT_FIELDS, ACCESS_LOG_FIELDS, FieldDef

__all__ = ["ReportData"]


@dataclass
class ReportData:
    """Immutable snapshot of all data needed to render a report."""

    # Search parameters
    req_id: str = ""
    src_ip: str = ""
    fqdn: str = ""
    load_balancer: str = ""
    tenant: str = ""
    namespace: str = ""
    search_window_hours: int = 24

    # Parsed data
    sec_events: list[dict] = field(default_factory=list)
    access_logs: list[dict] = field(default_factory=list)
    raw_sec: dict = field(default_factory=dict)
    raw_access: dict = field(default_factory=dict)

    # Optional research
    research_results: list[dict] | None = None
    research_queries: list[str] | None = None

    # Computed (populated by .build())
    verdict: Verdict = field(default_factory=lambda: Verdict("INFO", "", "info"))
    metrics: ReportMetrics = field(default_factory=ReportMetrics)
    findings: list[Finding] = field(default_factory=list)
    hints_markdown: list[str] = field(default_factory=list)
    mode_label: str = ""
    generated_at: str = ""

    # Schema references
    sec_field_defs: list[FieldDef] = field(default_factory=lambda: list(SECURITY_EVENT_FIELDS))
    log_field_defs: list[FieldDef] = field(default_factory=lambda: list(ACCESS_LOG_FIELDS))

    def build(self) -> "ReportData":
        """Compute derived fields. Call once after setting data fields."""
        self.verdict = compute_verdict(self.sec_events, self.access_logs)
        self.metrics = compute_metrics(self.sec_events, self.access_logs)
        self.findings = generate_findings(self.sec_events, self.access_logs)
        self.hints_markdown = findings_to_markdown(self.findings)
        self.mode_label = search_mode_label(self.req_id, self.src_ip, self.fqdn, self.load_balancer)
        self.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return self
