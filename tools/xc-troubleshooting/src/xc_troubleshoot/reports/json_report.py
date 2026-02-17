"""
JSON report renderer.
"""

from __future__ import annotations

import json

from .base import ReportData

__all__ = ["generate_json_report"]


def generate_json_report(data: ReportData) -> str:
    """Generate a JSON troubleshooting report."""
    d = data
    report: dict = {
        "report_metadata": {
            "search_mode": d.mode_label,
            "request_id": d.req_id or None,
            "source_ip": d.src_ip or None,
            "fqdn": d.fqdn or None,
            "load_balancer": d.load_balancer or None,
            "tenant": d.tenant,
            "namespace": d.namespace,
            "generated_at": d.generated_at,
            "search_window_hours": d.search_window_hours,
        },
        "security_events": d.sec_events,
        "access_logs": d.access_logs,
        "raw_security_events": d.raw_sec,
        "raw_access_logs": d.raw_access,
    }
    if d.research_results is not None:
        report["public_research"] = {
            "queries": d.research_queries or [],
            "results": d.research_results,
        }
    return json.dumps(report, indent=2, default=str)
