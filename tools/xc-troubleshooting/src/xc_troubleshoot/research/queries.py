"""
Query derivation — build search queries from security events and access logs.
"""

from __future__ import annotations

import logging

__all__ = ["build_research_queries"]

logger = logging.getLogger(__name__)


def build_research_queries(
    sec_events: list[dict],
    access_logs: list[dict],
) -> list[str]:
    """Build search queries from security events for public research."""
    queries: set[str] = set()

    for evt in sec_events:
        event_name = evt.get("sec_event_name", "")
        rsp_code = str(evt.get("response_code", ""))
        action = str(evt.get("action", "")).lower()

        if event_name and event_name != "N/A":
            queries.add(f'F5 XC "{event_name}"')
        if rsp_code and rsp_code != "N/A" and rsp_code.startswith(("4", "5")):
            if "block" in action:
                queries.add(f"F5 XC WAAP {rsp_code} blocked")
        if "jwt" in event_name.lower():
            queries.add("F5 XC JWT validation troubleshooting")
        if "openapi" in event_name.lower() or "fallthrough" in event_name.lower():
            queries.add("F5 XC OpenAPI validation fall through")
        bot = evt.get("bot_classification", "")
        if bot and bot != "N/A" and "bot" in bot.lower():
            queries.add("F5 XC bot defense configuration")

    for log in access_logs:
        flags = str(log.get("response_flags", ""))
        if flags and flags != "N/A" and flags != "-":
            queries.add(f"F5 XC response flags {flags}")

    return sorted(queries)
