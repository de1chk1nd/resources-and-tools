"""
API response parsers — extract structured summaries from raw F5 XC API data.

Uses field schemas from models.py so field definitions are not repeated.
"""

from __future__ import annotations

import json
import logging

from .models import FieldDef, SECURITY_EVENT_FIELDS, ACCESS_LOG_FIELDS

__all__ = ["extract_event_summary", "extract_access_log_summary"]

logger = logging.getLogger(__name__)


def _parse_entry(entry) -> dict:
    """Parse an API response entry — may be a JSON string or a dict."""
    if isinstance(entry, dict):
        return entry
    if isinstance(entry, str):
        try:
            return json.loads(entry)
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def _extract_policy_info(e: dict) -> dict[str, str]:
    """Extract policy hit details from the nested policy_hits structure."""
    policy_hits = e.get("policy_hits", {})
    hits = policy_hits.get("policy_hits", []) if isinstance(policy_hits, dict) else []
    if not hits:
        return {
            "policy_name": "N/A",
            "policy_rule": "N/A",
            "policy_result": "N/A",
            "oas_validation_action": "N/A",
            "rate_limiter_action": "N/A",
        }
    first = hits[0] if isinstance(hits[0], dict) else {}
    return {
        "policy_name": first.get("policy", first.get("policy_set", "N/A")),
        "policy_rule": first.get("policy_rule", "N/A"),
        "policy_result": first.get("result", "N/A"),
        "oas_validation_action": first.get("oas_validation_action", "N/A"),
        "rate_limiter_action": first.get("rate_limiter_action", "N/A"),
    }


def _extract_fields(raw: dict, fields: list[FieldDef], policy: dict[str, str]) -> dict:
    """Extract a summary dict from a raw API entry using a field schema."""
    result = {}
    for f in fields:
        if f.is_policy:
            result[f.key] = policy.get(f.key, f.default)
        elif f.fallback_key:
            result[f.key] = raw.get(f.api_key, raw.get(f.fallback_key, f.default))
        else:
            result[f.key] = raw.get(f.api_key, f.default)
    return result


def extract_event_summary(events_data: dict) -> list[dict]:
    """Extract key fields from security event response."""
    events = events_data.get("events", [])
    summaries = []
    for event in events:
        e = _parse_entry(event)
        policy = _extract_policy_info(e)
        summaries.append(_extract_fields(e, SECURITY_EVENT_FIELDS, policy))
    logger.debug("Parsed %d security events", len(summaries))
    return summaries


def extract_access_log_summary(logs_data: dict) -> list[dict]:
    """Extract key fields from access log response."""
    logs = logs_data.get("logs", logs_data.get("access_logs", []))
    summaries = []
    for log_entry in logs:
        raw = _parse_entry(log_entry)
        policy = _extract_policy_info(raw)
        summaries.append(_extract_fields(raw, ACCESS_LOG_FIELDS, policy))
    logger.debug("Parsed %d access logs", len(summaries))
    return summaries
