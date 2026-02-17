"""
Context-aware troubleshooting hints based on security event and access log data.

Returns structured `Finding` objects grouped by security event. Related
symptoms (action, response code, OAS, JWT, etc.) are merged into a single
finding so the reader sees one card per root cause.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

__all__ = ["Finding", "generate_findings", "findings_to_markdown"]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single grouped troubleshooting finding."""

    severity: str           # "error" | "warning" | "info"
    title: str              # short headline
    summary: str            # one-liner explanation
    details: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def generate_findings(
    sec_events: list[dict],
    access_logs: list[dict],
) -> list[Finding]:
    """Generate deduplicated, event-grouped findings from event data."""
    findings: list[Finding] = []

    if not sec_events and not access_logs:
        findings.append(Finding(
            severity="info",
            title="No Data",
            summary="No events found for the given search criteria.",
            recommendations=[
                "Verify the search criteria and that the search window is wide enough.",
                "Check that the namespace and load balancer name match your configuration.",
                "Security event logging may need to be enabled on the HTTP Load Balancer.",
            ],
        ))
        return findings

    # ------------------------------------------------------------------
    # Phase 1: Build one finding per unique (event_name, action) pair.
    # All related symptoms are merged into the same finding.
    # ------------------------------------------------------------------
    seen_event_keys: set[tuple[str, str]] = set()
    seen_global: set[str] = set()           # for cross-event dedup (waf_monitor, etc.)
    req_ids_covered: set[str] = set()       # track which req_ids have a finding

    for evt in sec_events:
        event_name = str(evt.get("sec_event_name", ""))
        action = str(evt.get("action", "")).lower()
        key = (event_name, action)
        if key in seen_event_keys:
            continue
        seen_event_keys.add(key)

        # Count occurrences
        count = sum(
            1 for e in sec_events
            if e.get("sec_event_name") == event_name
            and str(e.get("action", "")).lower() == action
        )
        count_label = f" ({count}x)" if count > 1 else ""

        # Collect req_ids for this event group
        for e in sec_events:
            if e.get("sec_event_name") == event_name and str(e.get("action", "")).lower() == action:
                rid = e.get("req_id", "")
                if rid and rid != "N/A":
                    req_ids_covered.add(rid)

        waf_mode = str(evt.get("waf_mode", "")).lower()
        rsp_code = str(evt.get("response_code", ""))
        event_type = str(evt.get("sec_event_type", "")).lower()
        jwt_status = str(evt.get("jwt_status", "")).lower()
        oas_action = str(evt.get("oas_validation_action", "")).upper()

        # --- Determine severity and title ---
        if "block" in action or "deny" in action:
            severity = "error"
            title = f"Blocked: {event_name}{count_label}"
            summary = "Request blocked by security policy."
        elif "report" in action:
            severity = "warning"
            title = f"Reported: {event_name}{count_label}"
            summary = "Logged but NOT blocked (action=Report)."
        else:
            severity = "info"
            title = f"{event_name}{count_label}"
            summary = f"Action: {evt.get('action', 'N/A')}"

        details: list[str] = []
        recommendations: list[str] = []

        # --- Core event info ---
        details.append(f"Event: `{event_name}` | Type: `{evt.get('sec_event_type')}`")
        details.append(f"Action: `{evt.get('action')}` | Response code: `{rsp_code}`")

        policy = evt.get("policy_name", "N/A")
        if policy != "N/A":
            details.append(f"Policy: `{policy}`")
        policy_rule = evt.get("policy_rule", "N/A")
        if policy_rule != "N/A":
            details.append(f"Policy rule: `{policy_rule}`")

        # --- Blocked specifics ---
        if "block" in action or "deny" in action:
            if "report" in action:
                pass  # hybrid — handled above
            if evt.get("rule_hits") and evt["rule_hits"] != "N/A":
                recommendations.append("Review WAF rule hits to identify which signature triggered.")
                recommendations.append("If false positive, consider adding an exclusion rule.")

            if "report" not in action:
                recommendations.append("This event would block if the policy/feature is switched from Report to Block mode."
                                       if "monitor" in waf_mode else
                                       "Review security policy to determine if this block is expected.")

        # --- Reported specifics ---
        if "report" in action and "block" not in action:
            recommendations.append(
                "This event would block if the policy/feature is switched from Report to Block mode."
            )

        # --- Response code ---
        if rsp_code == "403":
            details.append("HTTP 403 Forbidden — request was denied.")
            recommendations.append("Check service policies and WAF rules.")
        elif rsp_code == "429":
            details.append("HTTP 429 Rate Limited — request was throttled.")
            recommendations.append("Review rate limiting configuration.")
        elif rsp_code.startswith("5"):
            details.append(f"HTTP {rsp_code} — origin returned a server error.")
            recommendations.append("Check origin server health and connectivity.")

        # --- OAS / OpenAPI ---
        if "openapi" in event_name.lower() or "oas" in event_type or "fallthrough" in event_name.lower():
            oas_paths = sorted(set(
                e.get("path", "?") for e in sec_events
                if "openapi" in str(e.get("sec_event_name", "")).lower()
                or "fallthrough" in str(e.get("sec_event_name", "")).lower()
            ))
            details.append(f"OpenAPI validation — request did not match any path in the spec.")
            if oas_action and oas_action != "N/A":
                details.append(f"OAS validation action: `{oas_action}`")
            details.append(f"Affected path(s): {', '.join(f'`{p}`' for p in oas_paths)}")
            recommendations.append("Add the path to the OpenAPI spec, or adjust the fallthrough action.")

        # --- JWT ---
        if "jwt" in event_name.lower() or ("jwt" in jwt_status and jwt_status != "n/a"):
            jwt_st = evt.get("jwt_status", "N/A")
            jwt_act = evt.get("jwt_action", "N/A")
            details.append(f"JWT status: `{jwt_st}` | JWT action: `{jwt_act}`")
            if "missing" in str(jwt_st).lower():
                recommendations.append("Client is not sending a Bearer token — check client-side auth.")
            elif "invalid" in str(jwt_st).lower() or "expired" in str(jwt_st).lower():
                recommendations.append("Verify the token issuer, audience, and signing key configuration.")
            else:
                recommendations.append("If JWT is missing: check client-side auth. If invalid: verify issuer/audience/signing key.")

        # --- WAF monitor mode ---
        if ("monitor" in waf_mode or "detect" in waf_mode) and "waf_monitor" not in seen_global:
            seen_global.add("waf_monitor")
            details.append("WAF is in monitoring/detect mode — violations are logged but NOT blocked.")
            recommendations.append("Switch to blocking mode when ready for enforcement.")

        # --- Bot ---
        bot_class = str(evt.get("bot_classification", ""))
        if "bot" in bot_class.lower():
            details.append(f"Bot classification: `{bot_class}`")
            recommendations.append("Review Bot Defense settings.")

        findings.append(Finding(
            severity=severity,
            title=title,
            summary=summary,
            details=details,
            recommendations=recommendations,
        ))

    # ------------------------------------------------------------------
    # Phase 2: Access-log-only findings (response flags, etc.)
    # Correlate to existing findings by req_id when possible.
    # ------------------------------------------------------------------
    seen_flags: set[str] = set()
    flag_explanations = {
        "UH": "No healthy upstream host — check origin pool health.",
        "UF": "Upstream connection failure.",
        "UO": "Upstream overflow (circuit breaking).",
        "NR": "No route configured — check route configuration.",
        "UT": "Upstream request timeout.",
    }
    orphan_flag_details: list[str] = []

    for log in access_logs:
        flags = str(log.get("response_flags", ""))
        if not flags or flags in ("N/A", "-") or flags in seen_flags:
            continue
        seen_flags.add(flags)

        flag_detail_lines = [
            f"`{code}`: {desc}"
            for code, desc in flag_explanations.items()
            if code in flags
        ]

        req_id = log.get("req_id", "")
        if req_id and req_id != "N/A" and req_id in req_ids_covered:
            # Attach to an existing finding that covers this req_id
            for f in findings:
                # find the first finding whose events include this req_id
                f.details.append(f"Response flags: `{flags}`")
                for line in flag_detail_lines:
                    f.details.append(f"  {line}")
                break
        else:
            # No matching security event — create a standalone finding
            findings.append(Finding(
                severity="warning",
                title="Response Flags",
                summary=f"`{flags}`",
                details=flag_detail_lines,
            ))

    # ------------------------------------------------------------------
    # Phase 3: Fallback
    # ------------------------------------------------------------------
    if not findings:
        findings.append(Finding(
            severity="info",
            title="No Issues Detected",
            summary="The request appears to have been processed normally.",
            recommendations=[
                "If you still suspect an issue, widen the search window or verify the search criteria.",
            ],
        ))

    # Sort: errors first, then warnings, then info
    severity_order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: severity_order.get(f.severity, 9))

    logger.debug("Generated %d findings", len(findings))
    return findings


# ---------------------------------------------------------------------------
# Flat markdown conversion (for markdown report)
# ---------------------------------------------------------------------------

def findings_to_markdown(findings: list[Finding]) -> list[str]:
    """Convert structured findings to flat markdown lines."""
    lines: list[str] = []
    for f in findings:
        lines.append(f"- **{f.title}**: {f.summary}")
        for d in f.details:
            lines.append(f"  - {d}")
        for r in f.recommendations:
            lines.append(f"  - *{r}*")
    return lines
