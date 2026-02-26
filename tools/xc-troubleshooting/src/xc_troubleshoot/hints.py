"""
Context-aware troubleshooting hints based on security event and access log data.

Uses a pluggable detector pattern: each detector is a standalone class that
inspects events/logs and returns zero or more findings. New detectors can be
added without modifying existing code.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

__all__ = [
    "Finding",
    "Detector",
    "generate_findings",
    "DETECTORS",
]

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
# Detector base class
# ---------------------------------------------------------------------------

class Detector(ABC):
    """Base class for a finding detector.

    Subclasses implement ``detect()`` which receives parsed security events
    and access logs and returns a list of findings.
    """

    @abstractmethod
    def detect(
        self,
        sec_events: list[dict],
        access_logs: list[dict],
    ) -> list[Finding]:
        ...


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def _format_attack_type(raw: str) -> str:
    """Turn 'ATTACK_TYPE_CROSS_SITE_SCRIPTING' into 'Cross-Site Scripting'."""
    if not raw:
        return ""
    name = raw.removeprefix("ATTACK_TYPE_").replace("_", " ").strip()
    return name.title() if name else ""


class SecurityEventDetector(Detector):
    """Phase 1 — one finding per unique (event_name, action) pair.

    Merges related symptoms (response code, OAS, JWT, WAF mode, bot) into a
    single finding per root cause.
    """

    def detect(self, sec_events: list[dict], access_logs: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        seen_event_keys: set[tuple[str, str]] = set()
        seen_global: set[str] = set()

        for evt in sec_events:
            event_name = str(evt.get("sec_event_name", ""))
            action = str(evt.get("action", "")).lower()
            key = (event_name, action)
            if key in seen_event_keys:
                continue
            seen_event_keys.add(key)

            count = sum(
                1 for e in sec_events
                if e.get("sec_event_name") == event_name
                and str(e.get("action", "")).lower() == action
            )
            count_label = f" ({count}x)" if count > 1 else ""

            waf_mode = str(evt.get("waf_mode", "")).lower()
            rsp_code = str(evt.get("response_code", ""))

            # --- Build a descriptive summary from WAF data ---
            _sigs = evt.get("signatures") or []
            _tcs = evt.get("threat_campaigns") or []
            _atypes = evt.get("attack_types") or []

            def _build_waf_summary() -> str:
                """One-liner explaining *why* the WAF acted."""
                parts: list[str] = []
                if _tcs:
                    tc_names = [tc.get("name", "") for tc in _tcs if isinstance(tc, dict)]
                    if tc_names:
                        parts.append(f"threat campaign: {tc_names[0]}")
                if _sigs:
                    sig_names = [s.get("name", "") for s in _sigs if isinstance(s, dict)]
                    if sig_names and not parts:
                        display = sig_names[:2]
                        more = f" (+{len(sig_names) - 2} more)" if len(sig_names) > 2 else ""
                        parts.append(f"signature: {', '.join(display)}{more}")
                if not parts and _atypes:
                    at_names = [_format_attack_type(a.get("name", "")) if isinstance(a, dict) else str(a) for a in _atypes]
                    parts.append(f"attack type: {', '.join(at_names)}")
                if parts:
                    return f"Blocked — {'; '.join(parts)}."
                return "Request blocked by security policy."

            # --- Severity and title ---
            if "block" in action or "deny" in action:
                severity = "error"
                title = f"Blocked: {event_name}{count_label}"
                summary = _build_waf_summary()
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

            # --- WAF context (signatures, threat campaigns, risk) ---
            signatures = evt.get("signatures") or []
            threat_campaigns = evt.get("threat_campaigns") or []
            attack_types = evt.get("attack_types") or []
            violation_rating = str(evt.get("violation_rating", ""))
            req_risk = str(evt.get("req_risk", ""))
            risk_reasons = evt.get("req_risk_reasons") or []
            firewall_name = str(evt.get("app_firewall_name", ""))

            if firewall_name and firewall_name != "N/A":
                details.append(f"App Firewall: `{firewall_name}`")

            if req_risk and req_risk != "N/A":
                rating_str = f" (violation rating {violation_rating}/5)" if violation_rating and violation_rating != "N/A" else ""
                details.append(f"Request risk: **{req_risk}**{rating_str}")

            if attack_types:
                names = [_format_attack_type(a.get("name", "")) if isinstance(a, dict) else str(a) for a in attack_types]
                details.append(f"Attack type(s): {', '.join(f'`{n}`' for n in names)}")

            if signatures:
                details.append(f"**WAF Signatures ({len(signatures)}):**")
                for sig in signatures:
                    if not isinstance(sig, dict):
                        continue
                    sig_name = sig.get("name", "Unknown")
                    sig_id = sig.get("id", "")
                    sig_risk = sig.get("risk", "")
                    sig_accuracy = sig.get("accuracy", "").replace("_", " ")
                    sig_context = sig.get("context", "")
                    sig_attack = _format_attack_type(sig.get("attack_type", ""))
                    parts = [f"**{sig_name}**"]
                    if sig_id:
                        parts.append(f"ID `{sig_id}`")
                    tag_parts = []
                    if sig_attack:
                        tag_parts.append(sig_attack)
                    if sig_risk:
                        tag_parts.append(f"risk={sig_risk}")
                    if sig_accuracy:
                        tag_parts.append(f"accuracy={sig_accuracy}")
                    if sig_context:
                        tag_parts.append(f"in {sig_context}")
                    if tag_parts:
                        parts.append(f"({', '.join(tag_parts)})")
                    details.append(f"  - {' — '.join(parts)}")

            if threat_campaigns:
                details.append(f"**Threat Campaigns ({len(threat_campaigns)}):**")
                for tc in threat_campaigns:
                    if not isinstance(tc, dict):
                        continue
                    tc_name = tc.get("name", "Unknown")
                    tc_attack = _format_attack_type(tc.get("attack_type", ""))
                    tc_line = f"  - **{tc_name}**"
                    if tc_attack:
                        tc_line += f" ({tc_attack})"
                    details.append(tc_line)

            if risk_reasons:
                details.append("**Risk reasons:**")
                for reason in risk_reasons:
                    details.append(f"  - {reason}")

            # --- Blocked specifics ---
            if "block" in action or "deny" in action:
                if signatures:
                    sig_ids = [s.get("id", "") for s in signatures if isinstance(s, dict) and s.get("id")]
                    if sig_ids:
                        recommendations.append(
                            f"WAF signature(s) that triggered: {', '.join(f'`{sid}`' for sid in sig_ids)}. "
                            "If false positive, add an exclusion rule for the specific signature ID(s)."
                        )
                    else:
                        recommendations.append("Review WAF rule hits. If false positive, consider adding an exclusion rule.")
                elif evt.get("rule_hits") and evt["rule_hits"] != "N/A":
                    recommendations.append("Review WAF rule hits to identify which signature triggered.")
                    recommendations.append("If false positive, consider adding an exclusion rule.")
                if threat_campaigns:
                    recommendations.append(
                        "A known threat campaign was detected. This is likely a real attack — verify before whitelisting."
                    )
                if "report" not in action:
                    recommendations.append(
                        "This event would block if the policy/feature is switched from Report to Block mode."
                        if "monitor" in waf_mode else
                        "Review security policy to determine if this block is expected."
                    )

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

            # --- WAF monitor mode (once globally) ---
            if ("monitor" in waf_mode or "detect" in waf_mode) and "waf_monitor" not in seen_global:
                seen_global.add("waf_monitor")
                details.append("WAF is in monitoring/detect mode — violations are logged but NOT blocked.")
                recommendations.append("Switch to blocking mode when ready for enforcement.")

            findings.append(Finding(
                severity=severity, title=title, summary=summary,
                details=details, recommendations=recommendations,
            ))

        return findings


class OASDetector(Detector):
    """Detect OpenAPI / OAS validation findings."""

    def detect(self, sec_events: list[dict], access_logs: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        oas_events = [
            e for e in sec_events
            if "openapi" in str(e.get("sec_event_name", "")).lower()
            or "fallthrough" in str(e.get("sec_event_name", "")).lower()
            or "oas" in str(e.get("sec_event_type", "")).lower()
        ]
        if not oas_events:
            return findings

        oas_paths = sorted(set(e.get("path", "?") for e in oas_events))
        oas_action = str(oas_events[0].get("oas_validation_action", "")).upper()
        action = str(oas_events[0].get("action", "")).lower()

        severity = "error" if ("block" in action or "deny" in action) else "warning"

        details = [
            "OpenAPI validation — request did not match any path in the spec.",
            f"Affected path(s): {', '.join(f'`{p}`' for p in oas_paths)}",
        ]
        if oas_action and oas_action != "N/A":
            details.append(f"OAS validation action: `{oas_action}`")

        findings.append(Finding(
            severity=severity,
            title=f"OpenAPI Validation ({len(oas_events)} event(s))",
            summary="Request path not found in OpenAPI spec.",
            details=details,
            recommendations=["Add the path to the OpenAPI spec, or adjust the fallthrough action."],
        ))
        return findings


class JWTDetector(Detector):
    """Detect JWT-related findings."""

    def detect(self, sec_events: list[dict], access_logs: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        jwt_events = [
            e for e in sec_events
            if "jwt" in str(e.get("sec_event_name", "")).lower()
            or ("jwt" in str(e.get("jwt_status", "")).lower()
                and str(e.get("jwt_status", "")).lower() != "n/a")
        ]
        if not jwt_events:
            return findings

        evt = jwt_events[0]
        jwt_st = str(evt.get("jwt_status", "N/A"))
        jwt_act = str(evt.get("jwt_action", "N/A"))
        action = str(evt.get("action", "")).lower()

        severity = "error" if ("block" in action or "deny" in action) else "warning"
        details = [f"JWT status: `{jwt_st}` | JWT action: `{jwt_act}`"]
        recommendations: list[str] = []

        if "missing" in jwt_st.lower():
            recommendations.append("Client is not sending a Bearer token — check client-side auth.")
        elif "invalid" in jwt_st.lower() or "expired" in jwt_st.lower():
            recommendations.append("Verify the token issuer, audience, and signing key configuration.")
        else:
            recommendations.append(
                "If JWT is missing: check client-side auth. "
                "If invalid: verify issuer/audience/signing key."
            )

        findings.append(Finding(
            severity=severity,
            title=f"JWT Issue ({len(jwt_events)} event(s))",
            summary=f"JWT status: {jwt_st}",
            details=details,
            recommendations=recommendations,
        ))
        return findings


class BotDetector(Detector):
    """Detect bot classification findings."""

    def detect(self, sec_events: list[dict], access_logs: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        bot_events = [
            e for e in sec_events
            if "bot" in str(e.get("bot_classification", "")).lower()
        ]
        if not bot_events:
            return findings

        classifications = sorted(set(
            str(e.get("bot_classification", "")) for e in bot_events
        ))
        findings.append(Finding(
            severity="warning",
            title=f"Bot Detection ({len(bot_events)} event(s))",
            summary=f"Classification: {', '.join(classifications)}",
            details=[f"Bot classification: `{c}`" for c in classifications],
            recommendations=["Review Bot Defense settings."],
        ))
        return findings


class ResponseFlagDetector(Detector):
    """Phase 2 — Detect response flags from access logs."""

    FLAG_EXPLANATIONS = {
        "UH": "No healthy upstream host — check origin pool health.",
        "UF": "Upstream connection failure.",
        "UO": "Upstream overflow (circuit breaking).",
        "NR": "No route configured — check route configuration.",
        "UT": "Upstream request timeout.",
        "DC": "Downstream connection termination.",
        "LH": "Local service failed health check.",
        "RL": "Rate limited.",
    }

    def detect(self, sec_events: list[dict], access_logs: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        seen_flags: set[str] = set()

        for log in access_logs:
            flags = str(log.get("response_flags", ""))
            if not flags or flags in ("N/A", "-") or flags in seen_flags:
                continue
            seen_flags.add(flags)

            flag_details = [
                f"`{code}`: {desc}"
                for code, desc in self.FLAG_EXPLANATIONS.items()
                if code in flags
            ]

            if flag_details:
                findings.append(Finding(
                    severity="warning",
                    title="Response Flags",
                    summary=f"`{flags}`",
                    details=flag_details,
                ))

        return findings


class NoDataDetector(Detector):
    """Fallback — emitted when no events or logs are found at all."""

    def detect(self, sec_events: list[dict], access_logs: list[dict]) -> list[Finding]:
        if sec_events or access_logs:
            return []
        return [Finding(
            severity="info",
            title="No Data",
            summary="No events found for the given search criteria.",
            recommendations=[
                "Verify the search criteria and that the search window is wide enough.",
                "Try narrowing with --namespace if using the default (system) namespace, or widen with --hours.",
                "Security event logging may need to be enabled on the HTTP Load Balancer.",
            ],
        )]


class NoIssuesDetector(Detector):
    """Fallback — emitted when data exists but no other detector found issues."""

    def detect(self, sec_events: list[dict], access_logs: list[dict]) -> list[Finding]:
        # Only used as a final fallback — handled in generate_findings().
        return []


# ---------------------------------------------------------------------------
# Detector registry — order matters (NoData checked first, fallback last)
# ---------------------------------------------------------------------------

DETECTORS: list[Detector] = [
    NoDataDetector(),
    SecurityEventDetector(),
    OASDetector(),
    JWTDetector(),
    BotDetector(),
    ResponseFlagDetector(),
]


# ---------------------------------------------------------------------------
# Generator — runs all detectors, deduplicates, sorts
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


def generate_findings(
    sec_events: list[dict],
    access_logs: list[dict],
) -> list[Finding]:
    """Generate deduplicated, sorted findings by running all registered detectors."""
    findings: list[Finding] = []
    seen_titles: set[str] = set()

    for detector in DETECTORS:
        for finding in detector.detect(sec_events, access_logs):
            # Deduplicate by title (OAS/JWT may overlap with SecurityEventDetector)
            if finding.title in seen_titles:
                continue
            seen_titles.add(finding.title)
            findings.append(finding)

    # Fallback: if no issues were found but data exists
    if not findings and (sec_events or access_logs):
        findings.append(Finding(
            severity="info",
            title="No Issues Detected",
            summary="The request appears to have been processed normally.",
            recommendations=[
                "If you still suspect an issue, widen the search window or verify the search criteria.",
            ],
        ))

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
    logger.debug("Generated %d findings from %d detectors", len(findings), len(DETECTORS))
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
