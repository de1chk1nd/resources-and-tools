"""
Data models and field schemas for F5 XC events and access logs.

Defines the canonical field set once. All parsers and report renderers
derive their behaviour from these schemas, eliminating repetition.
"""

from __future__ import annotations

from typing import Any, TypedDict

__all__ = [
    "SecurityEvent",
    "AccessLog",
    "FieldDef",
    "SECURITY_EVENT_FIELDS",
    "ACCESS_LOG_FIELDS",
]


# ---------------------------------------------------------------------------
# TypedDict models
# ---------------------------------------------------------------------------

class SecurityEvent(TypedDict, total=False):
    req_id: str
    time: str
    sec_event_name: str
    sec_event_type: str
    action: str
    severity: str
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    method: str
    authority: str
    path: str
    response_code: str
    rsp_code_class: str
    waf_mode: str
    policy_name: str
    policy_rule: str
    policy_result: str
    oas_validation_action: str
    rule_hits: Any
    bot_classification: str
    country: str
    city: str
    asn: str
    src_site: str
    tls_fingerprint: str
    user_agent: str
    vh_name: str
    app: str
    jwt_status: str
    jwt_action: str
    req_size: str
    rsp_size: str
    x_forwarded_for: str
    namespace: str


class AccessLog(TypedDict, total=False):
    req_id: str
    time: str
    src_ip: str
    src_port: str
    method: str
    authority: str
    original_authority: str
    path: str
    response_code: str
    rsp_code_class: str
    duration: str
    protocol: str
    upstream_cluster: str
    upstream_response_time: str
    response_flags: str
    user_agent: str
    country: str
    city: str
    asn: str
    src_site: str
    tls_fingerprint: str
    ja4_tls_fingerprint: str
    waf_action: str
    vh_name: str
    vh_type: str
    app: str
    has_sec_event: str
    jwt_status: str
    jwt_mode: str
    policy_name: str
    policy_result: str
    oas_validation_action: str
    req_size: str
    rsp_size: str
    rtt_upstream_seconds: str
    rtt_downstream_seconds: str
    time_to_first_downstream_tx_byte: str
    time_to_last_rx_byte: str
    x_forwarded_for: str
    namespace: str


# ---------------------------------------------------------------------------
# Field definitions — drive parsing AND rendering from ONE list
# ---------------------------------------------------------------------------

class FieldDef:
    """Describes how to extract a field from raw API data and display it."""

    __slots__ = ("key", "label", "api_key", "fallback_key", "default", "is_policy")

    def __init__(
        self,
        key: str,
        label: str,
        api_key: str | None = None,
        fallback_key: str | None = None,
        default: Any = "N/A",
        is_policy: bool = False,
    ):
        self.key = key                          # internal dict key
        self.label = label                      # display label
        self.api_key = api_key or key           # key in the raw API response
        self.fallback_key = fallback_key        # optional fallback API key
        self.default = default
        self.is_policy = is_policy              # extracted from policy_hits


# -- Security event fields --------------------------------------------------

SECURITY_EVENT_FIELDS: list[FieldDef] = [
    FieldDef("req_id",                "Request ID",          "req_id"),
    FieldDef("time",                  "Timestamp",           "time",              "@timestamp"),
    FieldDef("sec_event_name",        "Event Name",          "sec_event_name"),
    FieldDef("sec_event_type",        "Event Type",          "sec_event_type"),
    FieldDef("action",                "Action",              "action"),
    FieldDef("severity",              "Severity",            "severity"),
    FieldDef("src_ip",                "Source IP",           "src_ip"),
    FieldDef("src_port",              "Source Port",         "src_port"),
    FieldDef("dst_ip",                "Destination IP",      "dst_ip"),
    FieldDef("dst_port",              "Destination Port",    "dst_port"),
    FieldDef("method",                "Method",              "method"),
    FieldDef("authority",             "Host",                "authority",         "domain"),
    FieldDef("path",                  "Path",                "req_path"),
    FieldDef("response_code",         "Response Code",       "rsp_code"),
    FieldDef("rsp_code_class",        "Response Code Class", "rsp_code_class"),
    FieldDef("waf_mode",              "WAF Mode",            "waf_mode"),
    FieldDef("policy_name",           "Policy",              None, is_policy=True),
    FieldDef("policy_rule",           "Policy Rule",         None, is_policy=True),
    FieldDef("policy_result",         "Policy Result",       None, is_policy=True),
    FieldDef("oas_validation_action", "OAS Validation",      None, is_policy=True),
    FieldDef("rule_hits",             "WAF Rule Hits",       "waf_rule_hits",     "violations", default=[]),
    FieldDef("bot_classification",    "Bot Classification",  "bot_classification"),
    FieldDef("country",               "Country",             "country"),
    FieldDef("city",                  "City",                "city"),
    FieldDef("asn",                   "ASN",                 "asn"),
    FieldDef("src_site",              "Site",                "src_site",          "site"),
    FieldDef("tls_fingerprint",       "TLS Fingerprint",     "tls_fingerprint"),
    FieldDef("user_agent",            "User Agent",          "user_agent"),
    FieldDef("vh_name",               "Virtual Host",        "vh_name"),
    FieldDef("app",                   "App",                 "app"),
    FieldDef("jwt_status",            "JWT Status",          "jwt_status"),
    FieldDef("jwt_action",            "JWT Action",          "jwt_action"),
    FieldDef("req_size",              "Request Size",        "req_size"),
    FieldDef("rsp_size",              "Response Size",       "rsp_size"),
    FieldDef("x_forwarded_for",       "X-Forwarded-For",     "x_forwarded_for"),
    FieldDef("namespace",             "Namespace",           "namespace"),
]


# -- Access log fields ------------------------------------------------------

ACCESS_LOG_FIELDS: list[FieldDef] = [
    FieldDef("req_id",                          "Request ID",           "req_id"),
    FieldDef("time",                            "Timestamp",            "time",              "@timestamp"),
    FieldDef("src_ip",                          "Source IP",            "src_ip"),
    FieldDef("src_port",                        "Source Port",          "src_port"),
    FieldDef("method",                          "Method",              "method"),
    FieldDef("authority",                       "Host",                "authority",         "domain"),
    FieldDef("original_authority",              "Original Authority",  "original_authority"),
    FieldDef("path",                            "Path",                "req_path"),
    FieldDef("response_code",                   "Response Code",       "rsp_code"),
    FieldDef("rsp_code_class",                  "Response Code Class", "rsp_code_class"),
    FieldDef("duration",                        "Duration",            "duration"),
    FieldDef("protocol",                        "Protocol",            "protocol"),
    FieldDef("upstream_cluster",                "Upstream Cluster",    "upstream_cluster"),
    FieldDef("upstream_response_time",          "Upstream Response Time", "upstream_response_time"),
    FieldDef("response_flags",                  "Response Flags",      "response_flags"),
    FieldDef("user_agent",                      "User Agent",          "user_agent"),
    FieldDef("country",                         "Country",             "country"),
    FieldDef("city",                            "City",                "city"),
    FieldDef("asn",                             "ASN",                 "asn"),
    FieldDef("src_site",                        "Site",                "src_site",          "site"),
    FieldDef("tls_fingerprint",                 "TLS Fingerprint",     "tls_fingerprint"),
    FieldDef("ja4_tls_fingerprint",             "JA4 Fingerprint",     "ja4_tls_fingerprint"),
    FieldDef("waf_action",                      "WAF Action",          "waf_action"),
    FieldDef("vh_name",                         "Virtual Host",        "vh_name"),
    FieldDef("vh_type",                         "VH Type",             "vh_type"),
    FieldDef("app",                             "App",                 "app"),
    FieldDef("has_sec_event",                   "Has Security Event",  "has_sec_event"),
    FieldDef("jwt_status",                      "JWT Status",          "jwt_status"),
    FieldDef("jwt_mode",                        "JWT Mode",            "jwt_mode"),
    FieldDef("policy_name",                     "Policy",              None, is_policy=True),
    FieldDef("policy_result",                   "Policy Result",       None, is_policy=True),
    FieldDef("oas_validation_action",           "OAS Validation",      None, is_policy=True),
    FieldDef("req_size",                        "Request Size",        "req_size"),
    FieldDef("rsp_size",                        "Response Size",       "rsp_size"),
    FieldDef("rtt_upstream_seconds",            "RTT Upstream",        "rtt_upstream_seconds"),
    FieldDef("rtt_downstream_seconds",          "RTT Downstream",      "rtt_downstream_seconds"),
    FieldDef("time_to_first_downstream_tx_byte","TTFB",                "time_to_first_downstream_tx_byte"),
    FieldDef("time_to_last_rx_byte",            "Time to Last RX Byte","time_to_last_rx_byte"),
    FieldDef("x_forwarded_for",                 "X-Forwarded-For",     "x_forwarded_for"),
    FieldDef("namespace",                       "Namespace",           "namespace"),
]
