"""
HTTP Load Balancer configuration parser — extract enabled security features.

Fetches and parses the HTTP Load Balancer configuration from the F5 XC API
to identify which security services are enabled (WAF, Bot Defense, API
Protection, DDoS, Service Policies, etc.).

The LB name is derived from the ``vh_name`` field in access logs / security
events (stripping the ``ves-io-http-loadbalancer-`` prefix) or from the
``--load-balancer`` CLI parameter.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

__all__ = [
    "LBConfig",
    "SecurityService",
    "UserIdentification",
    "parse_lb_config",
    "parse_user_identification",
    "parse_user_field",
    "enrich_user_identification_from_events",
    "derive_lb_name",
]

logger = logging.getLogger(__name__)

# ves-io-http-loadbalancer-<name> → <name>
_VH_PREFIX = "ves-io-http-loadbalancer-"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SecurityService:
    """A single security service detected in the LB configuration."""

    name: str               # display name (e.g. "Web Application Firewall")
    short: str              # short abbreviation (e.g. "WAF")
    enabled: bool = False   # whether the feature is enabled
    mode: str = ""          # e.g. "blocking", "monitoring", "custom"
    detail: str = ""        # additional detail (policy name, profile name, etc.)
    icon: str = ""          # icon identifier for SVG rendering


@dataclass
class UserIdentification:
    """Resolved user identification policy — how sessions are identified."""

    name: str = ""
    namespace: str = ""
    rules: list[str] = field(default_factory=list)   # e.g. ["TLS Fingerprint", "Client IP", "Cookie: session_id"]
    raw: dict = field(default_factory=dict)


@dataclass
class LBConfig:
    """Parsed HTTP Load Balancer configuration with security feature summary."""

    lb_name: str = ""
    namespace: str = ""
    domains: list[str] = field(default_factory=list)
    lb_type: str = ""               # "HTTP" or "HTTPS"
    advertise_policy: str = ""      # "Internet", "Site", "VIP" etc.
    origin_pools: list[str] = field(default_factory=list)
    services: list[SecurityService] = field(default_factory=list)
    raw_config: dict = field(default_factory=dict)
    error: str = ""                 # non-empty if fetch/parse failed
    # User identification reference from LB spec (name + namespace)
    user_id_ref: dict = field(default_factory=dict)
    # Resolved user identification policy (fetched separately)
    user_identification: UserIdentification | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def derive_lb_name(
    vh_name: str = "",
    load_balancer: str = "",
) -> str:
    """Derive the HTTP LB object name from vh_name or --load-balancer.

    vh_name looks like ``ves-io-http-loadbalancer-<name>``.
    --load-balancer is the raw name passed by the user.
    """
    if load_balancer:
        # User-supplied — may or may not have prefix
        if load_balancer.startswith(_VH_PREFIX):
            return load_balancer[len(_VH_PREFIX):]
        return load_balancer

    if vh_name:
        if vh_name.startswith(_VH_PREFIX):
            return vh_name[len(_VH_PREFIX):]
        # Might be the raw name already
        return vh_name

    return ""


def derive_lb_namespace(
    events: list[dict],
    access_logs: list[dict],
    default_ns: str = "",
) -> str:
    """Derive the LB namespace from event/log data.

    The namespace in events/logs is the *actual* namespace (not "system").
    """
    for entry in events + access_logs:
        ns = str(entry.get("namespace", "") or "")
        if ns and ns.lower() not in ("", "n/a", "none", "system"):
            return ns
    return default_ns


def _first_vh_name(events: list[dict], access_logs: list[dict]) -> str:
    """Extract the first non-empty vh_name from events or logs."""
    for entry in events + access_logs:
        vh = str(entry.get("vh_name", "") or "")
        if vh and vh.lower() not in ("", "n/a", "none"):
            return vh
    return ""


# ---------------------------------------------------------------------------
# Config parser
# ---------------------------------------------------------------------------

def _get_nested(d: dict, *keys, default="") -> str:
    """Safely traverse nested dicts."""
    current = d
    for k in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(k, {})
    if current is None or current == {}:
        return default
    return str(current) if not isinstance(current, (dict, list)) else default


def _get_nested_dict(d: dict, *keys) -> dict:
    """Safely traverse nested dicts, returning a dict."""
    current = d
    for k in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(k, {})
    return current if isinstance(current, dict) else {}


def parse_lb_config(raw: dict) -> LBConfig:
    """Parse a raw HTTP LB config response into an LBConfig.

    ``raw`` is the JSON response from
    ``GET /api/config/namespaces/{ns}/http_loadbalancers/{name}``
    """
    if not raw or "spec" not in raw:
        return LBConfig(error="No spec in LB config response")

    spec = raw.get("spec", {})
    metadata = raw.get("metadata", {})

    cfg = LBConfig(
        lb_name=metadata.get("name", ""),
        namespace=metadata.get("namespace", ""),
        raw_config=raw,
    )

    # --- Domains ---
    domains = spec.get("domains", [])
    cfg.domains = [str(d) for d in domains] if isinstance(domains, list) else []

    # --- LB type (HTTP vs HTTPS) ---
    # The XC API uses empty objects {} to indicate "enabled", so check is not None
    if "https" in spec or "https_auto_cert" in spec:
        cfg.lb_type = "HTTPS"
    else:
        cfg.lb_type = "HTTP"

    # --- Advertise policy ---
    if "advertise_on_public" in spec:
        cfg.advertise_policy = "Internet (Public)"
    elif "advertise_on_public_default_vip" in spec:
        cfg.advertise_policy = "Internet (Default VIP)"
    elif "advertise_custom" in spec:
        cfg.advertise_policy = "Custom"
    elif "do_not_advertise" in spec:
        cfg.advertise_policy = "Not Advertised"
    else:
        cfg.advertise_policy = "Default"

    # --- Origin pools ---
    default_pool = spec.get("default_route_pools", [])
    if isinstance(default_pool, list):
        for pool in default_pool:
            if isinstance(pool, dict):
                pool_ref = pool.get("pool", {})
                if isinstance(pool_ref, dict):
                    name = pool_ref.get("name", "")
                    ns = pool_ref.get("namespace", "")
                    if name:
                        cfg.origin_pools.append(f"{ns}/{name}" if ns else name)

    # --- Security services ---
    services: list[SecurityService] = []

    # 1. WAF / App Firewall
    waf_svc = SecurityService(name="Web Application Firewall", short="WAF", icon="waf")
    app_fw = spec.get("app_firewall")
    if "disable_waf" in spec:
        waf_svc.enabled = False
        waf_svc.mode = "Disabled"
    elif app_fw is not None and isinstance(app_fw, dict):
        fw_name = app_fw.get("name", "")
        fw_ns = app_fw.get("namespace", "")
        waf_svc.enabled = True
        waf_svc.detail = f"{fw_ns}/{fw_name}" if fw_ns else fw_name
        waf_exclusion = spec.get("waf_exclusion_rules", [])
        waf_svc.mode = "Enabled"
        if waf_exclusion:
            waf_svc.mode += f" ({len(waf_exclusion)} exclusion rules)"
    services.append(waf_svc)

    # 2. Bot Defense
    bot_svc = SecurityService(name="Bot Defense", short="Bot", icon="bot")
    bot_defense = spec.get("bot_defense")
    if "disable_bot_defense" in spec:
        bot_svc.enabled = False
        bot_svc.mode = "Disabled"
    elif bot_defense is not None and isinstance(bot_defense, dict):
        if "disable" in bot_defense:
            bot_svc.enabled = False
            bot_svc.mode = "Disabled"
        else:
            regional = bot_defense.get("regional_endpoint", "")
            policy = bot_defense.get("policy", {})
            bot_svc.enabled = True
            if isinstance(policy, dict) and policy.get("name"):
                bot_svc.detail = policy["name"]
            if regional:
                bot_svc.mode = f"Regional: {regional}"
            else:
                bot_svc.mode = "Enabled"
    services.append(bot_svc)

    # 3. API Protection / API Definition
    #    The XC API may return empty keys like api_protection_rules: {} even
    #    when not configured.  Check disable_api_definition first, and verify
    #    that enable-style values are non-empty before flagging as active.
    api_svc = SecurityService(name="API Protection", short="API Prot.", icon="api")
    if "disable_api_definition" in spec and "disable_api_testing" in spec:
        # Both explicitly disabled → feature is off
        api_svc.enabled = False
        api_svc.mode = "Disabled"
    elif "api_definition" in spec and "disable_api_definition" not in spec:
        api_def = spec.get("api_definition") or {}
        api_name = api_def.get("name", "") if isinstance(api_def, dict) else ""
        if api_name:
            api_svc.enabled = True
            api_svc.detail = api_name
            api_svc.mode = "API Definition"
        else:
            api_svc.enabled = False
            api_svc.mode = "Disabled"
    elif "api_definitions" in spec and "disable_api_definition" not in spec:
        api_defs = spec.get("api_definitions") or {}
        api_name = api_defs.get("name", "") if isinstance(api_defs, dict) else ""
        if api_name:
            api_svc.enabled = True
            api_svc.detail = api_name
            api_svc.mode = "API Definition"
        else:
            api_svc.enabled = False
            api_svc.mode = "Disabled"
    elif "api_protection_rules" in spec:
        api_prot = spec.get("api_protection_rules")
        # Only flag as enabled if there are actual rules configured
        has_rules = False
        if isinstance(api_prot, dict):
            rules = api_prot.get("rules", api_prot.get("api_groups_rules", []))
            has_rules = bool(rules)
        elif isinstance(api_prot, list):
            has_rules = bool(api_prot)
        if has_rules:
            api_svc.enabled = True
            api_svc.mode = "Protection Rules"
        else:
            api_svc.enabled = False
            api_svc.mode = "Disabled"
    else:
        api_svc.enabled = False
        api_svc.mode = "Disabled"
    services.append(api_svc)

    # 4. API Discovery
    disc_svc = SecurityService(name="API Discovery", short="API Disc.", icon="discovery")
    if "enable_api_discovery" in spec or "api_discovery" in spec:
        disc_svc.enabled = True
        api_disc = spec.get("enable_api_discovery") or spec.get("api_discovery") or {}
        if isinstance(api_disc, dict) and "enable_learn_from_redirect_traffic" in api_disc:
            disc_svc.mode = "Enabled (incl. redirects)"
        else:
            disc_svc.mode = "Enabled"
    elif "disable_api_discovery" in spec:
        disc_svc.enabled = False
        disc_svc.mode = "Disabled"
    services.append(disc_svc)

    # 5. L7 DDoS / DDoS Detection & Mitigation
    ddos_svc = SecurityService(name="DDoS Detection & Mitigation", short="DDoS", icon="ddos")
    ddos_mitigation = spec.get("ddos_mitigation_rules", [])
    enable_ddos = "enable_ddos_detection" in spec
    slow_ddos = spec.get("slow_ddos_mitigation")
    # L7 DDoS protection — may be nested under l7_ddos_protection or as
    # top-level l7_ddos_action_* keys (both variants exist in different API versions)
    l7_prot = spec.get("l7_ddos_protection")
    l7_action_top = (
        "l7_ddos_action_default" in spec
        or "l7_ddos_action_block" in spec
        or "l7_ddos_action_js_challenge" in spec
    )
    has_l7 = l7_action_top or (l7_prot is not None and isinstance(l7_prot, dict))
    has_slow = slow_ddos is not None and isinstance(slow_ddos, dict) and "disable" not in slow_ddos
    if enable_ddos or (isinstance(ddos_mitigation, list) and ddos_mitigation) or has_l7 or has_slow:
        ddos_svc.enabled = True
        parts = []
        if enable_ddos:
            parts.append("Detection")
        if isinstance(ddos_mitigation, list) and ddos_mitigation:
            parts.append(f"{len(ddos_mitigation)} mitigation rule(s)")
        # L7 DDoS — nested structure
        if isinstance(l7_prot, dict):
            if "mitigation_block" in l7_prot:
                parts.append("L7 DDoS: Block")
            elif "mitigation_js_challenge" in l7_prot:
                parts.append("L7 DDoS: JS Challenge")
            elif "mitigation_default" in l7_prot:
                parts.append("L7 DDoS: Default")
            else:
                parts.append("L7 DDoS Protection")
        # L7 DDoS — top-level keys (older API style)
        elif "l7_ddos_action_block" in spec:
            parts.append("L7 DDoS: Block")
        elif "l7_ddos_action_js_challenge" in spec:
            parts.append("L7 DDoS: JS Challenge")
        elif "l7_ddos_action_default" in spec:
            parts.append("L7 DDoS: Default")
        if has_slow:
            parts.append("Slow DDoS mitigation")
        ddos_svc.mode = "; ".join(parts) if parts else "Enabled"
    else:
        ddos_svc.enabled = False
        ddos_svc.mode = "Disabled"
    services.append(ddos_svc)

    # 6. Service Policies
    sp_svc = SecurityService(name="Service Policies", short="Svc Pol.", icon="policy")
    active_sp = spec.get("active_service_policies")
    if "no_service_policies" in spec:
        sp_svc.enabled = False
        sp_svc.mode = "Disabled"
    elif active_sp is not None and isinstance(active_sp, dict):
        policies = active_sp.get("policies", [])
        if isinstance(policies, list) and policies:
            names = []
            for p in policies:
                if isinstance(p, dict):
                    names.append(p.get("name", "?"))
            sp_svc.enabled = True
            sp_svc.detail = ", ".join(names[:3])
            if len(names) > 3:
                sp_svc.detail += f" (+{len(names) - 3} more)"
            sp_svc.mode = f"{len(policies)} policy/ies"
        else:
            sp_svc.enabled = False
            sp_svc.mode = "No policies configured"
    elif "service_policies_from_namespace" in spec:
        sp_svc.enabled = True
        sp_svc.mode = "From namespace"
    services.append(sp_svc)

    # 7. Rate Limiting
    rl_svc = SecurityService(name="Rate Limiting", short="Rate Lim.", icon="ratelimit")
    rate_limit = spec.get("rate_limit")
    if "disable_rate_limit" in spec:
        rl_svc.enabled = False
        rl_svc.mode = "Disabled"
    elif rate_limit is not None and isinstance(rate_limit, dict) and "disable" not in rate_limit:
        rl_svc.enabled = True
        rate_limiter = rate_limit.get("rate_limiter")
        if isinstance(rate_limiter, dict) and rate_limiter.get("name"):
            rl_svc.detail = rate_limiter["name"]
        burst_mult = rate_limit.get("burst_multiplier", "")
        if burst_mult:
            rl_svc.mode = f"Burst multiplier: {burst_mult}"
        else:
            rl_svc.mode = "Enabled"
    else:
        rl_svc.enabled = False
        rl_svc.mode = "Disabled"
    services.append(rl_svc)

    # 8. IP Reputation
    ip_rep_svc = SecurityService(name="IP Reputation", short="IP Rep.", icon="ipreputation")
    if "enable_ip_reputation" in spec:
        ip_rep_svc.enabled = True
        ip_rep_cfg = spec.get("enable_ip_reputation", {})
        if isinstance(ip_rep_cfg, dict):
            cats = ip_rep_cfg.get("ip_threat_categories", [])
            if isinstance(cats, list) and cats:
                ip_rep_svc.mode = f"Enabled ({len(cats)} categories)"
            else:
                ip_rep_svc.mode = "Enabled"
        else:
            ip_rep_svc.mode = "Enabled"
    elif "disable_ip_reputation" in spec:
        ip_rep_svc.enabled = False
        ip_rep_svc.mode = "Disabled"
    services.append(ip_rep_svc)

    # 9. Malicious User Detection + User Identification reference
    mu_svc = SecurityService(name="Malicious User Detection", short="Mal. User", icon="maluser")
    user_id = spec.get("user_identification")
    if "enable_malicious_user_detection" in spec:
        mu_svc.enabled = True
        mu_svc.mode = "Enabled"
        if isinstance(user_id, dict) and user_id.get("name"):
            uid_ns = user_id.get("namespace", "")
            uid_name = user_id["name"]
            mu_svc.detail = f"User ID: {uid_ns}/{uid_name}" if uid_ns else f"User ID: {uid_name}"
            cfg.user_id_ref = user_id
    elif "disable_malicious_user_detection" in spec:
        mu_svc.enabled = False
        mu_svc.mode = "Disabled"
    services.append(mu_svc)

    # 10. CORS Policy
    cors_svc = SecurityService(name="CORS Policy", short="CORS", icon="cors")
    cors = spec.get("cors_policy")
    if cors is not None and isinstance(cors, dict):
        cors_svc.enabled = True
        origins = cors.get("allow_origins", [])
        if isinstance(origins, list) and origins:
            cors_svc.mode = f"{len(origins)} origin(s)"
        else:
            cors_svc.mode = "Configured"
    else:
        cors_svc.enabled = False
        cors_svc.mode = "Disabled"
    services.append(cors_svc)

    # 11. Trusted Client Rules
    tc_svc = SecurityService(name="Trusted Client Rules", short="Trusted", icon="trusted")
    trusted = spec.get("trusted_clients", [])
    if isinstance(trusted, list) and trusted:
        tc_svc.enabled = True
        tc_svc.mode = f"{len(trusted)} rule(s)"
    else:
        tc_svc.enabled = False
        tc_svc.mode = "Disabled"
    services.append(tc_svc)

    # 12. Client-Side Defense (CSP)
    csd_svc = SecurityService(name="Client-Side Defense", short="CSD", icon="csd")
    if "enable_client_side_defense" in spec:
        csd_svc.enabled = True
        csd_svc.mode = "Enabled"
    elif "disable_client_side_defense" in spec:
        csd_svc.enabled = False
        csd_svc.mode = "Disabled"
    services.append(csd_svc)

    # 13. Data Guard (Sensitive Data)
    dg_svc = SecurityService(name="Data Guard", short="Data Guard", icon="dataguard")
    data_guard = spec.get("data_guard_rules", [])
    if "enable_data_guard" in spec:
        dg_svc.enabled = True
        dg_svc.mode = "Enabled"
    elif isinstance(data_guard, list) and data_guard:
        dg_svc.enabled = True
        dg_svc.mode = f"{len(data_guard)} rule(s)"
    else:
        dg_svc.enabled = False
        dg_svc.mode = "Disabled"
    services.append(dg_svc)

    # 14. GraphQL Inspection
    gql_svc = SecurityService(name="GraphQL Inspection", short="GraphQL", icon="graphql")
    gql_rules = spec.get("graphql_rules", [])
    if isinstance(gql_rules, list) and gql_rules:
        gql_svc.enabled = True
        gql_svc.mode = f"{len(gql_rules)} rule(s)"
    else:
        gql_svc.enabled = False
        gql_svc.mode = "Disabled"
    services.append(gql_svc)

    # 15. Malware Protection
    mal_svc = SecurityService(name="Malware Protection", short="Malware", icon="malware")
    if "disable_malware_protection" in spec:
        mal_svc.enabled = False
        mal_svc.mode = "Disabled"
    elif "malware_protection_settings" in spec:
        mal_svc.enabled = True
        mp_settings = spec.get("malware_protection_settings", {})
        if isinstance(mp_settings, dict):
            mp_rules = mp_settings.get("malware_protection_rules", [])
            if isinstance(mp_rules, list) and mp_rules:
                mal_svc.mode = f"Enabled ({len(mp_rules)} rule(s))"
            else:
                mal_svc.mode = "Enabled"
        else:
            mal_svc.mode = "Enabled"
    elif "enable_malware_protection" in spec:
        mal_svc.enabled = True
        mal_svc.mode = "Enabled"
    else:
        mal_svc.enabled = False
        mal_svc.mode = "Not configured"
    services.append(mal_svc)

    # 16. Threat Mesh
    tm_svc = SecurityService(name="Threat Mesh", short="Threat Mesh", icon="threatmesh")
    if "disable_threat_mesh" in spec:
        tm_svc.enabled = False
        tm_svc.mode = "Disabled"
    elif "enable_threat_mesh" in spec or "threat_mesh" in spec:
        tm_svc.enabled = True
        tm_svc.mode = "Enabled"
    else:
        tm_svc.enabled = False
        tm_svc.mode = "Not configured"
    services.append(tm_svc)

    # 17. Challenge (JS Challenge / Captcha)
    ch_svc = SecurityService(name="Challenge Rules", short="Challenge", icon="challenge")
    if "no_challenge" in spec or "disable_challenge" in spec:
        ch_svc.enabled = False
        ch_svc.mode = "Disabled"
    elif "enable_challenge" in spec:
        ch_svc.enabled = True
        enable_challenge = spec.get("enable_challenge", {})
        if isinstance(enable_challenge, dict):
            if "default_js_challenge_parameters" in enable_challenge:
                ch_svc.mode = "JS Challenge (default)"
            elif "default_captcha_challenge_parameters" in enable_challenge:
                ch_svc.mode = "Captcha (default)"
            elif "default_mitigation_settings" in enable_challenge:
                ch_svc.mode = "Default mitigation"
            else:
                ch_svc.mode = "Enabled"
        else:
            ch_svc.mode = "Enabled"
    elif "js_challenge" in spec or "captcha_challenge" in spec or "policy_based_challenge" in spec:
        ch_svc.enabled = True
        if "js_challenge" in spec:
            ch_svc.mode = "JS Challenge"
        elif "captcha_challenge" in spec:
            ch_svc.mode = "Captcha"
        else:
            ch_svc.mode = "Policy-based"
    else:
        ch_svc.enabled = False
        ch_svc.mode = "Not configured"
    services.append(ch_svc)

    # 18. Sensitive Data Policy / Protected Cookies
    sd_svc = SecurityService(name="Sensitive Data Policy", short="Sensitive", icon="dataguard")
    protected_cookies = spec.get("protected_cookies", [])
    has_sd_policy = "default_sensitive_data_policy" in spec or "sensitive_data_policy" in spec
    if has_sd_policy or (isinstance(protected_cookies, list) and protected_cookies):
        sd_svc.enabled = True
        parts = []
        if has_sd_policy:
            parts.append("Policy active")
        if isinstance(protected_cookies, list) and protected_cookies:
            parts.append(f"{len(protected_cookies)} protected cookie(s)")
        sd_svc.mode = "; ".join(parts)
    else:
        sd_svc.enabled = False
        sd_svc.mode = "Disabled"
    services.append(sd_svc)

    cfg.services = services
    return cfg


# ---------------------------------------------------------------------------
# User Identification parser
# ---------------------------------------------------------------------------

# Known XC spec keys for identifier rules and their display labels
_UID_RULE_MAP = {
    "client_ip":                       "Client IP",
    "tls_fingerprint":                 "TLS Fingerprint",
    "ip_and_tls":                      "Client IP + TLS Fingerprint",
    "client_ip_and_tls_fingerprint":   "Client IP + TLS Fingerprint",
    "ja3_fingerprint":                 "JA3 Fingerprint",
    "ja4_fingerprint":                 "JA4 Fingerprint",
    "tls_ja3_fingerprint":             "JA3 Fingerprint",
}

# Spec-level keys that indicate a specific identification mechanism.
# Includes ``none`` which is used by ATI Device ID policies (JS-based).
_SPEC_IDENTIFIER_MAP = {
    **_UID_RULE_MAP,
    "none":                            "None (JS-based / ATI Device ID)",
}

# Internal metadata keys to skip when scanning spec for unknown identifier keys
_SPEC_SKIP_KEYS = frozenset({
    "rules", "cookie_identifier", "cookie", "header_identifier",
    "http_header_name", "gc_spec", "description", "disabled",
})


def _extract_rule_from_dict(d: dict) -> str | None:
    """Try to extract a human-readable identifier label from a dict.

    Returns the label string, or None if no known pattern was found.
    """
    for key, label in _UID_RULE_MAP.items():
        if key in d:
            return label
    if "cookie" in d:
        cookie = d["cookie"]
        if isinstance(cookie, dict):
            return f"Cookie: {cookie.get('name', '?')}"
        return f"Cookie: {cookie}"
    if "header" in d:
        header = d["header"]
        if isinstance(header, dict):
            return f"Header: {header.get('name', '?')}"
        return f"Header: {header}"
    if "query_param" in d:
        return "Query Parameter"
    if "http_header_name" in d:
        return f"Header: {d['http_header_name']}"
    return None


def parse_user_identification(raw: dict) -> UserIdentification:
    """Parse a raw user_identification config response.

    ``raw`` is the JSON response from
    ``GET /api/config/namespaces/{ns}/user_identifications/{name}``

    The spec typically contains one of these identifier rule patterns:
    - ``rules``: a list of individual identifier objects, each with keys like
      ``client_identifier`` containing ``ip_and_tls``, ``tls_fingerprint``, etc.
    - Top-level shorthand keys like ``tls_fingerprint: {}``, ``client_ip: {}``
    - For ATI Device ID policies the spec may have ``none: {}`` or be
      effectively empty (identification is handled via JS injection).
    """
    uid = UserIdentification()
    if not raw:
        return uid

    metadata = raw.get("metadata", {})
    uid.name = metadata.get("name", "")
    uid.namespace = metadata.get("namespace", "")
    uid.raw = raw

    spec = raw.get("spec", {})
    if not isinstance(spec, dict):
        return uid

    rules: list[str] = []

    # Pattern 1: explicit rules list
    rule_list = spec.get("rules", [])
    if isinstance(rule_list, list):
        for rule in rule_list:
            if not isinstance(rule, dict):
                continue
            # Each rule may have a client_identifier sub-object
            client_id = rule.get("client_identifier", rule)
            if isinstance(client_id, dict):
                label = _extract_rule_from_dict(client_id)
                if label:
                    rules.append(label)

    # Pattern 2: top-level shorthand keys in spec
    if not rules:
        for key, label in _SPEC_IDENTIFIER_MAP.items():
            if key in spec:
                rules.append(label)
        # Also check for cookie-based identification
        if "cookie_identifier" in spec or "cookie" in spec:
            cookie_cfg = spec.get("cookie_identifier") or spec.get("cookie", {})
            if isinstance(cookie_cfg, dict) and cookie_cfg.get("name"):
                rules.append(f"Cookie: {cookie_cfg['name']}")
            else:
                rules.append("Cookie")
        if "header_identifier" in spec or "http_header_name" in spec:
            hdr = spec.get("header_identifier") or spec.get("http_header_name", "")
            if isinstance(hdr, dict):
                rules.append(f"Header: {hdr.get('name', '?')}")
            elif hdr:
                rules.append(f"Header: {hdr}")

    # Pattern 3: fallback — inspect remaining spec keys to surface unknown
    # identifier types rather than showing "no identifiers resolved".
    if not rules:
        unknown_keys = [
            k for k in spec
            if k not in _SPEC_SKIP_KEYS and k not in _SPEC_IDENTIFIER_MAP
        ]
        if unknown_keys:
            for k in unknown_keys:
                # Present the raw key in a readable format
                readable = k.replace("_", " ").title()
                rules.append(readable)
            logger.debug(
                "User ID %s/%s: no known identifier pattern; "
                "raw spec keys surfaced: %s",
                uid.namespace, uid.name, unknown_keys,
            )

    uid.rules = rules
    return uid


# ---------------------------------------------------------------------------
# Runtime user identifier extraction (from event/log ``user`` field)
# ---------------------------------------------------------------------------

def parse_user_field(user_value: str) -> dict[str, str]:
    """Parse the ``user`` field from a security event or access log.

    F5 XC encodes the active identifier in the ``user`` field using the
    format ``<Type>-<Name>-<Value>`` (or variations).  Known patterns:

    - ``Cookie-<cookie_name>-<cookie_value>``
    - ``IP-<ip_address>``
    - ``TLSFingerprint-<hash>``
    - ``Header-<header_name>-<value>``
    - ``None`` / empty

    Returns a dict with keys ``type``, ``name``, ``value``, ``raw``.
    """
    result: dict[str, str] = {"type": "", "name": "", "value": "", "raw": user_value}
    if not user_value or user_value.lower() in ("", "n/a", "none", "-"):
        return result

    parts = user_value.split("-", 2)
    prefix = parts[0].lower() if parts else ""

    if prefix == "cookie" and len(parts) >= 2:
        result["type"] = "Cookie"
        # Cookie name may itself contain dashes — the last segment is the
        # hex value (typically 16 chars).  Try to split on the last dash
        # where the value portion looks like a hex string.
        remainder = user_value[len("Cookie-"):]
        # Find the last '-' followed by what looks like a hex value
        last_dash = remainder.rfind("-")
        if last_dash > 0:
            candidate_val = remainder[last_dash + 1:]
            candidate_name = remainder[:last_dash]
            # Hex values from XC are typically 16 chars, but be lenient
            if len(candidate_val) >= 8 and all(c in "0123456789abcdefABCDEF" for c in candidate_val):
                result["name"] = candidate_name
                result["value"] = candidate_val
            else:
                result["name"] = remainder
        else:
            result["name"] = remainder
    elif prefix == "ip" and len(parts) >= 2:
        result["type"] = "Client IP"
        result["value"] = "-".join(parts[1:])
    elif prefix in ("tlsfingerprint", "tls") and len(parts) >= 2:
        result["type"] = "TLS Fingerprint"
        result["value"] = "-".join(parts[1:])
    elif prefix == "header" and len(parts) >= 2:
        result["type"] = "Header"
        remainder = user_value[len("Header-"):]
        last_dash = remainder.rfind("-")
        if last_dash > 0:
            result["name"] = remainder[:last_dash]
            result["value"] = remainder[last_dash + 1:]
        else:
            result["name"] = remainder
    else:
        # Unknown format — store as-is
        result["type"] = "Unknown"
        result["value"] = user_value

    return result


def enrich_user_identification_from_events(
    lb_config: LBConfig,
    raw_sec: dict,
    raw_access: dict,
) -> None:
    """Enrich the user identification on ``lb_config`` using runtime data.

    The ``user`` field in security events and access logs reveals the
    **actual** identifier used at runtime (e.g. ``Cookie-_imp_apg_r_-abc123``).
    This is more reliable than parsing the policy spec because it shows
    what the system is *actually doing*.

    ``raw_sec`` / ``raw_access`` are the raw API responses (not parsed
    summaries) because the ``user`` field is not part of the standard
    parsed schema.

    If ``lb_config.user_identification`` already has rules from the API
    response, this adds a ``runtime_identifiers`` list as supplementary
    information.  If the rules list is empty (API couldn't resolve), this
    populates it from the event data.
    """
    import json as _json

    if not lb_config:
        return

    # Collect unique user identifiers from raw events + logs
    seen: set[str] = set()
    parsed_users: list[dict[str, str]] = []

    raw_entries: list = []
    if isinstance(raw_sec, dict):
        raw_entries.extend(raw_sec.get("events", []))
    if isinstance(raw_access, dict):
        raw_entries.extend(raw_access.get("logs", raw_access.get("access_logs", [])))

    for entry in raw_entries:
        # Entries may be JSON strings or dicts
        if isinstance(entry, str):
            try:
                entry = _json.loads(entry)
            except (ValueError, TypeError):
                continue
        if not isinstance(entry, dict):
            continue
        raw_user = str(entry.get("user", "") or "")
        if not raw_user or raw_user.lower() in ("", "n/a", "none", "-"):
            continue
        if raw_user in seen:
            continue
        seen.add(raw_user)
        parsed_users.append(parse_user_field(raw_user))

    if not parsed_users:
        return

    # Build human-readable descriptions from the parsed user fields
    runtime_rules: list[str] = []
    for pu in parsed_users:
        if pu["type"] == "Cookie" and pu["name"]:
            runtime_rules.append(f"Cookie: {pu['name']}")
        elif pu["type"] == "Client IP" and pu["value"]:
            runtime_rules.append(f"Client IP: {pu['value']}")
        elif pu["type"] == "TLS Fingerprint":
            runtime_rules.append("TLS Fingerprint")
        elif pu["type"] == "Header" and pu["name"]:
            runtime_rules.append(f"Header: {pu['name']}")
        elif pu["type"] and pu["value"]:
            runtime_rules.append(f"{pu['type']}: {pu['value']}")

    # Deduplicate while preserving order (e.g. many events with same cookie name)
    deduped: list[str] = []
    seen_rules: set[str] = set()
    for r in runtime_rules:
        if r not in seen_rules:
            deduped.append(r)
            seen_rules.add(r)
    runtime_rules = deduped

    if not runtime_rules:
        return

    # Ensure we have a UserIdentification object
    if lb_config.user_identification is None:
        uid_ref = lb_config.user_id_ref or {}
        lb_config.user_identification = UserIdentification(
            name=uid_ref.get("name", ""),
            namespace=uid_ref.get("namespace", ""),
        )

    uid = lb_config.user_identification

    # If the API-based rules are empty, populate from runtime
    if not uid.rules:
        uid.rules = runtime_rules
        logger.info(
            "User ID rules resolved from event data: %s",
            ", ".join(runtime_rules),
        )
    else:
        # API rules exist — store runtime info for cross-reference but don't
        # overwrite.  The report can show both.
        logger.debug(
            "User ID has API rules (%s) + runtime identifiers (%s)",
            ", ".join(uid.rules), ", ".join(runtime_rules),
        )
