"""
Workflow orchestrator — decoupled from CLI and argument parsing.

Can be called from the CLI, tests, or any other entry point.
The full pipeline: query -> parse -> analyse -> render -> save.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Callable

import requests

from .config import AppConfig, DEFAULT_NAMESPACE, PROJECT_ROOT
from .client import XCClient, build_query
from .parsers import extract_event_summary, extract_access_log_summary
from .analysis import search_mode_label
from .research import build_research_queries, run_public_research
from .lb_config import (
    LBConfig, derive_lb_name, derive_lb_namespace, _first_vh_name,
    parse_lb_config, parse_user_identification,
    enrich_user_identification_from_events,
)
from .reports import (
    ReportData,
    generate_html_report,
    save_report,
)

__all__ = ["run", "QueryResult"]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class QueryResult:
    """Holds results from the API query phase, including any errors."""
    raw_sec: dict = field(default_factory=dict)
    raw_access: dict = field(default_factory=dict)
    sec_error: str | None = None
    access_error: str | None = None

    @property
    def has_errors(self) -> bool:
        return self.sec_error is not None or self.access_error is not None


# ---------------------------------------------------------------------------
# Pipeline steps
# ---------------------------------------------------------------------------

def _query_apis(
    client: XCClient,
    namespace: str,
    query: str,
    search_hours: int,
    limit: int,
) -> QueryResult:
    """Query both API endpoints, capturing errors without aborting."""
    result = QueryResult()

    try:
        result.raw_sec = client.query_security_events(
            namespace=namespace, query=query,
            search_window_hours=search_hours, limit=limit,
        )
        logger.info("Security events: %s total hits", result.raw_sec.get("total_hits", "?"))
    except requests.exceptions.RequestException as e:
        logger.warning("Security events query failed: %s", e)
        if hasattr(e, "response") and e.response is not None:
            logger.debug("Status %d — %s", e.response.status_code, e.response.text[:500])
        result.raw_sec = {"error": str(e)}
        result.sec_error = str(e)

    try:
        result.raw_access = client.query_access_logs(
            namespace=namespace, query=query,
            search_window_hours=search_hours, limit=limit,
        )
        logger.info("Access logs: %s total hits", result.raw_access.get("total_hits", "?"))
    except requests.exceptions.RequestException as e:
        logger.warning("Access logs query failed: %s", e)
        if hasattr(e, "response") and e.response is not None:
            logger.debug("Status %d — %s", e.response.status_code, e.response.text[:500])
        result.raw_access = {"error": str(e)}
        result.access_error = str(e)

    return result


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run(
    cfg: AppConfig,
    client: XCClient | None = None,
) -> list[str]:
    """Execute the full troubleshooting pipeline.

    Args:
        cfg: Validated, merged application config.
        client: Optional pre-built XCClient (for testing / DI).

    Returns:
        List of file paths for the generated reports.
    """
    s = cfg.search
    r = cfg.report

    # Validate at least one search criterion
    if not s.req_id and not s.src_ip and not s.fqdn:
        raise ValueError("No search criteria provided. Use --req-id, --src-ip, and/or --fqdn.")

    # Resolve output dir
    output_dir = r.output_dir
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(PROJECT_ROOT, output_dir)

    # Log search info
    mode = search_mode_label(s.req_id, s.src_ip, s.fqdn, s.load_balancer)
    logger.info("Search     : %s", mode)
    if s.req_id:
        logger.info("Request ID : %s", s.req_id)
    if s.src_ip:
        logger.info("Source IP  : %s", s.src_ip)
    if s.fqdn:
        logger.info("FQDN       : %s", s.fqdn)
    if s.load_balancer:
        logger.info("Load Bal.  : %s", s.load_balancer)
    logger.info("Tenant     : %s", cfg.tenant.name)
    if s.namespace == DEFAULT_NAMESPACE:
        logger.info("Namespace  : %s (all namespaces)", s.namespace)
    else:
        logger.info("Namespace  : %s", s.namespace)
    logger.info("Window     : %dh", s.search_window_hours)
    logger.info("Limit      : %d", s.limit)
    logger.info("Format     : %s", r.format)

    # Build query + client
    query = build_query(
        req_id=s.req_id, src_ip=s.src_ip,
        fqdn=s.fqdn, load_balancer=s.load_balancer,
    )
    if client is None:
        api_url = f"https://{cfg.tenant.name}.console.ves.volterra.io"
        client = XCClient(api_url=api_url, api_token=cfg.auth.api_token)

    # Query
    qr = _query_apis(client, s.namespace, query, s.search_window_hours, s.limit)

    # Parse
    sec_events = extract_event_summary(qr.raw_sec)
    access_logs = extract_access_log_summary(qr.raw_access)

    # Fetch HTTP LB configuration (best-effort)
    lb_config: LBConfig | None = None
    api_errors: list[str] = [e for e in [qr.sec_error, qr.access_error] if e]
    try:
        vh_name = _first_vh_name(sec_events, access_logs)
        lb_name = derive_lb_name(vh_name=vh_name, load_balancer=s.load_balancer)
        lb_ns = derive_lb_namespace(sec_events, access_logs, default_ns=s.namespace)
        if lb_name and lb_ns and lb_ns.lower() != "system":
            logger.info("Fetching HTTP LB config: %s/%s", lb_ns, lb_name)
            raw_lb = client.get_http_loadbalancer(namespace=lb_ns, name=lb_name)
            lb_config = parse_lb_config(raw_lb)
            logger.info("LB config loaded: %d services parsed", len(lb_config.services))

            # Fetch User Identification policy (if referenced)
            uid_ref = lb_config.user_id_ref
            if uid_ref and isinstance(uid_ref, dict) and uid_ref.get("name"):
                uid_name = uid_ref["name"]
                uid_ns = uid_ref.get("namespace", lb_ns) or lb_ns
                try:
                    logger.info("Fetching User Identification: %s/%s", uid_ns, uid_name)
                    raw_uid = client.get_user_identification(namespace=uid_ns, name=uid_name)
                    lb_config.user_identification = parse_user_identification(raw_uid)
                    logger.info(
                        "User ID loaded: %s (%s)",
                        lb_config.user_identification.name,
                        ", ".join(lb_config.user_identification.rules) or "no rules",
                    )
                except Exception as uid_err:
                    logger.warning("Could not fetch User Identification: %s", uid_err)
        elif lb_name:
            logger.info(
                "Skipping LB config fetch: namespace is '%s' (need a specific namespace). "
                "Use --namespace to specify.",
                lb_ns,
            )
    except Exception as e:
        logger.warning("Could not fetch HTTP LB config: %s", e)
        api_errors.append(f"HTTP LB config: {e}")

    # Enrich user identification from runtime event data (best-effort).
    # The ``user`` field in events/logs reveals the actual identifier in use
    # (e.g. "Cookie-_imp_apg_r_-<value>"), which is more reliable than
    # parsing the policy spec via API.
    if lb_config:
        try:
            enrich_user_identification_from_events(lb_config, qr.raw_sec, qr.raw_access)
        except Exception as e:
            logger.debug("Could not enrich user identification from events: %s", e)

    # Research (optional)
    research_results: list[dict] | None = None
    research_queries: list[str] | None = None
    if cfg.research:
        research_queries = build_research_queries(sec_events, access_logs)
        research_results = run_public_research(sec_events, access_logs)

    # Build report data
    report_data = ReportData(
        req_id=s.req_id, src_ip=s.src_ip, fqdn=s.fqdn,
        load_balancer=s.load_balancer,
        tenant=cfg.tenant.name, namespace=s.namespace,
        search_window_hours=s.search_window_hours,
        sec_events=sec_events, access_logs=access_logs,
        raw_sec=qr.raw_sec, raw_access=qr.raw_access,
        research_results=research_results, research_queries=research_queries,
        lb_config=lb_config,
        api_errors=api_errors,
    ).build()

    # Render + save
    content = generate_html_report(report_data)
    filepath = save_report(
        content, s.req_id, s.src_ip, output_dir, "html",
        fqdn=s.fqdn, load_balancer=s.load_balancer,
    )
    logger.info("Report saved: file://%s", filepath)

    return [filepath]
