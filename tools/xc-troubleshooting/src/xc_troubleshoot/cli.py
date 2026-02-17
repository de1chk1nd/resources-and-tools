"""
CLI entry point for the F5 XC WAAP Troubleshooting Tool.

Handles argument parsing and orchestrates the full workflow:
config -> query -> parse -> build report data -> render -> save.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

import requests

from .config import DEFAULT_CONFIG_PATH, PROJECT_ROOT, ConfigError, load_config
from .client import XCClient, build_query
from .parsers import extract_event_summary, extract_access_log_summary
from .analysis import search_mode_label
from .research import build_research_queries, run_public_research
from .reports import (
    ReportData,
    generate_markdown_report,
    generate_html_report,
    generate_json_report,
    save_report,
)

__all__ = ["main"]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="F5 XC WAAP Troubleshooting Tool — query security events by request ID and/or source IP",
    )
    parser.add_argument("--config", "-c", default=DEFAULT_CONFIG_PATH,
                        help=f"Path to YAML config file (default: {DEFAULT_CONFIG_PATH})")

    search = parser.add_argument_group("search criteria (at least one required)")
    search.add_argument("--req-id", "-r", default=None, help="Request ID (overrides config)")
    search.add_argument("--src-ip", "-s", default=None, help="Source IP (overrides config)")
    search.add_argument("--fqdn", "-d", default=None, help="FQDN / hostname (overrides config)")
    search.add_argument("--load-balancer", "-l", default=None, help="Load balancer name (overrides config)")

    parser.add_argument("--namespace", "-n", default=None, help="Namespace (overrides config)")
    parser.add_argument("--format", "-f", choices=["all", "markdown", "html", "json"],
                        default=None, help="Report format (default: markdown)")
    parser.add_argument("--hours", type=int, default=None, help="Search window in hours")
    parser.add_argument("--limit", type=int, default=None, help="Max events per query (default: 50)")
    parser.add_argument("--output-dir", "-o", default=None, help="Output directory for reports")

    extras = parser.add_argument_group("optional features")
    extras.add_argument("--research", action="store_true", default=False,
                        help="Search F5 public docs & community for known issues")
    extras.add_argument("--verbose", "-v", action="store_true", default=False,
                        help="Enable verbose (debug) logging")

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = _parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="[%(levelname)-5s] %(message)s",
        stream=sys.stderr,
    )

    # Load config
    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        logger.error("%s", e)
        sys.exit(1)

    # CLI overrides — search criteria
    req_id = args.req_id if args.req_id is not None else (cfg["request"].get("req_id", "") or "")
    src_ip = args.src_ip if args.src_ip is not None else (cfg["request"].get("src_ip", "") or "")
    fqdn = args.fqdn if args.fqdn is not None else (cfg["request"].get("fqdn", "") or "")
    load_balancer = args.load_balancer if args.load_balancer is not None else (cfg["request"].get("load_balancer", "") or "")

    if not req_id and not src_ip and not fqdn:
        logger.error("No search criteria provided. Use --req-id, --src-ip, and/or --fqdn.")
        sys.exit(1)

    # CLI overrides — settings
    namespace = args.namespace or cfg["request"].get("namespace", "default")
    report_fmt = args.format or cfg["report"].get("format", "markdown")
    search_hours: int = args.hours or cfg["request"].get("search_window_hours", 24)
    limit: int = args.limit or cfg["request"].get("limit", 50)
    output_dir = args.output_dir or cfg["report"].get("output_dir", "reports")

    if not os.path.isabs(output_dir):
        output_dir = os.path.join(PROJECT_ROOT, output_dir)

    # Info
    mode = search_mode_label(req_id, src_ip, fqdn, load_balancer)
    logger.info("Search     : %s", mode)
    if req_id:      logger.info("Request ID : %s", req_id)
    if src_ip:      logger.info("Source IP  : %s", src_ip)
    if fqdn:        logger.info("FQDN       : %s", fqdn)
    if load_balancer: logger.info("Load Bal.  : %s", load_balancer)
    logger.info("Tenant     : %s", cfg["tenant"]["name"])
    logger.info("Namespace  : %s", namespace)
    logger.info("Window     : %dh", search_hours)
    logger.info("Limit      : %d", limit)
    logger.info("Format     : %s", report_fmt)

    # Build query + client
    query = build_query(req_id=req_id, src_ip=src_ip, fqdn=fqdn, load_balancer=load_balancer)
    tenant_name = cfg["tenant"]["name"]
    api_url = f"https://{tenant_name}.console.ves.volterra.io"
    client = XCClient(api_url=api_url, api_token=cfg["auth"]["api_token"])

    raw_sec: dict = {}
    raw_access: dict = {}

    try:
        raw_sec = client.query_security_events(namespace=namespace, query=query,
                                                search_window_hours=search_hours, limit=limit)
        logger.info("Security events: %s total hits", raw_sec.get("total_hits", "?"))
    except requests.exceptions.HTTPError as e:
        logger.warning("Security events query failed: %s", e)
        if e.response is not None:
            logger.debug("Status %d — %s", e.response.status_code, e.response.text[:500])
        raw_sec = {"error": str(e)}

    try:
        raw_access = client.query_access_logs(namespace=namespace, query=query,
                                               search_window_hours=search_hours, limit=limit)
        logger.info("Access logs: %s total hits", raw_access.get("total_hits", "?"))
    except requests.exceptions.HTTPError as e:
        logger.warning("Access logs query failed: %s", e)
        if e.response is not None:
            logger.debug("Status %d — %s", e.response.status_code, e.response.text[:500])
        raw_access = {"error": str(e)}

    # Parse
    sec_events = extract_event_summary(raw_sec)
    access_logs = extract_access_log_summary(raw_access)

    # Research
    research_results: list[dict] | None = None
    research_queries: list[str] | None = None
    if args.research:
        research_queries = build_research_queries(sec_events, access_logs)
        research_results = run_public_research(sec_events, access_logs)

    # Build report data (computed once, shared by all renderers)
    report_data = ReportData(
        req_id=req_id, src_ip=src_ip, fqdn=fqdn, load_balancer=load_balancer,
        tenant=tenant_name, namespace=namespace, search_window_hours=search_hours,
        sec_events=sec_events, access_logs=access_logs,
        raw_sec=raw_sec, raw_access=raw_access,
        research_results=research_results, research_queries=research_queries,
    ).build()

    # Render + save
    formats = ["markdown", "html"] if report_fmt == "all" else [report_fmt]
    renderers = {
        "markdown": generate_markdown_report,
        "html": generate_html_report,
        "json": generate_json_report,
    }

    for fmt in formats:
        renderer = renderers.get(fmt)
        if not renderer:
            continue
        content = renderer(report_data)
        filepath = save_report(content, req_id, src_ip, output_dir, fmt,
                               fqdn=fqdn, load_balancer=load_balancer)
        logger.info("Report saved: %s", filepath)
