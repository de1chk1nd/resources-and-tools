"""
CLI entry point and orchestration for the scanner subcommand.

Connects to F5 XC, lists all HTTP/HTTPS load balancers across namespaces,
and writes a CSV + HTML report.
"""

import argparse
import csv
import logging
import os
import sys
from datetime import datetime

import requests

from ..config import DEFAULT_CONFIG_PATH, PROJECT_ROOT, ConfigError, load_config, resolve_namespaces
from ..client import XCClient
from ..logging_setup import setup_logging
from ..report.scanner_report import generate_scanner_report

logger = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List all HTTP/HTTPS load balancers across F5 XC namespaces and export as CSV.",
    )
    parser.add_argument(
        "--config",
        "-c",
        default=DEFAULT_CONFIG_PATH,
        help="Path to YAML config file (default: config/config.yaml)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default=None,
        help="Output directory for the CSV report (overrides config)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose (debug) logging",
    )
    return parser.parse_args()



def main() -> None:
    args = _parse_args()

    # Logging setup
    setup_logging(verbose=args.verbose, log_prefix="scanner")

    # Load config
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        sys.exit(1)

    tenant_name = cfg["tenant"]["name"]
    api_token = cfg["auth"]["api_token"]
    api_url = f"https://{tenant_name}.console.ves.volterra.io"

    ns_cfg = cfg.get("namespaces", {}) or {}
    ns_include = ns_cfg.get("include") or []
    ns_exclude = ns_cfg.get("exclude") or []

    output_dir = args.output_dir or cfg.get("report", {}).get("output_dir", "reports")
    # Resolve output_dir relative to project root if not absolute
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(PROJECT_ROOT, output_dir)

    # Build client
    client = XCClient(api_url, api_token)

    # 1. Get all namespaces
    print(f"Connecting to tenant: {tenant_name}")
    try:
        all_namespaces = client.list_namespaces()
    except requests.RequestException as exc:
        logger.error("Failed to list namespaces: %s", exc)
        sys.exit(1)
    print(f"Found {len(all_namespaces)} namespaces on tenant")

    # 2. Apply include/exclude filter
    namespaces = resolve_namespaces(all_namespaces, ns_include, ns_exclude)

    has_include = len(ns_include) > 0
    has_exclude = len(ns_exclude) > 0
    if has_include and has_exclude:
        print(
            f"Namespace filter: include {len(ns_include)} + exclude {len(ns_exclude)} "
            f"-> {len(namespaces)} namespaces to scan"
        )
    elif has_include:
        print(
            f"Namespace filter: include {len(ns_include)} "
            f"-> {len(namespaces)} namespaces to scan"
        )
    elif has_exclude:
        print(
            f"Namespace filter: exclude {len(ns_exclude)} "
            f"-> {len(namespaces)} namespaces to scan"
        )
    else:
        print(f"No namespace filter — scanning all {len(namespaces)} namespaces")

    if not namespaces:
        logger.error("No namespaces to scan after filtering.")
        sys.exit(1)

    # 3. Iterate namespaces and collect LBs
    rows: list[tuple[str, str, str]] = []  # (namespace, lb_name, lb_type)
    for i, ns in enumerate(namespaces, 1):
        print(f"  [{i}/{len(namespaces)}] Scanning namespace: {ns} ...", end=" ")
        try:
            lbs = client.list_all_loadbalancers(ns)
        except requests.RequestException as exc:
            print(f"ERROR: {exc}")
            logger.warning("Failed to list LBs in namespace '%s': %s", ns, exc)
            continue
        print(f"{len(lbs)} load balancer(s)")
        for lb_name, lb_type in lbs:
            rows.append((ns, lb_name, lb_type))

    # 4. Summary
    print()
    print(f"Total: {len(rows)} load balancer(s) across {len(namespaces)} namespace(s)")

    if not rows:
        print("No load balancers found — no CSV generated.")
        return

    # 5. Write CSV
    timestamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    run_dir = os.path.join(output_dir, f"scanner_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)
    csv_filename = f"scanner_{timestamp}.csv"
    csv_path = os.path.join(run_dir, csv_filename)

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M")
    ns_count = len(namespaces)
    lb_count = len(rows)

    with open(csv_path, "w", newline="") as f:
        # Comment header — explains context and where data starts
        f.write(f"# Scanner report — tenant: {tenant_name}\n")
        f.write(f"# Generated: {scan_time}\n")
        f.write(f"# Namespaces scanned: {ns_count}  |  Load balancers found: {lb_count}\n")
        f.write("#\n")
        f.write("# To use with the mover:\n")
        f.write("#   1. Copy the rows you need into config/xc-mover.csv\n")
        f.write("#   2. Only the namespace and lb_name columns are required\n")
        f.write("#\n")
        f.write("# --- DATA STARTS BELOW THIS LINE ---\n")
        writer = csv.writer(f)
        writer.writerow(["namespace", "lb_name", "lb_type"])
        for ns, lb_name, lb_type in sorted(rows):
            writer.writerow([ns, lb_name, lb_type])

    # 6. Write HTML report
    html_filename = f"scanner_{timestamp}.html"
    html_path = os.path.join(run_dir, html_filename)
    generate_scanner_report(
        report_path=html_path,
        tenant_name=tenant_name,
        scan_time=scan_time,
        ns_count=ns_count,
        ns_scanned=namespaces,
        rows=rows,
        total_ns_on_tenant=len(all_namespaces),
        ns_include=ns_include,
        ns_exclude=ns_exclude,
    )

    abs_csv = os.path.abspath(csv_path)
    abs_html = os.path.abspath(html_path)
    print(f"CSV report saved to:  file://{abs_csv}")
    print(f"HTML report saved to: file://{abs_html}")
