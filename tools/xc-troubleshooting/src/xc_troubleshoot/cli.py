"""
CLI entry point for the F5 XC WAAP Troubleshooting Tool.

Thin shell: parses arguments, loads config, merges overrides, delegates to
the orchestrator for the actual workflow.
"""

from __future__ import annotations

import argparse
import logging
import sys

from .config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_NAMESPACE,
    ConfigError,
    load_config,
    merge_cli_overrides,
)
from .orchestrator import run

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

    parser.add_argument("--namespace", "-n", default=None,
                        help=f"Namespace to query (default: '{DEFAULT_NAMESPACE}' = all namespaces)")
    parser.add_argument("--format", "-f", choices=["html"],
                        default=None, help="Report format (default: html)")
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

    # Merge CLI overrides
    try:
        cfg = merge_cli_overrides(cfg, args)
    except ConfigError as e:
        logger.error("%s", e)
        sys.exit(1)

    # Run pipeline
    try:
        run(cfg)
    except ValueError as e:
        logger.error("%s", e)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted.")
        sys.exit(130)
