"""
Configuration loading, validation, and typed models.

Supports:
  - YAML config file (hardcoded secrets still work)
  - Environment variable overrides (XC_API_TOKEN, XC_TENANT)
  - CLI argument merging via merge_cli_overrides()

Namespace is NOT configured here — it defaults to "system" (all namespaces)
and can be overridden via CLI --namespace / -n only.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .validation import (
    ValidationError,
    sanitize_fqdn,
    sanitize_lb_name,
    sanitize_namespace,
    sanitize_req_id,
    sanitize_src_ip,
    sanitize_tenant,
)

__all__ = [
    "DEFAULT_CONFIG_PATH",
    "PROJECT_ROOT",
    "DEFAULT_NAMESPACE",
    "ConfigError",
    "TenantConfig",
    "AuthConfig",
    "SearchParams",
    "ReportConfig",
    "AppConfig",
    "load_config",
    "merge_cli_overrides",
]

logger = logging.getLogger(__name__)

# Default config path — relative to the project root (two levels up from this file)
DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config",
    "config.yaml",
)

# Project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Environment variable names
ENV_API_TOKEN = "XC_API_TOKEN"
ENV_TENANT = "XC_TENANT"

# Default namespace — "system" queries across all namespaces
DEFAULT_NAMESPACE = "system"


# ---------------------------------------------------------------------------
# Typed configuration models
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """Raised when the configuration file is missing or invalid."""


@dataclass(frozen=True)
class TenantConfig:
    name: str


@dataclass(frozen=True)
class AuthConfig:
    api_token: str

    def __repr__(self) -> str:
        """Redact token in repr to prevent accidental logging."""
        return f"AuthConfig(api_token='***redacted***')"


@dataclass(frozen=True)
class SearchParams:
    req_id: str = ""
    src_ip: str = ""
    fqdn: str = ""
    load_balancer: str = ""
    namespace: str = DEFAULT_NAMESPACE
    search_window_hours: int = 24
    limit: int = 50


@dataclass(frozen=True)
class ReportConfig:
    output_dir: str = "reports"
    format: str = "html"


@dataclass(frozen=True)
class AppConfig:
    tenant: TenantConfig
    auth: AuthConfig
    search: SearchParams
    report: ReportConfig
    research: bool = False
    verbose: bool = False


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

_PLACEHOLDER_VALUES = frozenset({
    "your-actual-api-token",
    "REPLACE_WITH_YOUR_API_TOKEN",
    "your-api-token",
})


def load_config(config_path: str) -> AppConfig:
    """Load and validate the YAML configuration file.

    Environment variables take precedence over YAML values for secrets:
      - XC_API_TOKEN  -> auth.api_token
      - XC_TENANT     -> tenant.name

    Namespace is NOT read from YAML — it defaults to "system" (all namespaces)
    and can only be overridden via CLI --namespace / -n.

    The YAML file can still contain the api_token directly (backward compatible).

    Raises:
        ConfigError: If the config file is missing or contains placeholder values.
    """
    path = Path(config_path)
    if not path.exists():
        raise ConfigError(
            f"Config file not found: {config_path}\n"
            "Copy config/config.yaml.example to config/config.yaml and fill in your values."
        )

    with open(path, "r") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ConfigError(f"Invalid config file format: expected YAML mapping, got {type(raw).__name__}")

    # --- Tenant ---
    tenant_name = os.environ.get(ENV_TENANT) or raw.get("tenant", {}).get("name", "")
    if not tenant_name:
        raise ConfigError("Missing tenant name. Set 'tenant.name' in config or XC_TENANT env var.")

    try:
        tenant_name = sanitize_tenant(tenant_name)
    except ValidationError as e:
        raise ConfigError(str(e)) from e

    # --- Auth (env var > YAML, both are valid) ---
    api_token = os.environ.get(ENV_API_TOKEN) or raw.get("auth", {}).get("api_token", "")
    if not api_token or api_token in _PLACEHOLDER_VALUES or api_token.startswith("your-"):
        raise ConfigError(
            "Missing or placeholder API token. "
            f"Set '{ENV_API_TOKEN}' env var or 'auth.api_token' in config."
        )

    # --- Request / Search (namespace is NOT read from YAML) ---
    req_section = raw.get("request", {})

    try:
        req_id = sanitize_req_id(req_section.get("req_id", "") or "")
        src_ip = sanitize_src_ip(req_section.get("src_ip", "") or "")
        fqdn = sanitize_fqdn(req_section.get("fqdn", "") or "")
        lb = sanitize_lb_name(req_section.get("load_balancer", "") or "")
    except ValidationError as e:
        raise ConfigError(str(e)) from e

    search_hours = int(req_section.get("search_window_hours", 24) or 24)
    limit = int(req_section.get("limit", 50) or 50)

    # --- Report ---
    rpt_section = raw.get("report", {})
    output_dir = rpt_section.get("output_dir", "reports") or "reports"
    report_fmt = rpt_section.get("format", "html") or "html"
    if report_fmt not in ("html",):
        raise ConfigError(f"Invalid report format: {report_fmt!r}. Only 'html' is supported.")

    config = AppConfig(
        tenant=TenantConfig(name=tenant_name),
        auth=AuthConfig(api_token=api_token),
        search=SearchParams(
            req_id=req_id, src_ip=src_ip, fqdn=fqdn, load_balancer=lb,
            namespace=DEFAULT_NAMESPACE,
            search_window_hours=search_hours, limit=limit,
        ),
        report=ReportConfig(output_dir=output_dir, format=report_fmt),
    )

    logger.debug("Config loaded from %s (token from %s)",
                 config_path,
                 "env" if os.environ.get(ENV_API_TOKEN) else "file")
    return config


# ---------------------------------------------------------------------------
# CLI override merging
# ---------------------------------------------------------------------------

def merge_cli_overrides(cfg: AppConfig, args) -> AppConfig:
    """Merge CLI arguments over loaded config, returning a new AppConfig.

    ``args`` is expected to have attributes matching argparse output:
    req_id, src_ip, fqdn, load_balancer, namespace, format, hours, limit,
    output_dir, research, verbose.

    Namespace defaults to "system" (all namespaces). Use --namespace / -n
    to query a specific namespace instead.

    Raises:
        ConfigError: If merged values fail validation.
    """
    search = cfg.search
    report = cfg.report

    try:
        req_id = sanitize_req_id(args.req_id) if args.req_id is not None else search.req_id
        src_ip = sanitize_src_ip(args.src_ip) if args.src_ip is not None else search.src_ip
        fqdn = sanitize_fqdn(args.fqdn) if args.fqdn is not None else search.fqdn
        lb = sanitize_lb_name(args.load_balancer) if args.load_balancer is not None else search.load_balancer
        ns = sanitize_namespace(args.namespace) if args.namespace is not None else search.namespace
    except ValidationError as e:
        raise ConfigError(str(e)) from e

    hours = args.hours if args.hours is not None else search.search_window_hours
    limit = args.limit if args.limit is not None else search.limit
    fmt = args.format if args.format is not None else report.format
    out_dir = args.output_dir if args.output_dir is not None else report.output_dir

    return AppConfig(
        tenant=cfg.tenant,
        auth=cfg.auth,
        search=SearchParams(
            req_id=req_id, src_ip=src_ip, fqdn=fqdn, load_balancer=lb,
            namespace=ns, search_window_hours=hours, limit=limit,
        ),
        report=ReportConfig(output_dir=out_dir, format=fmt),
        research=getattr(args, "research", False),
        verbose=getattr(args, "verbose", False),
    )
