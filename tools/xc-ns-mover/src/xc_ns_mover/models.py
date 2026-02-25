"""
Shared data models and constants used across the xc-ns-mover project.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ------------------------------------------------------------------
# Friendly names for resource types
# ------------------------------------------------------------------

FRIENDLY_TYPE_NAMES = {
    "origin_pools": "Origin Pool",
    "healthchecks": "Health Check",
    "certificates": "TLS Certificate",
    "service_policys": "Service Policy",
    "api_definitions": "API Definition",
    "app_firewalls": "App Firewall",
    "ip_prefix_sets": "IP Prefix Set",
    "rate_limiter_policys": "Rate Limiter",
    "user_identifications": "User Identification",
}


# ------------------------------------------------------------------
# Data model for the mover report
# ------------------------------------------------------------------

@dataclass
class DepMoveResult:
    """Result of moving a single dependent object."""
    resource_type: str
    name: str
    new_name: str = ""  # Non-empty when renamed due to conflict
    status: str = ""  # "moved", "failed", "skipped", "dry-run", "reverted", "blocked", "manual-rework"
    error: str = ""
    backup_json: str = ""  # Original config JSON (for report)
    planned_config_json: str = ""  # JSON string of the planned config (dry-run)


@dataclass
class MoveResult:
    lb_name: str
    new_lb_name: str = ""  # Non-empty when renamed due to conflict
    src_namespace: str = ""
    dst_namespace: str = ""
    tls_mode: str = ""
    cname_old: str = ""
    cname_new: str = ""
    acme_cname_old: str = ""
    acme_cname_new: str = ""
    domains: list[str] = field(default_factory=list)  # LB domain list (for DNS Changes section)
    dns_managed: bool = False  # True if all LB domains are under XC-managed DNS zones
    status: str = ""  # "moved", "failed", "skipped", "dry-run", "reverted", "blocked"
    error: str = ""
    dependencies: list[DepMoveResult] = field(default_factory=list)
    planned_config_json: str = ""  # JSON string of the planned config (dry-run)
    backup_json: str = ""  # Original LB config JSON (for report)


@dataclass
class ManualReworkItem:
    """A certificate that could not be moved automatically.

    The private key contains secret material (blindfolded, clear, vault,
    or wingman) that cannot be extracted via the XC API.  The pre-flight
    check searched for a matching certificate in the target or shared
    namespace based on domain/SAN matching.
    """
    cert_name: str
    cert_key: tuple[str, str]           # (resource_type, cert_name)
    lb_names: list[str]                 # LBs referencing this cert
    src_namespace: str
    dst_namespace: str
    secret_type: str                    # e.g. "private key (blindfolded)"
    cert_domains: list[str]             # CN + SANs from the original cert
    matched_cert_name: str = ""         # Name of the matched cert (empty = no match)
    matched_cert_ns: str = ""           # Namespace of matched cert ("shared" or target)
    matched_cert_domains: list[str] = field(default_factory=list)
    original_config_json: str = ""      # Backup of the original cert config


# ------------------------------------------------------------------
# Batch graph data for the report
# ------------------------------------------------------------------

@dataclass
class BatchGraphData:
    """Data needed to render a dependency graph for one batch."""
    batch_index: int
    lb_names: list[str]
    # Per-LB deps: lb_name -> [(resource_type, dep_name)]
    lb_to_deps: dict[str, list[tuple[str, str]]]
    # Deps shared by >1 LB in this batch
    shared_deps: set[tuple[str, str]]
    # Sub-deps: dep_key -> [child dep_keys] (e.g. origin_pool -> [healthcheck])
    dep_children: dict[tuple[str, str], list[tuple[str, str]]]
    # Deps that are referenced by objects OUTSIDE the move list
    # (e.g. an origin pool used by another LB not in the CSV)
    external_deps: set[tuple[str, str]] = field(default_factory=set)
