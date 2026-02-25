"""
Orchestration helpers for the mover subcommand.

Contains the union-find batch clustering logic and extracted pre-flight
phase functions that were previously inlined in ``main()``.
"""

from __future__ import annotations

import json
import logging

import requests

from ..client import XCClient
from ..spec_utils import find_ns_refs, guess_resource_type
from ..models import (
    FRIENDLY_TYPE_NAMES,
    BatchGraphData,
    ManualReworkItem,
)

__all__ = [
    "UnionFind",
    "discover_lbs_and_deps",
    "cluster_batches",
    "scan_external_references",
    "detect_nonportable_certs",
    "match_certificates",
    "scan_dns_zones",
    "build_batch_graphs",
]

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Union-Find for batch clustering
# ------------------------------------------------------------------

class UnionFind:
    """Simple union-find (disjoint set) for grouping LBs by shared deps."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        if x not in self._parent:
            self._parent[x] = x
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[ra] = rb


# ------------------------------------------------------------------
# Phase 0: Discovery
# ------------------------------------------------------------------

def discover_lbs_and_deps(
    client: XCClient,
    to_move: list[tuple[str, str]],
) -> tuple[
    dict[str, dict],                          # lb_configs
    dict[str, list[tuple[str, str, str]]],    # lb_deps
    set[str],                                  # discovery_failed
]:
    """GET all LB configs and discover their dependencies.

    Returns:
        lb_configs: lb_name -> full GET config
        lb_deps: lb_name -> [(resource_type, dep_name, dep_ns)]
        discovery_failed: set of lb_names that could not be fetched
    """
    lb_configs: dict[str, dict] = {}
    lb_deps: dict[str, list[tuple[str, str, str]]] = {}
    discovery_failed: set[str] = set()

    for src_ns, lb_name in to_move:
        try:
            lb_config = client.get_http_loadbalancer(src_ns, lb_name)
            lb_configs[lb_name] = lb_config
        except requests.RequestException as exc:
            logger.info("FAILED to get '%s': %s", lb_name, exc)
            discovery_failed.add(lb_name)
            continue

        deps = client.discover_dependencies(src_ns, lb_config)
        lb_deps[lb_name] = deps

    return lb_configs, lb_deps, discovery_failed


def cluster_batches(
    lb_deps: dict[str, list[tuple[str, str, str]]],
) -> tuple[
    list[list[str]],                               # batches
    dict[tuple[str, str], list[str]],               # dep_to_lbs
]:
    """Cluster LBs into batches based on shared dependencies.

    Returns:
        batches: list of LB name groups
        dep_to_lbs: dep_key -> [lb_names sharing that dep]
    """
    uf = UnionFind()
    dep_to_lbs: dict[tuple[str, str], list[str]] = {}

    for lb_name, deps in lb_deps.items():
        uf.find(lb_name)  # ensure LB is in the UF even with no deps
        for resource_type, dep_name, _ in deps:
            dep_key = (resource_type, dep_name)
            if dep_key not in dep_to_lbs:
                dep_to_lbs[dep_key] = []
            dep_to_lbs[dep_key].append(lb_name)

    # Union all LBs that share a dependency
    for dep_key, lb_names in dep_to_lbs.items():
        for i in range(1, len(lb_names)):
            uf.union(lb_names[0], lb_names[i])

    # Build batches: group by root
    batch_map: dict[str, list[str]] = {}
    for lb_name in lb_deps:
        root = uf.find(lb_name)
        batch_map.setdefault(root, []).append(lb_name)

    batches: list[list[str]] = list(batch_map.values())

    # Log batch info
    if len(batches) == len(lb_deps):
        logger.info("No shared dependencies — %d independent LB(s)", len(batches))
    else:
        multi = [b for b in batches if len(b) > 1]
        logger.info(
            "%d batch(es): %d shared-dep group(s), %d independent LB(s)",
            len(batches), len(multi), len(batches) - len(multi),
        )
        for b in multi:
            shared_deps = set()
            for lb_name in b:
                for rt, dn, _ in lb_deps.get(lb_name, []):
                    if len(dep_to_lbs.get((rt, dn), [])) > 1:
                        friendly = FRIENDLY_TYPE_NAMES.get(rt, rt)
                        shared_deps.add(f"{friendly} '{dn}'")
            logger.info(
                "  Batch [%s] — shared: %s",
                ", ".join(b), ", ".join(sorted(shared_deps)),
            )

    return batches, dep_to_lbs


# ------------------------------------------------------------------
# Phase 0b: External reference scan
# ------------------------------------------------------------------

def scan_external_references(
    client: XCClient,
    to_move: list[tuple[str, str]],
    lb_deps: dict[str, list[tuple[str, str, str]]],
) -> dict[tuple[str, str], list[tuple[str, str]]]:
    """Scan for dependencies used by LBs NOT in the move list.

    The ``referring_objects`` field from the XC API is unreliable, so we
    actively scan other LBs in the same namespace(s) to detect external
    referrers.

    Returns:
        external_dep_refs: dep_key -> [(external_lb_name, lb_ns)]
    """
    all_dep_keys: set[tuple[str, str]] = set()
    for deps_list in lb_deps.values():
        for rt, dn, _ in deps_list:
            all_dep_keys.add((rt, dn))

    external_dep_refs: dict[tuple[str, str], list[tuple[str, str]]] = {}

    if not all_dep_keys:
        return external_dep_refs

    move_lb_names = {name for _, name in to_move}
    src_namespaces = sorted({ns for ns, _ in to_move})

    logger.info("Scanning for external references to dependencies...")
    for ns in src_namespaces:
        try:
            all_lbs_in_ns = client.list_all_loadbalancers(ns)
        except requests.RequestException as exc:
            logger.warning("Could not list LBs in namespace '%s': %s", ns, exc)
            continue

        for other_lb_name, lb_type in all_lbs_in_ns:
            if other_lb_name in move_lb_names:
                continue
            plural_type = lb_type + "s" if not lb_type.endswith("s") else lb_type
            try:
                other_config = client.get_config_object(ns, plural_type, other_lb_name)
            except requests.RequestException as exc:
                logger.debug(
                    "Cannot fetch %s '%s' in '%s' for external ref scan: %s",
                    plural_type, other_lb_name, ns, exc,
                )
                continue
            other_spec = other_config.get("spec") or {}
            other_refs = find_ns_refs(other_spec, ns)
            for path, obj_name, _ in other_refs:
                rt = guess_resource_type(path)
                if rt is not None:
                    dk = (rt, obj_name)
                    if dk in all_dep_keys:
                        external_dep_refs.setdefault(dk, []).append(
                            (other_lb_name, ns)
                        )

    if external_dep_refs:
        logger.info("Found %d dep(s) with external references:", len(external_dep_refs))
        for dk, refs in external_dep_refs.items():
            friendly = FRIENDLY_TYPE_NAMES.get(dk[0], dk[0])
            ref_names = [f"'{n}' ({ns})" for n, ns in refs]
            logger.info("  %s '%s' — used by: %s", friendly, dk[1], ", ".join(ref_names))
    else:
        logger.info("No external references found.")

    return external_dep_refs


# ------------------------------------------------------------------
# Phase 0d-detect: Identify non-portable certificates
# ------------------------------------------------------------------

def detect_nonportable_certs(
    client: XCClient,
    lb_deps: dict[str, list[tuple[str, str, str]]],
) -> tuple[
    set[tuple[str, str]],                          # secret_cert_keys
    dict[tuple[str, str], dict],                   # secret_cert_configs
    dict[tuple[str, str], list[str]],              # secret_cert_lb_map
    dict[tuple[str, str], str],                    # secret_cert_reasons
]:
    """Identify certificates with non-portable private keys.

    Scans all certificate dependencies and checks whether their private
    keys can be extracted via the API.

    Returns:
        secret_cert_keys: set of (resource_type, cert_name) for non-portable certs
        secret_cert_configs: cert_key -> full GET config
        secret_cert_lb_map: cert_key -> [lb_names referencing this cert]
        secret_cert_reasons: cert_key -> human-readable reason string
    """
    secret_cert_keys: set[tuple[str, str]] = set()
    secret_cert_configs: dict[tuple[str, str], dict] = {}
    secret_cert_lb_map: dict[tuple[str, str], list[str]] = {}
    secret_cert_reasons: dict[tuple[str, str], str] = {}

    for lb_name, deps in lb_deps.items():
        for rt, dep_name, dep_ns in deps:
            if rt != "certificates":
                continue
            key = (rt, dep_name)
            if key in secret_cert_keys:
                if lb_name not in secret_cert_lb_map.get(key, []):
                    secret_cert_lb_map.setdefault(key, []).append(lb_name)
                continue
            try:
                cert_config = client.get_config_object(dep_ns, rt, dep_name)
            except requests.RequestException as exc:
                logger.debug("Cannot fetch cert '%s/%s': %s", dep_ns, dep_name, exc)
                continue
            portable, reason = XCClient.is_cert_portable(cert_config)
            if not portable:
                secret_cert_keys.add(key)
                secret_cert_configs[key] = cert_config
                secret_cert_reasons[key] = reason
                secret_cert_lb_map.setdefault(key, []).append(lb_name)

    if secret_cert_keys:
        logger.info(
            "Detected %d certificate(s) with non-portable private keys (will be resolved in Phase 0d).",
            len(secret_cert_keys),
        )

    return secret_cert_keys, secret_cert_configs, secret_cert_lb_map, secret_cert_reasons


# ------------------------------------------------------------------
# Phase 0d: Certificate domain matching
# ------------------------------------------------------------------

def match_certificates(
    client: XCClient,
    secret_cert_keys: set[tuple[str, str]],
    secret_cert_configs: dict[tuple[str, str], dict],
    secret_cert_lb_map: dict[tuple[str, str], list[str]],
    secret_cert_reasons: dict[tuple[str, str], str],
    lb_configs: dict[str, dict],
    lb_src_ns: dict[str, str],
    target_namespace: str,
    batches: list[list[str]],
) -> tuple[
    dict[tuple[str, str], ManualReworkItem],   # manual_rework_items
    set[str],                                   # cert_blocked_lbs
]:
    """Search for matching certificates in the target and shared namespaces.

    For each non-portable certificate, tries three matching strategies:
      1. Domain match: cert SANs/CN cover all LB domains
      2. Cert-domain match: if LB has no domains, match by original cert domains
      3. Name match: same name as source cert (fallback)

    Returns:
        manual_rework_items: cert_key -> ManualReworkItem
        cert_blocked_lbs: LB names blocked due to unmatched certs
    """
    manual_rework_items: dict[tuple[str, str], ManualReworkItem] = {}
    cert_blocked_lbs: set[str] = set()

    if not secret_cert_keys:
        logger.info("No certificates with non-portable private keys found.")
        return manual_rework_items, cert_blocked_lbs

    logger.info(
        "Found %d certificate(s) with non-portable private keys — running pre-flight check...",
        len(secret_cert_keys),
    )

    # Build catalog of available certs: [(name, namespace, domains)]
    available_certs: list[tuple[str, str, list[str]]] = []

    target_cert_configs = client.list_certificates_full(target_namespace)
    for tc in target_cert_configs:
        tc_name = (tc.get("metadata") or {}).get("name", "")
        if tc_name:
            tc_domains = XCClient.extract_cert_domains(tc)
            available_certs.append((tc_name, target_namespace, tc_domains))

    shared_cert_configs = client.list_certificates_full("shared")
    for sc in shared_cert_configs:
        sc_name = (sc.get("metadata") or {}).get("name", "")
        if sc_name:
            sc_domains = XCClient.extract_cert_domains(sc)
            available_certs.append((sc_name, "shared", sc_domains))

    logger.info(
        "Pre-flight: %d cert(s) in target '%s', %d cert(s) in 'shared'",
        len(target_cert_configs), target_namespace, len(shared_cert_configs),
    )

    # Match each non-portable cert against available certs
    for key in sorted(secret_cert_keys):
        cert_config = secret_cert_configs[key]
        reason = secret_cert_reasons[key]
        cert_domains = XCClient.extract_cert_domains(cert_config)
        affected_lbs = secret_cert_lb_map[key]

        # Collect all domains from the affected LBs
        lb_domains: set[str] = set()
        for lb_name in affected_lbs:
            lb_config = lb_configs.get(lb_name)
            if lb_config:
                lb_domains.update(XCClient.extract_lb_domains(lb_config))

        best_match: tuple[str, str, list[str]] | None = None

        # Strategy 1: match by LB domains
        if lb_domains:
            for avail_name, avail_ns, avail_domains in available_certs:
                if avail_domains and all(
                    XCClient.domain_matches_cert(d, avail_domains)
                    for d in lb_domains
                ):
                    best_match = (avail_name, avail_ns, avail_domains)
                    break

        # Strategy 2: match by original cert domains (if LB has none)
        if not best_match and not lb_domains and cert_domains:
            for avail_name, avail_ns, avail_domains in available_certs:
                if avail_domains and all(
                    XCClient.domain_matches_cert(d, avail_domains)
                    for d in cert_domains
                ):
                    best_match = (avail_name, avail_ns, avail_domains)
                    break

        # Strategy 3: name-based fallback
        if not best_match:
            for avail_name, avail_ns, avail_domains in available_certs:
                if avail_name == key[1]:
                    best_match = (avail_name, avail_ns, avail_domains)
                    logger.info(
                        "  Cert '%s' -> name-matched to '%s' in '%s'",
                        key[1], avail_name, avail_ns,
                    )
                    break

        item = ManualReworkItem(
            cert_name=key[1],
            cert_key=key,
            lb_names=list(affected_lbs),
            src_namespace=lb_src_ns.get(affected_lbs[0], "?"),
            dst_namespace=target_namespace,
            secret_type=reason,
            cert_domains=cert_domains,
            original_config_json=json.dumps(cert_config, indent=2),
        )

        if best_match:
            item.matched_cert_name = best_match[0]
            item.matched_cert_ns = best_match[1]
            item.matched_cert_domains = list(best_match[2])
            logger.info(
                "  Cert '%s' -> matched to '%s' in '%s'",
                key[1], best_match[0], best_match[1],
            )
        else:
            logger.info(
                "  Cert '%s' -> NO MATCH (domains: %s)",
                key[1], ", ".join(lb_domains) if lb_domains else "(none)",
            )
            cert_blocked_lbs.update(affected_lbs)

        manual_rework_items[key] = item

    # Expand blocking to entire batches
    if cert_blocked_lbs:
        for batch_lb_names_chk in batches:
            if cert_blocked_lbs & set(batch_lb_names_chk):
                cert_blocked_lbs.update(batch_lb_names_chk)
        logger.info(
            "Blocking %d LB(s) due to unmatched certificates",
            len(cert_blocked_lbs),
        )

    return manual_rework_items, cert_blocked_lbs


# ------------------------------------------------------------------
# Phase 0e: DNS zone pre-flight
# ------------------------------------------------------------------

def scan_dns_zones(
    client: XCClient,
    lb_configs: dict[str, dict],
) -> tuple[
    list[dict],      # zone_configs
    set[str],        # managed_zones
    set[str],        # dns_managed_lbs
]:
    """Check for XC-managed DNS zones and identify LBs with auto-managed DNS.

    Returns:
        zone_configs: raw zone config dicts from the API
        managed_zones: set of zone domain strings with managed records enabled
        dns_managed_lbs: set of LB names where ALL domains are under a managed zone
    """
    zone_configs = client.list_dns_zones()
    managed_zones = XCClient.extract_managed_zone_domains(zone_configs)

    if not zone_configs and not managed_zones:
        logger.warning(
            "Could not read DNS zones — assuming no XC-managed DNS. "
            "Grant read access to /api/config/dns/namespaces/system/dns_zones "
            "to enable managed DNS detection."
        )

    dns_managed_lbs: set[str] = set()
    le_lb_count = 0
    for lb_name, config in lb_configs.items():
        tls_mode = XCClient.extract_tls_mode(config)
        if "encrypt" not in tls_mode.lower():
            continue
        le_lb_count += 1
        lb_domains = XCClient.extract_lb_domains(config)
        if not lb_domains:
            continue
        all_managed = all(
            any(XCClient.domain_is_under_zone(d, z) for z in managed_zones)
            for d in lb_domains
        )
        if all_managed:
            dns_managed_lbs.add(lb_name)
            logger.info("LB '%s' — all domains under managed DNS zone(s)", lb_name)

    logger.info(
        "Phase 0e: %d of %d Let's Encrypt LB(s) have XC-managed DNS",
        len(dns_managed_lbs), le_lb_count,
    )

    return zone_configs, managed_zones, dns_managed_lbs


# ------------------------------------------------------------------
# Batch graph builder (for the HTML report)
# ------------------------------------------------------------------

def build_batch_graphs(
    batches: list[list[str]],
    lb_deps: dict[str, list[tuple[str, str, str]]],
    lb_configs: dict[str, dict],
    lb_src_ns: dict[str, str],
    external_dep_refs: dict[tuple[str, str], list[tuple[str, str]]],
) -> list[BatchGraphData]:
    """Build ``BatchGraphData`` objects for the HTML report.

    Separates direct LB refs (tier 1) from sub-deps (tier 2) so the
    SVG renderer can draw a proper hierarchy.
    """
    # Compute direct LB refs (tier 1) for each LB
    lb_direct_deps: dict[str, set[tuple[str, str]]] = {}
    for lb_name in lb_deps:
        lb_config = lb_configs[lb_name]
        spec = lb_config.get("spec") or {}
        src_ns = lb_src_ns[lb_name]
        direct_refs = find_ns_refs(spec, src_ns)
        direct_keys: set[tuple[str, str]] = set()
        for path, obj_name, _ in direct_refs:
            rt = guess_resource_type(path)
            if rt is not None:
                direct_keys.add((rt, obj_name))
        lb_direct_deps[lb_name] = direct_keys

    all_batch_graphs: list[BatchGraphData] = []
    for batch_idx, batch_lb_names_g in enumerate(batches, 1):
        bg_lb_to_deps: dict[str, list[tuple[str, str]]] = {}
        bg_shared: set[tuple[str, str]] = set()
        bg_dep_children: dict[tuple[str, str], list[tuple[str, str]]] = {}

        # Collect ONLY direct deps per LB (tier 1)
        all_deps_in_batch: set[tuple[str, str]] = set()
        for lb_name in batch_lb_names_g:
            direct: list[tuple[str, str]] = []
            for rt, dn, _ in lb_deps.get(lb_name, []):
                dk = (rt, dn)
                if dk in lb_direct_deps.get(lb_name, set()):
                    direct.append(dk)
                all_deps_in_batch.add(dk)
            bg_lb_to_deps[lb_name] = direct

        # Shared = direct deps referenced by >1 LB in this batch
        dep_count_in_batch: dict[tuple[str, str], int] = {}
        for deps_list in bg_lb_to_deps.values():
            for dk in deps_list:
                dep_count_in_batch[dk] = dep_count_in_batch.get(dk, 0) + 1
        bg_shared = {dk for dk, c in dep_count_in_batch.items() if c > 1}

        # Sub-deps: deps in the BFS list that are NOT direct LB refs
        all_direct_in_batch: set[tuple[str, str]] = set()
        for dlist in bg_lb_to_deps.values():
            all_direct_in_batch.update(dlist)

        for lb_name in batch_lb_names_g:
            bfs_list = lb_deps.get(lb_name, [])
            current_parent: tuple[str, str] | None = None
            for rt, dn, _ in bfs_list:
                dk = (rt, dn)
                if dk in all_direct_in_batch:
                    current_parent = dk
                elif current_parent is not None:
                    if current_parent not in bg_dep_children:
                        bg_dep_children[current_parent] = []
                    if dk not in bg_dep_children[current_parent]:
                        bg_dep_children[current_parent].append(dk)

        # Also check sub-deps that are shared across the batch
        for children in bg_dep_children.values():
            for child_dk in children:
                child_count = sum(
                    1 for lb_name in batch_lb_names_g
                    for rt, dn, _ in lb_deps.get(lb_name, [])
                    if (rt, dn) == child_dk
                )
                if child_count > 1:
                    bg_shared.add(child_dk)

        # External deps: deps in this batch referenced by LBs outside the move set
        bg_external = {
            dk for dk in all_deps_in_batch if dk in external_dep_refs
        }

        all_batch_graphs.append(BatchGraphData(
            batch_index=batch_idx,
            lb_names=batch_lb_names_g,
            lb_to_deps=bg_lb_to_deps,
            shared_deps=bg_shared,
            dep_children=bg_dep_children,
            external_deps=bg_external,
        ))

    return all_batch_graphs
