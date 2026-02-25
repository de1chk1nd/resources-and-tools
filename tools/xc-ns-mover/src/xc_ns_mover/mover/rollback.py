"""
Batch-aware rollback logic for the mover subcommand.

When a move fails mid-way, this module undoes any partial changes:
1. Deletes objects that were already created in the target namespace.
2. Re-creates objects that were deleted from the source namespace.
"""

from __future__ import annotations

import logging

import requests

from ..client import XCClient
from ..models import FRIENDLY_TYPE_NAMES, DepMoveResult, MoveResult

__all__ = ["rollback_batch"]

logger = logging.getLogger(__name__)


def rollback_batch(
    client: XCClient,
    src_ns: str,
    target_ns: str,
    deleted_lbs: list[tuple[str, dict]],
    deleted_deps: list[tuple[str, str, dict]],
    created_deps: list[tuple[str, str]],
    created_lbs: list[str],
    lb_results: dict[str, MoveResult],
    dep_results: dict[tuple[str, str], DepMoveResult],
) -> None:
    """Rollback a batch: undo creates in target, re-create deletes in source.

    Order:
      1. Delete any LBs created in target (top-down)
      2. Delete any deps created in target (top-down)
      3. Re-create deps in source from backups (bottom-up = reversed delete order)
      4. Re-create LBs in source from backups (top = last)
    """
    logger.info("ROLLBACK: Cleaning up target namespace...")

    # 1. Delete LBs we created in target
    for lb_name in reversed(created_lbs):
        try:
            client.delete_http_loadbalancer(target_ns, lb_name)
            logger.info("      ROLLBACK: Deleted LB '%s' from '%s'", lb_name, target_ns)
        except requests.RequestException as exc:
            logger.info("ROLLBACK: FAILED to delete LB '%s' from target: %s", lb_name, exc)
            logger.info("      ROLLBACK: FAILED to delete LB '%s' from target: %s", lb_name, exc)

    # 2. Delete deps we created in target
    for rt, dn in reversed(created_deps):
        friendly = FRIENDLY_TYPE_NAMES.get(rt, rt)
        try:
            client.delete_config_object(target_ns, rt, dn)
            logger.info("      ROLLBACK: Deleted %s '%s' from '%s'", friendly, dn, target_ns)
        except requests.RequestException as exc:
            logger.info("ROLLBACK: FAILED to delete %s '%s' from target: %s", friendly, dn, exc)
            logger.info("      ROLLBACK: FAILED to delete %s '%s' from target: %s", friendly, dn, exc)

    logger.info("ROLLBACK: Restoring objects in source namespace...")

    # 3. Re-create deps in source (reversed delete order = bottom-up)
    for resource_type, dep_name, dep_config in reversed(deleted_deps):
        friendly = FRIENDLY_TYPE_NAMES.get(resource_type, resource_type)
        key = (resource_type, dep_name)
        try:
            metadata = XCClient.clean_metadata(dep_config, src_ns)
            spec = XCClient.clean_spec(dep_config)
            client.create_config_object(src_ns, resource_type, metadata, spec)
            logger.info("      ROLLBACK: %s '%s' — restored in '%s'", friendly, dep_name, src_ns)
            if key in dep_results:
                dep_results[key].status = "reverted"
                dep_results[key].error = ""
        except requests.RequestException as exc:
            logger.info("ROLLBACK: %s '%s' — FAILED: %s", friendly, dep_name, exc)
            logger.info("      ROLLBACK: %s '%s' — FAILED: %s", friendly, dep_name, exc)
            if key in dep_results:
                dep_results[key].error += f" | ROLLBACK FAILED: {exc}"

    # 4. Re-create LBs in source
    for lb_name, lb_config in reversed(deleted_lbs):
        try:
            metadata = XCClient.clean_metadata(lb_config, src_ns)
            spec = XCClient.clean_spec(lb_config)
            client.create_http_loadbalancer(src_ns, metadata, spec)
            logger.info("      ROLLBACK: LB '%s' — restored in '%s'", lb_name, src_ns)
            if lb_name in lb_results:
                lb_results[lb_name].status = "reverted"
                # Fetch new CNAME (may differ from original)
                try:
                    restored = client.get_http_loadbalancer(src_ns, lb_name)
                    lb_results[lb_name].cname_new = XCClient.extract_cname(restored)
                    lb_results[lb_name].acme_cname_new = XCClient.extract_acme_cname(restored)
                except requests.RequestException as _rb_exc:
                    logger.debug(
                        "ROLLBACK: Could not fetch CNAME for restored LB '%s': %s",
                        lb_name, _rb_exc,
                    )
                    lb_results[lb_name].cname_new = "(fetch failed after rollback)"
                    lb_results[lb_name].acme_cname_new = "(fetch failed after rollback)"
        except requests.RequestException as exc:
            logger.info("ROLLBACK: LB '%s' — FAILED: %s", lb_name, exc)
            logger.info("      ROLLBACK: LB '%s' — FAILED: %s", lb_name, exc)
            if lb_name in lb_results:
                lb_results[lb_name].error += f" | ROLLBACK FAILED: {exc}"
