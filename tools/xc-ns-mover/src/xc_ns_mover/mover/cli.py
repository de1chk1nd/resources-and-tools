"""
CLI entry point and orchestration for the mover subcommand.

Moves HTTP load balancers and their dependencies between namespaces.

LBs that share dependencies (e.g. origin pools, health checks) are
automatically grouped into **batches** and moved together as an atomic
unit.  This is required because XC enforces referential integrity — you
cannot delete an origin pool that is still referenced by another LB.

Processing order per batch:
  Phase 0  — Discovery & clustering (runs once for all LBs)
  Phase 0b — Cross-reference scan for external referrers
  Phase 0c — Certificate secret detection + conflict detection in target namespace
  Phase 0d — Certificate private key pre-flight (domain matching in target/shared)
  Phase 0e — DNS zone pre-flight (managed DNS detection)
  Phase 1  — Backup all LB + dependency configs
  Phase 2  — Safety checks (referring-objects)
  Phase 3  — DELETE top-down: all LBs first, then deps (parents before leaves)
  Phase 4  — CREATE bottom-up: leaf deps first, then parent deps, then all LBs
  Phase 5  — Verify new CNAMEs
  On failure at any point — ROLLBACK everything in the batch

In --dry-run mode, no changes are made and the planned JSON config is
included in the report.

Generates an HTML report with before/after details, backup configs, and
warnings about CNAME / ACME challenge changes.
Asks for confirmation per batch unless --force-all is given.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime

import requests

from ..config import DEFAULT_CONFIG_PATH, PROJECT_ROOT, ConfigError, load_config, validate_xc_name
from ..client import XCClient
from ..spec_utils import rewrite_name_refs, rewrite_cert_ref
from ..logging_setup import setup_logging
from ..models import (
    FRIENDLY_TYPE_NAMES,
    BatchGraphData,
    DepMoveResult,
    ManualReworkItem,
    MoveResult,
)
from .fingerprint import (
    compute_fingerprint,
    write_fingerprint,
    read_fingerprint,
    delete_fingerprint,
)
from .conflict import resolve_conflict
from .rollback import rollback_batch
from .orchestrator import (
    discover_lbs_and_deps,
    cluster_batches,
    scan_external_references,
    detect_nonportable_certs,
    match_certificates,
    scan_dns_zones,
    build_batch_graphs,
)
from ..report.mover_report import generate_mover_report

logger = logging.getLogger(__name__)

# Fixed path for the mover input CSV — always in config/
MOVER_CSV_PATH = os.path.join(PROJECT_ROOT, "config", "xc-mover.csv")


# ------------------------------------------------------------------
# Backward-compat alias (internal references use _FRIENDLY_TYPE_NAMES)
# ------------------------------------------------------------------
_FRIENDLY_TYPE_NAMES = FRIENDLY_TYPE_NAMES


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Move HTTP load balancers (and their dependencies) to a new namespace. "
            "Reads config/xc-mover.csv and re-creates each LB in the target namespace. "
            "LBs that share dependencies are automatically batched together."
        ),
    )
    parser.add_argument(
        "--config",
        "-c",
        default=DEFAULT_CONFIG_PATH,
        help="Path to YAML config file (default: config/config.yaml)",
    )
    parser.add_argument(
        "--force-all",
        action="store_true",
        help="Skip per-batch confirmation prompts — move everything without asking",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Simulate the move without making any changes. "
            "Generates the HTML report with planned configs."
        ),
    )
    parser.add_argument(
        "--conflict-action",
        choices=["ask", "skip", "prefix"],
        default="ask",
        help=(
            "Action when a name conflict is detected in the target namespace. "
            "'ask' (default): prompt interactively per object. "
            "'skip': automatically skip conflicting objects. "
            "'prefix': automatically rename using the conflict_prefix from config. "
            "For batch/CI jobs use 'skip' or 'prefix' to avoid interactive prompts."
        ),
    )
    parser.add_argument(
        "--skip-dry-run",
        action="store_true",
        help=(
            "Skip the dry-run verification check. By default the mover "
            "requires a prior --dry-run with the same configuration. "
            "Use this flag to bypass that check (e.g. in CI/CD pipelines)."
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose (debug) logging",
    )
    return parser.parse_args()


def _read_csv(csv_path: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    with open(csv_path, newline="") as f:
        lines = [line for line in f if not line.lstrip().startswith("#")]
    if not lines:
        return entries
    reader = csv.DictReader(lines)
    for row_num, row in enumerate(reader, 2):  # line 1 = header
        ns = row.get("namespace", "").strip()
        name = row.get("lb_name", "").strip()
        if not ns or not name:
            continue
        validate_xc_name(ns, f"namespace on CSV line {row_num}")
        validate_xc_name(name, f"lb_name on CSV line {row_num}")
        entries.append((ns, name))
    return entries


def _print_step(label: str, result: str = "") -> None:
    """Print a pre-flight step with a compact result, overwriting the 'running' line."""
    if result:
        # Final line — overwrite in-progress text
        sys.stdout.write(f"\r  {label:<48s} {result}\n")
    else:
        # In-progress — no newline, will be overwritten
        sys.stdout.write(f"\r  {label:<48s} ...")
    sys.stdout.flush()


def _print_progress(current: int, total: int, width: int = 40) -> None:
    """Print an in-place progress bar: [=====>          ] 3 of 10 LBs done"""
    if total == 0:
        return
    frac = current / total
    filled = int(width * frac)
    bar = "=" * filled
    if filled < width:
        bar += ">"
    bar = bar.ljust(width)
    line = f"\r  [{bar}] {current} of {total} load balancer(s) done"
    sys.stdout.write(line)
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")


def _confirm(prompt: str) -> bool:
    while True:
        answer = input(f"{prompt} [y/n]: ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main() -> None:
    args = _parse_args()

    log_path = setup_logging(verbose=args.verbose, log_prefix="mover")

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        sys.exit(1)

    tenant_name = cfg["tenant"]["name"]
    api_token = cfg["auth"]["api_token"]
    api_url = f"https://{tenant_name}.console.ves.volterra.io"

    mover_cfg = cfg.get("mover", {}) or {}
    target_namespace = (mover_cfg.get("target_namespace") or "").strip()
    conflict_prefix = (mover_cfg.get("conflict_prefix") or "").strip()
    conflict_action = args.conflict_action

    if not target_namespace:
        logger.error("mover.target_namespace is not set in config.")
        sys.exit(1)
    validate_xc_name(target_namespace, "mover.target_namespace")

    if conflict_action == "prefix" and not conflict_prefix:
        logger.error(
            "--conflict-action=prefix requires mover.conflict_prefix to be set in config."
        )
        sys.exit(1)

    if conflict_action == "ask" and not conflict_prefix:
        # Prefix is optional in ask mode — but if missing, we can only skip
        logger.info(
            "mover.conflict_prefix is not set — conflicts can only be resolved by skipping."
        )

    input_csv = MOVER_CSV_PATH
    if not os.path.isfile(input_csv):
        logger.error(
            "Input CSV not found: %s\n"
            "Copy config/xc-mover.csv.example to config/xc-mover.csv and add your LBs.",
            input_csv,
        )
        sys.exit(1)

    entries = _read_csv(input_csv)
    if not entries:
        print("No HTTP load balancers found in CSV — nothing to do.")
        return

    report_dir = cfg.get("report", {}).get("output_dir", "reports")
    if not os.path.isabs(report_dir):
        report_dir = os.path.join(PROJECT_ROOT, report_dir)

    dry_run = args.dry_run

    print(f"Tenant:           {tenant_name}")
    print(f"Input CSV:        {input_csv}")
    print(f"Target namespace: {target_namespace}")
    print(f"LBs to move:      {len(entries)}")
    if conflict_prefix:
        print(f"Conflict prefix:  {conflict_prefix}")
    print(f"Conflict action:  {conflict_action}")
    if dry_run:
        print(f"Mode:             DRY RUN (no changes will be made)")
    print(f"Log file:         {log_path}")
    print()

    # ------------------------------------------------------------------
    # Dry-run verification: ensure a dry-run was executed before a real run
    # ------------------------------------------------------------------
    dryrun_verified = False
    current_fingerprint = compute_fingerprint(tenant_name, target_namespace, input_csv)

    if dry_run:
        # Dry-run mode — fingerprint will be written at the end
        pass
    elif args.skip_dry_run:
        # User explicitly skipped the dry-run check
        print("Dry-run check:    SKIPPED (--skip-dry-run)")
        logger.info("Dry-run verification skipped by user (--skip-dry-run).")
    else:
        stored_fp, stored_ts = read_fingerprint()
        if stored_fp == current_fingerprint:
            # Fingerprint matches — dry-run was done with same config
            dryrun_verified = True
            print(f"Dry-run check:    VERIFIED (fingerprint match, dry-run from {stored_ts})")
        elif stored_fp:
            # Fingerprint exists but doesn't match — config changed
            print()
            print("=" * 70)
            print("WARNING: Configuration has changed since the last dry-run!")
            print(f"  Last dry-run: {stored_ts}")
            print(f"  Stored fingerprint:  {stored_fp}")
            print(f"  Current fingerprint: {current_fingerprint}")
            print()
            print("The CSV, target namespace, or tenant has been modified.")
            print("It is strongly recommended to re-run with --dry-run first.")
            print()
            print("To continue without a matching dry-run, type SKIP-DRYRUN")
            print("=" * 70)
            answer = input("  > ").strip()
            if answer != "SKIP-DRYRUN":
                print("Aborted. Run with --dry-run first.")
                sys.exit(0)
            print()
            logger.info("Dry-run verification overridden by user (config changed).")
        else:
            # No fingerprint at all — no dry-run was ever done
            print()
            print("=" * 70)
            print("WARNING: No dry-run has been performed for this configuration!")
            print()
            print("A dry-run (--dry-run) generates a detailed report showing")
            print("exactly what will be moved, which dependencies are affected,")
            print("and whether any certificates require manual rework.")
            print()
            print("It is strongly recommended to review the dry-run report")
            print("before making any changes.")
            print()
            print("To continue without a dry-run, type SKIP-DRYRUN")
            print("=" * 70)
            answer = input("  > ").strip()
            if answer != "SKIP-DRYRUN":
                print("Aborted. Run with --dry-run first.")
                sys.exit(0)
            print()
            logger.info("Dry-run verification overridden by user (no prior dry-run).")

    to_move = [(ns, name) for ns, name in entries if ns != target_namespace]
    skipped_same_ns = len(entries) - len(to_move)
    if skipped_same_ns:
        print(
            f"Skipping {skipped_same_ns} LB(s) already in target namespace "
            f"'{target_namespace}'"
        )
    if not to_move:
        print("All LBs are already in the target namespace — nothing to do.")
        return

    move_set: set[tuple[str, str]] = set(to_move)
    client = XCClient(api_url, api_token)

    # ==================================================================
    # Phase 0: Discovery — GET all LB configs + deps, cluster into batches
    # ==================================================================
    print("Pre-flight checks:")
    _print_step("Discovering load balancers & dependencies")

    lb_configs, lb_deps, discovery_failed = discover_lbs_and_deps(client, to_move)
    batches, dep_to_lbs = cluster_batches(lb_deps)

    # Build src_ns lookup (all LBs in our list come from the same ns in practice,
    # but we store per-LB to be safe)
    lb_src_ns: dict[str, str] = {name: ns for ns, name in to_move}

    _total_dep_count = sum(len(v) for v in lb_deps.values())
    _print_step(
        "Discovering load balancers & dependencies",
        f"{len(lb_configs)} LB(s), {_total_dep_count} dep(s), {len(batches)} batch(es)",
    )

    # ==================================================================
    # Phase 0b: Cross-reference scan
    # ==================================================================
    _print_step("Scanning external references")
    external_dep_refs = scan_external_references(client, to_move, lb_deps)
    _ext_ref_count = len(external_dep_refs)
    _print_step(
        "Scanning external references",
        f"{_ext_ref_count} external ref(s)" if _ext_ref_count else "none found",
    )

    # ==================================================================
    # Phase 0d-detect: Identify non-portable certificates
    # ==================================================================
    _print_step("Scanning certificates")
    secret_cert_keys, secret_cert_configs, secret_cert_lb_map, secret_cert_reasons = (
        detect_nonportable_certs(client, lb_deps)
    )
    _total_cert_deps = sum(
        1 for deps in lb_deps.values() for rt, _, _ in deps if rt == "certificates"
    )
    _print_step(
        "Scanning certificates",
        f"{_total_cert_deps} scanned, {len(secret_cert_keys)} non-portable"
        if _total_cert_deps else "none found",
    )

    # ==================================================================
    # Phase 0c: Conflict detection — check for existing objects with
    # the same names in the target namespace.  When a conflict is found,
    # the user is prompted (or auto-resolved via --conflict-action) to
    # either skip the object or rename it with the configured prefix.
    # ==================================================================
    _print_step("Checking conflicts in target namespace")
    logger.info("Checking for name conflicts in target namespace...")

    # Rename maps: original_name -> new_name (only for objects that need renaming)
    lb_rename_map: dict[str, str] = {}      # lb_name -> new_lb_name
    dep_rename_map: dict[tuple[str, str], str] = {}  # (resource_type, dep_name) -> new_dep_name
    conflict_skipped_lbs: set[str] = set()
    conflict_skipped_deps: set[tuple[str, str]] = set()

    # Collect existing names in target namespace (per resource type)
    existing_lb_names = client.list_http_loadbalancer_names(target_namespace)
    existing_dep_names: dict[str, set[str]] = {}  # resource_type -> set of names

    # Collect all dep resource types we need to check
    dep_resource_types: set[str] = set()
    for deps_list in lb_deps.values():
        for rt, _, _ in deps_list:
            dep_resource_types.add(rt)

    for rt in dep_resource_types:
        existing_dep_names[rt] = client.list_config_object_names(target_namespace, rt)

    # Check LB conflicts
    conflict_count = 0
    for lb_name in list(lb_deps.keys()):
        if lb_name in existing_lb_names:
            conflict_count += 1
            if not conflict_prefix and conflict_action == "ask":
                print(f"    CONFLICT: HTTP LB '{lb_name}' already exists in '{target_namespace}' — skipping (no conflict_prefix configured)")
                conflict_skipped_lbs.add(lb_name)
            else:
                resolution = resolve_conflict(
                    "HTTP LB", lb_name, conflict_prefix, conflict_action,
                )
                if resolution is None:
                    conflict_skipped_lbs.add(lb_name)
                else:
                    lb_rename_map[lb_name] = resolution

    # Check dep conflicts
    for lb_name in lb_deps:
        if lb_name in conflict_skipped_lbs:
            continue
        for rt, dep_name, _ in lb_deps[lb_name]:
            dep_key = (rt, dep_name)
            if dep_key in dep_rename_map or dep_key in conflict_skipped_deps:
                continue  # already resolved
            # Skip non-portable certificates — they are never created in the
            # target namespace, so a same-name object there is expected (it's
            # the cert we want to match against in Phase 0d).
            if dep_key in secret_cert_keys:
                continue
            existing = existing_dep_names.get(rt, set())
            if dep_name in existing:
                conflict_count += 1
                friendly = _FRIENDLY_TYPE_NAMES.get(rt, rt)
                if not conflict_prefix and conflict_action == "ask":
                    print(f"    CONFLICT: {friendly} '{dep_name}' already exists in '{target_namespace}' — skipping (no conflict_prefix configured)")
                    conflict_skipped_deps.add(dep_key)
                else:
                    resolution = resolve_conflict(
                        friendly, dep_name, conflict_prefix, conflict_action,
                    )
                    if resolution is None:
                        conflict_skipped_deps.add(dep_key)
                    else:
                        dep_rename_map[dep_key] = resolution

    if conflict_count == 0:
        logger.info("No name conflicts found.")
        _print_step("Checking conflicts in target namespace", "none found")
    else:
        renamed_count = len(lb_rename_map) + len(dep_rename_map)
        skipped_count = len(conflict_skipped_lbs) + len(conflict_skipped_deps)
        logger.info("Conflicts found: %d  Renamed: %d  Skipped: %d", conflict_count, renamed_count, skipped_count)
        _conflict_parts = []
        if renamed_count:
            _conflict_parts.append(f"{renamed_count} renamed")
        if skipped_count:
            _conflict_parts.append(f"{skipped_count} skipped")
        _print_step(
            "Checking conflicts in target namespace",
            f"{conflict_count} conflict(s): {', '.join(_conflict_parts)}",
        )

    # If a dep is skipped due to conflict, check if any LB referencing it
    # can still be moved.  A skipped dep means the existing one in the
    # target ns will be used (it already exists), so the LB can still be
    # moved — it will reference the pre-existing object.  But if a whole
    # LB is skipped, all its deps that aren't shared with other LBs can
    # also be skipped.
    #
    # Remove conflict-skipped LBs from the move set and their batches.
    if conflict_skipped_lbs:
        # Remove from to_move, lb_deps, lb_configs, etc.
        to_move = [(ns, name) for ns, name in to_move if name not in conflict_skipped_lbs]
        move_set = set(to_move)

        # Rebuild batches without the skipped LBs
        for lb_name in conflict_skipped_lbs:
            lb_deps.pop(lb_name, None)

        # Re-cluster after removing skipped LBs
        batches, dep_to_lbs = cluster_batches(lb_deps)
        lb_src_ns = {name: ns for ns, name in to_move}

    if not to_move:
        print("All LBs skipped due to conflicts — nothing to do.")
        return

    # ==================================================================
    # Phase 0d: Certificate private key pre-flight — matching
    # ==================================================================
    if secret_cert_keys:
        _print_step("Matching certificates in target/shared")
    manual_rework_items, cert_blocked_lbs = match_certificates(
        client, secret_cert_keys, secret_cert_configs, secret_cert_lb_map,
        secret_cert_reasons, lb_configs, lb_src_ns, target_namespace, batches,
    )
    if secret_cert_keys:
        # Remove non-portable certs from external_dep_refs
        for key in secret_cert_keys:
            external_dep_refs.pop(key, None)
        _matched = sum(1 for i in manual_rework_items.values() if i.matched_cert_name)
        _unmatched = len(manual_rework_items) - _matched
        _print_step(
            "Matching certificates in target/shared",
            f"{_matched} of {len(secret_cert_keys)} matched"
            + (f", {_unmatched} blocked" if _unmatched else ""),
        )

    # ==================================================================
    # Phase 0e: DNS zone pre-flight
    # ==================================================================
    _print_step("Scanning DNS zones")
    zone_configs, managed_zones, dns_managed_lbs = scan_dns_zones(client, lb_configs)
    if not zone_configs and not managed_zones:
        _print_step("Scanning DNS zones", "unavailable (no permission)")
    elif managed_zones:
        _print_step(
            "Scanning DNS zones",
            f"{len(zone_configs)} zone(s), {len(managed_zones)} managed",
        )
    else:
        _print_step(
            "Scanning DNS zones",
            f"{len(zone_configs)} zone(s), none managed",
        )
    print()

    # Build BatchGraphData for the report
    all_batch_graphs = build_batch_graphs(
        batches, lb_deps, lb_configs, lb_src_ns, external_dep_refs,
    )

    # ==================================================================
    # Process each batch
    # ==================================================================

    results: list[MoveResult] = []
    total_moved = 0
    total_failed = 0
    total_reverted = 0
    total_skipped = 0

    # Add results for LBs that failed discovery
    for lb_name in discovery_failed:
        src_ns_lookup = {name: ns for ns, name in entries}
        src_ns = src_ns_lookup.get(lb_name, "?")
        result = MoveResult(
            lb_name=lb_name, src_namespace=src_ns, dst_namespace=target_namespace,
            status="failed", error="Failed to retrieve load balancer configuration from the API during initial discovery. Check that the LB name and namespace in the CSV are correct and that the API token has read access.",
        )
        results.append(result)
        total_failed += 1

    # Add results for LBs skipped due to name conflicts
    for lb_name in conflict_skipped_lbs:
        src_ns_lookup = {name: ns for ns, name in entries}
        src_ns = src_ns_lookup.get(lb_name, "?")
        result = MoveResult(
            lb_name=lb_name, src_namespace=src_ns, dst_namespace=target_namespace,
            status="skipped",
            error=f"Skipped due to name conflict — an HTTP load balancer with the name '{lb_name}' already exists in the target namespace '{target_namespace}'. Use --conflict-action=prefix to auto-rename, or remove the existing object first.",
            tls_mode=XCClient.extract_tls_mode(lb_configs.get(lb_name, {})),
            cname_old=XCClient.extract_cname(lb_configs.get(lb_name, {})),
            acme_cname_old=XCClient.extract_acme_cname(lb_configs.get(lb_name, {})),
            domains=XCClient.extract_lb_domains(lb_configs.get(lb_name, {})),
            dns_managed=lb_name in dns_managed_lbs,
            backup_json=json.dumps(lb_configs.get(lb_name, {}), indent=2),
        )
        results.append(result)
        total_skipped += 1

    # Progress tracking
    total_lbs_in_batches = sum(len(b) for b in batches)
    lbs_done = 0

    print(f"\nProcessing {total_lbs_in_batches} load balancer(s) in {len(batches)} batch(es)...")
    if dry_run:
        _print_progress(lbs_done, total_lbs_in_batches)

    for batch_idx, batch_lb_names in enumerate(batches, 1):
        batch_label = ", ".join(batch_lb_names)
        is_multi = len(batch_lb_names) > 1
        batch_tag = f"Batch {batch_idx}/{len(batches)}" if len(batches) > 1 else "Batch"

        if not dry_run:
            if is_multi:
                logger.info("%s: [%s] (shared dependencies — atomic move)", batch_tag, batch_label)
            else:
                logger.info("%s: %s", batch_tag, batch_label)

            # Log rename info for this batch if any renames apply
            batch_renames = []
            for lb_name in batch_lb_names:
                if lb_name in lb_rename_map:
                    batch_renames.append(f"LB '{lb_name}' -> '{lb_rename_map[lb_name]}'")
                for rt, dep_name, _ in lb_deps.get(lb_name, []):
                    dep_key = (rt, dep_name)
                    if dep_key in dep_rename_map:
                        friendly = _FRIENDLY_TYPE_NAMES.get(rt, rt)
                        batch_renames.append(f"{friendly} '{dep_name}' -> '{dep_rename_map[dep_key]}'")
            if batch_renames:
                seen_renames: set[str] = set()
                for r in batch_renames:
                    if r not in seen_renames:
                        seen_renames.add(r)
                        logger.info("  Rename: %s", r)

        # Pre-check: detect if this batch is blocked by unmatched certificates
        # (known from Phase 0d) BEFORE asking the user for confirmation.
        batch_cert_blocked = False
        batch_cert_blocked_reasons: list[str] = []
        for lb_name in batch_lb_names:
            if lb_name in cert_blocked_lbs:
                batch_cert_blocked = True
                # Find which cert(s) caused the block
                for ck, ri in manual_rework_items.items():
                    if not ri.matched_cert_name and lb_name in ri.lb_names:
                        reason = (
                            f"TLS Certificate '{ri.cert_name}' has a non-portable "
                            f"private key ({ri.secret_type}) and no matching "
                            f"certificate was found in the target or shared namespace. "
                            f"Required domains: {', '.join(ri.cert_domains) or '(unknown)'}"
                        )
                        if reason not in batch_cert_blocked_reasons:
                            batch_cert_blocked_reasons.append(reason)

        if batch_cert_blocked:
            # Identify which LBs in this batch actually own the cert problem
            lbs_with_cert_problem: set[str] = set()
            for ck, ri in manual_rework_items.items():
                if not ri.matched_cert_name:
                    for ln in ri.lb_names:
                        if ln in batch_lb_names:
                            lbs_with_cert_problem.add(ln)
            cert_problem_lb_list = sorted(lbs_with_cert_problem)
            cert_problem_lb_ref = ", ".join(f"'{n}'" for n in cert_problem_lb_list[:3])
            if len(cert_problem_lb_list) > 3:
                cert_problem_lb_ref += f" (+{len(cert_problem_lb_list) - 3} more)"

            if not dry_run:
                brief_reason = batch_cert_blocked_reasons[0] if batch_cert_blocked_reasons else "unmatched certificate"
                for lb_name in batch_lb_names:
                    lbs_done += 1
                    print(f"  [{lbs_done}/{total_lbs_in_batches}] BLOCKED: '{lb_name}' — {brief_reason}")
                if not args.force_all:
                    input("    Press Enter to continue...")

            for lb_name in batch_lb_names:
                src_ns = lb_src_ns.get(lb_name, "?")
                lb_config = lb_configs.get(lb_name, {})
                tls_mode = XCClient.extract_tls_mode(lb_config)

                # --- Differentiated error messages ---
                if lb_name in lbs_with_cert_problem:
                    # Case A: This LB itself has the non-portable cert
                    blocked_error = (
                        "Cannot move — this load balancer uses a TLS certificate "
                        "with a non-portable private key and no matching certificate "
                        "was found in the target or shared namespace: "
                        + "; ".join(batch_cert_blocked_reasons)
                        + ". Create the certificate in the target or shared "
                        "namespace first, then re-run the mover."
                    )
                elif tls_mode == "Let's Encrypt":
                    # Case B: Let's Encrypt LB — only blocked because of batch
                    blocked_error = (
                        "Batch blocked — this Let's Encrypt load balancer shares "
                        "dependencies (e.g. origin pools) with "
                        f"{cert_problem_lb_ref} which has a non-portable TLS "
                        "certificate that could not be matched. This LB's "
                        "auto-certificate (Let's Encrypt) is not affected. "
                        f"Resolve the certificate issue on {cert_problem_lb_ref} "
                        "first, then re-run the mover to move the entire batch."
                    )
                else:
                    # Case C: Other LB — only blocked because of batch
                    blocked_error = (
                        "Batch blocked — this load balancer shares dependencies "
                        f"with {cert_problem_lb_ref} which has a non-portable "
                        "TLS certificate that could not be matched. The entire "
                        "batch must be resolved together. Resolve the certificate "
                        f"issue on {cert_problem_lb_ref} first, then re-run the "
                        "mover."
                    )

                result = MoveResult(
                    lb_name=lb_name, src_namespace=src_ns,
                    dst_namespace=target_namespace, status="blocked",
                    error=blocked_error,
                    tls_mode=tls_mode,
                    cname_old=XCClient.extract_cname(lb_config),
                    acme_cname_old=XCClient.extract_acme_cname(lb_config),
                    domains=XCClient.extract_lb_domains(lb_config),
                    dns_managed=lb_name in dns_managed_lbs,
                    backup_json=json.dumps(lb_config, indent=2),
                )
                # Add dep results — with per-object root-cause attribution
                # Build a lookup: which specific cert(s) block this LB?
                _lb_blocking_certs: list[str] = []
                for ck, ri in manual_rework_items.items():
                    if not ri.matched_cert_name and lb_name in ri.lb_names:
                        _lb_blocking_certs.append(ri.cert_name)

                for rt, dep_name, dep_ns in lb_deps.get(lb_name, []):
                    dep_key = (rt, dep_name)
                    dep_status = "manual-rework" if dep_key in secret_cert_keys else "blocked"
                    friendly_dep = _FRIENDLY_TYPE_NAMES.get(rt, rt)
                    if dep_key in secret_cert_keys:
                        dep_err = (
                            f"Non-portable private key "
                            f"({secret_cert_reasons.get(dep_key, '?')}). "
                            f"No matching cert found in target/shared namespace."
                        )
                    elif _lb_blocking_certs:
                        # This dep is collateral — blocked because its parent
                        # LB can't be moved (LB is blocked by cert issue).
                        dep_err = (
                            f"Blocked — parent LB '{lb_name}' cannot be moved "
                            f"(unresolved TLS certificate issue). This "
                            f"{friendly_dep.lower()} will be moved automatically "
                            f"once the LB is unblocked."
                        )
                    else:
                        # Fallback: LB is blocked by a cert on another
                        # LB in the same batch (batch-level cascade).
                        dep_err = (
                            f"Blocked — the batch containing '{lb_name}' "
                            f"cannot be moved (unresolved TLS certificate "
                            f"issue on {cert_problem_lb_ref}). This "
                            f"{friendly_dep.lower()} will be moved automatically "
                            f"once the batch is unblocked."
                        )
                    dep_result = DepMoveResult(
                        resource_type=rt, name=dep_name,
                        status=dep_status, error=dep_err,
                    )
                    result.dependencies.append(dep_result)
                results.append(result)
                if not dry_run:
                    total_failed += 1
            if dry_run:
                lbs_done += len(batch_lb_names)
                _print_progress(lbs_done, total_lbs_in_batches)
            continue

        # Pre-check: detect if this batch is blocked by external dep refs
        # (known from Phase 0b) BEFORE asking the user for confirmation.
        batch_pre_blocked = False
        batch_pre_blocked_reasons: list[str] = []
        for lb_name in batch_lb_names:
            for rt, dep_name, _ in lb_deps.get(lb_name, []):
                dep_key = (rt, dep_name)
                if dep_key in external_dep_refs:
                    friendly = _FRIENDLY_TYPE_NAMES.get(rt, rt)
                    ext_refs = external_dep_refs[dep_key]
                    ref_names = [f"'{n}' ({ns})" for n, ns in ext_refs]
                    ref_summary = ", ".join(ref_names[:5])
                    if len(ref_names) > 5:
                        ref_summary += f" (+{len(ref_names) - 5} more)"
                    reason = (
                        f"{friendly} '{dep_name}' is referenced by external object(s) "
                        f"not in the move list: {ref_summary}"
                    )
                    if reason not in batch_pre_blocked_reasons:
                        batch_pre_blocked_reasons.append(reason)
                    batch_pre_blocked = True

        if batch_pre_blocked:
            if not dry_run:
                # Brief one-liner per LB, detail in verbose mode
                brief_reason = batch_pre_blocked_reasons[0] if batch_pre_blocked_reasons else "external dependency references"
                for lb_name in batch_lb_names:
                    lbs_done += 1
                    print(f"  [{lbs_done}/{total_lbs_in_batches}] BLOCKED: '{lb_name}' — {brief_reason}")
                for reason in batch_pre_blocked_reasons[1:]:
                    logger.info("  Additional block reason: %s", reason)
                if not args.force_all:
                    input("    Press Enter to continue...")
            # Record as blocked and skip
            for lb_name in batch_lb_names:
                src_ns = lb_src_ns.get(lb_name, "?")
                lb_config = lb_configs.get(lb_name, {})
                blocked_error = (
                    f"Cannot move — dependencies are referenced by external objects not in the move list: "
                    + "; ".join(batch_pre_blocked_reasons)
                    + ". Add the referencing objects to the move CSV or remove them first."
                )
                result = MoveResult(
                    lb_name=lb_name, src_namespace=src_ns,
                    dst_namespace=target_namespace, status="blocked",
                    error=blocked_error,
                    tls_mode=XCClient.extract_tls_mode(lb_config),
                    cname_old=XCClient.extract_cname(lb_config),
                    acme_cname_old=XCClient.extract_acme_cname(lb_config),
                    domains=XCClient.extract_lb_domains(lb_config),
                    dns_managed=lb_name in dns_managed_lbs,
                    backup_json=json.dumps(lb_config, indent=2),
                )
                # Add dependency results as blocked
                for rt, dep_name, dep_ns in lb_deps.get(lb_name, []):
                    dep_key = (rt, dep_name)
                    friendly_dep = _FRIENDLY_TYPE_NAMES.get(rt, rt)
                    dep_result = DepMoveResult(
                        resource_type=rt, name=dep_name,
                        status="blocked",
                    )
                    if dep_key in secret_cert_keys:
                        # Non-portable certificate — never moved, only
                        # rewritten.  Show cert-specific status/message.
                        dep_result.status = "manual-rework"
                        rw = manual_rework_items.get(dep_key)
                        if rw and rw.matched_cert_name:
                            dep_result.error = (
                                f"Non-portable {rw.secret_type}. "
                                f"Certificate stays in source namespace — "
                                f"LB reference will be rewritten to "
                                f"'{rw.matched_cert_name}' in "
                                f"'{rw.matched_cert_ns}' once the batch "
                                f"is unblocked."
                            )
                        else:
                            dep_result.error = (
                                f"Non-portable "
                                f"{secret_cert_reasons.get(dep_key, 'private key')}. "
                                f"Certificate stays in source namespace."
                            )
                    elif dep_key in external_dep_refs:
                        ext_refs = external_dep_refs[dep_key]
                        ref_names_d = [f"'{n}' ({ns})" for n, ns in ext_refs]
                        ref_summary_d = ", ".join(ref_names_d[:5])
                        if len(ref_names_d) > 5:
                            ref_summary_d += f" (+{len(ref_names_d) - 5} more)"
                        dep_result.error = (
                            f"Cannot move {friendly_dep} '{dep_name}' — it is referenced by "
                            f"external object(s) not in the move list: {ref_summary_d}. "
                            f"Moving it would break those objects. Either add the referencing "
                            f"objects to the move CSV or remove them first."
                        )
                    else:
                        dep_result.error = (
                            f"Blocked — parent LB '{lb_name}' cannot be moved "
                            f"(another dependency in this batch has external references). "
                            f"This {friendly_dep.lower()} will be moved automatically "
                            f"once the batch is unblocked."
                        )
                    result.dependencies.append(dep_result)
                results.append(result)
                if not dry_run:
                    total_failed += 1
            if dry_run:
                lbs_done += len(batch_lb_names)
                _print_progress(lbs_done, total_lbs_in_batches)
            continue

        # Confirmation
        if not dry_run and not args.force_all:
            src_ns = lb_src_ns.get(batch_lb_names[0], "?")
            if is_multi:
                prompt = f"  Move [{batch_label}] ({src_ns} -> {target_namespace})?"
            else:
                prompt = f"  Move '{batch_lb_names[0]}' ({src_ns} -> {target_namespace})?"
            if not _confirm(prompt):
                for lb_name in batch_lb_names:
                    src_ns = lb_src_ns.get(lb_name, "?")
                    result = MoveResult(
                        lb_name=lb_name, src_namespace=src_ns,
                        dst_namespace=target_namespace, status="skipped",
                    )
                    result.tls_mode = XCClient.extract_tls_mode(lb_configs.get(lb_name, {}))
                    result.cname_old = XCClient.extract_cname(lb_configs.get(lb_name, {}))
                    result.acme_cname_old = XCClient.extract_acme_cname(lb_configs.get(lb_name, {}))
                    result.domains = XCClient.extract_lb_domains(lb_configs.get(lb_name, {}))
                    result.dns_managed = lb_name in dns_managed_lbs
                    result.backup_json = json.dumps(lb_configs.get(lb_name, {}), indent=2)
                    results.append(result)
                    total_skipped += 1
                for lb_name in batch_lb_names:
                    lbs_done += 1
                    print(f"  [{lbs_done}/{total_lbs_in_batches}] SKIPPED: '{lb_name}' — skipped by user")
                continue

        # ==============================================================
        # Phase 1: Backup all LB + dep configs for this batch
        # ==============================================================

        # Collect the merged, de-duplicated dependency list for the batch
        # (preserving BFS order: top-level refs first, sub-deps after)
        seen_deps: set[tuple[str, str]] = set()
        batch_deps_ordered: list[tuple[str, str, str]] = []  # (type, name, ns)
        batch_dep_configs: dict[tuple[str, str], dict] = {}   # key -> full GET config

        batch_results: dict[str, MoveResult] = {}
        batch_dep_results: dict[tuple[str, str], DepMoveResult] = {}

        batch_blocked = False
        batch_backup_failed = False
        blocked_reason = ""

        for lb_name in batch_lb_names:
            src_ns = lb_src_ns.get(lb_name, "?")
            lb_config = lb_configs[lb_name]

            result = MoveResult(
                lb_name=lb_name, src_namespace=src_ns,
                dst_namespace=target_namespace,
                tls_mode=XCClient.extract_tls_mode(lb_config),
                cname_old=XCClient.extract_cname(lb_config),
                acme_cname_old=XCClient.extract_acme_cname(lb_config),
                domains=XCClient.extract_lb_domains(lb_config),
                dns_managed=lb_name in dns_managed_lbs,
                backup_json=json.dumps(lb_config, indent=2),
            )
            batch_results[lb_name] = result

            for resource_type, dep_name, dep_ns in lb_deps.get(lb_name, []):
                key = (resource_type, dep_name)
                friendly = _FRIENDLY_TYPE_NAMES.get(resource_type, resource_type)

                if key in seen_deps:
                    # Shared dep — add a reference to this LB's result but don't re-fetch
                    dep_result = DepMoveResult(
                        resource_type=resource_type, name=dep_name,
                        status="skipped",  # will be updated when the dep is actually moved
                    )
                    # Copy backup_json if we have it
                    if key in batch_dep_results and batch_dep_results[key].backup_json:
                        dep_result.backup_json = ""  # cross-ref, not duplicate
                    result.dependencies.append(dep_result)
                    continue

                seen_deps.add(key)

                # GET the dep config
                try:
                    dep_config = client.get_config_object(dep_ns, resource_type, dep_name)
                except requests.RequestException as exc:
                    dep_result = DepMoveResult(
                        resource_type=resource_type, name=dep_name,
                        status="failed" if not dry_run else "dry-run",
                        error=f"Failed to retrieve dependency configuration from the API: {exc}",
                    )
                    result.dependencies.append(dep_result)
                    batch_dep_results[key] = dep_result
                    logger.info("%s '%s' — FAILED to get config: %s", friendly, dep_name, exc)
                    if not dry_run:
                        batch_backup_failed = True
                    continue

                dep_result = DepMoveResult(
                    resource_type=resource_type, name=dep_name,
                    backup_json=json.dumps(dep_config, indent=2),
                )
                result.dependencies.append(dep_result)
                batch_dep_results[key] = dep_result
                batch_dep_configs[key] = dep_config
                batch_deps_ordered.append((resource_type, dep_name, dep_ns))

                # Safety check: external referrers
                # Skip for non-portable certs — they are NOT being moved,
                # so external referrers are irrelevant.
                if key in secret_cert_keys:
                    if dry_run:
                        dep_result.status = "manual-rework"
                    continue

                # Source 1: referring_objects from the GET (unreliable, may be empty)
                referring = XCClient.extract_referring_objects(dep_config)
                external_refs = XCClient.filter_external_referrers(
                    referring, move_set, src_ns,
                )
                # Source 2: active scan from Phase 0b (reliable)
                if not external_refs and key in external_dep_refs:
                    external_refs = [
                        {"kind": "http_loadbalancer", "namespace": ns, "name": name}
                        for name, ns in external_dep_refs[key]
                    ]
                if external_refs:
                    ref_names = [
                        f"{r.get('kind', '?')}/{r.get('namespace', '?')}/{r.get('name', '?')}"
                        for r in external_refs
                    ]
                    ref_summary = ", ".join(ref_names[:5])
                    if len(ref_names) > 5:
                        ref_summary += f" (+{len(ref_names) - 5} more)"
                    dep_result.status = "blocked"
                    dep_result.error = (
                        f"Cannot move this dependency — it is referenced by {len(external_refs)} external object(s) "
                        f"not included in the move list: {ref_summary}. "
                        f"Moving it would break those objects. Either add the referencing objects to the move CSV or remove them first."
                    )
                    logger.info(
                        "%s '%s' — BLOCKED: referenced by %d external object(s): %s",
                        friendly, dep_name, len(external_refs), ref_summary,
                    )
                    batch_blocked = True
                    blocked_reason = (
                        f"{friendly} '{dep_name}' is referenced by objects outside "
                        f"the move list ({ref_summary}). Moving it would break those "
                        f"objects. Remove them first or add them to the move list."
                    )

                if dry_run and not batch_blocked:
                    dep_result.status = "dry-run"

        # Handle batch-level abort conditions
        if batch_backup_failed and not dry_run:
            logger.info("    FAILED: Could not backup all dependencies — aborting batch.")
            for key, dep_result in batch_dep_results.items():
                if dep_result.status == "":
                    dep_result.status = "failed"
                    dep_result.error = "Batch aborted before any changes were made because one or more dependency configurations could not be retrieved from the source namespace."
            for lb_name, result in batch_results.items():
                result.status = "failed"
                result.error = "Batch aborted — one or more dependency configurations could not be backed up from the source namespace. No changes were made. Check API connectivity and permissions, then retry."
                results.append(result)
                total_failed += 1
                lbs_done += 1
                print(f"  [{lbs_done}/{total_lbs_in_batches}] FAILED: '{lb_name}' — dependency backup failed, no changes made")
            if not args.force_all:
                input("    Press Enter to continue...")
            continue

        if batch_blocked:
            logger.info("BLOCKED: %s", blocked_reason)
            # Mark untouched deps as blocked too
            for key, dep_result in batch_dep_results.items():
                if dep_result.status == "":
                    dep_result.status = "blocked"
                    dep_result.error = f"Batch blocked — cannot proceed because a dependency in this batch is still referenced by external objects: {blocked_reason}"
            for lb_name, result in batch_results.items():
                result.status = "blocked"
                result.error = f"Batch blocked — {blocked_reason}"
                results.append(result)
                if not dry_run:
                    total_failed += 1
            if dry_run:
                lbs_done += len(batch_lb_names)
                _print_progress(lbs_done, total_lbs_in_batches)
            else:
                for lb_name in batch_lb_names:
                    lbs_done += 1
                    print(f"  [{lbs_done}/{total_lbs_in_batches}] BLOCKED: '{lb_name}' — blocked by external dependency references")
                if not args.force_all:
                    input("    Press Enter to continue...")
            continue

        # Prepare planned configs for all LBs
        # Apply rename maps for both LBs and their dependency references.
        lb_planned: dict[str, tuple[dict, dict]] = {}  # lb_name -> (metadata, spec)
        for lb_name in batch_lb_names:
            src_ns = lb_src_ns[lb_name]
            metadata, spec = XCClient.prepare_for_move(
                lb_configs[lb_name], src_ns, target_namespace,
            )

            # Apply LB rename if needed
            new_lb_name = lb_rename_map.get(lb_name)
            if new_lb_name:
                metadata["name"] = new_lb_name
                batch_results[lb_name].new_lb_name = new_lb_name

            # Apply dependency renames in spec references
            for dep_key, new_dep_name in dep_rename_map.items():
                _, old_dep_name = dep_key[0], dep_key[1]
                spec = rewrite_name_refs(spec, dep_key[1], new_dep_name, target_namespace)

            # Rewrite cert references for matched non-portable certificates
            for cert_key, rework_item in manual_rework_items.items():
                if rework_item.matched_cert_name and lb_name in rework_item.lb_names:
                    spec = rewrite_cert_ref(
                        spec,
                        old_name=rework_item.cert_name,
                        new_name=rework_item.matched_cert_name,
                        new_namespace=rework_item.matched_cert_ns,
                    )

            lb_planned[lb_name] = (metadata, spec)
            if dry_run:
                planned_body = {"metadata": metadata, "spec": spec}
                batch_results[lb_name].planned_config_json = json.dumps(planned_body, indent=2)

        # Dry-run: compute planned configs for deps and mark everything
        if dry_run:
            # Build planned configs for all unique deps in the batch
            seen_dep_planned: set[tuple[str, str]] = set()
            for resource_type, dep_name, dep_ns in reversed(batch_deps_ordered):
                key = (resource_type, dep_name)
                if key in seen_dep_planned or key in conflict_skipped_deps:
                    continue
                if key in secret_cert_keys:
                    continue  # non-portable cert — no planned config
                if key not in batch_dep_configs:
                    continue
                seen_dep_planned.add(key)

                src_ns = lb_src_ns[batch_lb_names[0]]
                dep_metadata, dep_spec = XCClient.prepare_for_move(
                    batch_dep_configs[key], src_ns, target_namespace,
                )
                actual_dep_name = dep_rename_map.get(key, dep_name)
                if key in dep_rename_map:
                    dep_metadata["name"] = actual_dep_name
                for sub_key, new_sub_name in dep_rename_map.items():
                    if sub_key != key:
                        dep_spec = rewrite_name_refs(dep_spec, sub_key[1], new_sub_name, target_namespace)

                planned_body = {"metadata": dep_metadata, "spec": dep_spec}
                planned_json = json.dumps(planned_body, indent=2)
                # Set on the canonical DepMoveResult
                if key in batch_dep_results:
                    batch_dep_results[key].planned_config_json = planned_json

            for lb_name, result in batch_results.items():
                result.status = "dry-run"
                results.append(result)
                total_moved += 1
            # Mark shared dep references as dry-run too, and apply
            # conflict-skip / rename info for deps.
            # Also propagate planned_config_json to dep results on each LB.
            for result in batch_results.values():
                for d in result.dependencies:
                    dep_key = (d.resource_type, d.name)
                    if dep_key in conflict_skipped_deps:
                        d.status = "skipped"
                        d.error = f"Skipped due to name conflict — an object with the name '{d.name}' already exists in the target namespace. The existing object in the target namespace will be used instead."
                    elif dep_key in secret_cert_keys:
                        d.status = "manual-rework"
                        rw = manual_rework_items.get(dep_key)
                        if rw and rw.matched_cert_name:
                            d.error = (
                                f"Non-portable {rw.secret_type}. "
                                f"Will be rewritten to '{rw.matched_cert_name}' "
                                f"in '{rw.matched_cert_ns}'."
                            )
                        else:
                            d.error = (
                                f"Non-portable {secret_cert_reasons.get(dep_key, 'private key')}. "
                                f"Certificate stays in source namespace."
                            )
                    elif d.status == "skipped":
                        d.status = "dry-run"
                    if dep_key in dep_rename_map:
                        d.new_name = dep_rename_map[dep_key]
                    # Propagate planned config from canonical result
                    if dep_key in batch_dep_results and batch_dep_results[dep_key].planned_config_json:
                        d.planned_config_json = batch_dep_results[dep_key].planned_config_json
            lbs_done += len(batch_lb_names)
            _print_progress(lbs_done, total_lbs_in_batches)
            continue

        # ==============================================================
        # Phase 3: DELETE — top-down (all LBs first, then deps)
        # ==============================================================
        logger.info("    Phase 3: Deleting from source (top-down)...")

        deleted_lbs: list[tuple[str, dict]] = []  # (name, backup_config)
        deleted_deps: list[tuple[str, str, dict]] = []  # (type, name, backup_config)
        delete_failed = False

        # 3a. Delete all LBs in the batch
        for lb_name in batch_lb_names:
            src_ns = lb_src_ns[lb_name]
            try:
                client.delete_http_loadbalancer(src_ns, lb_name)
                deleted_lbs.append((lb_name, lb_configs[lb_name]))
                logger.info("      Deleted LB '%s' from '%s'", lb_name, src_ns)
            except requests.RequestException as exc:
                logger.info("FAILED to delete LB '%s': %s", lb_name, exc)
                batch_results[lb_name].error = f"Failed to delete load balancer from source namespace: {exc}"
                delete_failed = True
                break

        if delete_failed:
            logger.info("Delete failed — rolling back batch...")
            rollback_batch(
                client, lb_src_ns[batch_lb_names[0]], target_namespace,
                deleted_lbs, deleted_deps, [], [],
                batch_results, batch_dep_results,
                
            )
            for key, dep_result in batch_dep_results.items():
                if dep_result.status == "":
                    dep_result.status = "failed"
                    dep_result.error = "Batch aborted — the load balancer could not be deleted from the source namespace. No changes were made to dependencies. A rollback was attempted for any already-deleted LBs."
            for lb_name, result in batch_results.items():
                if result.status != "reverted":
                    result.status = "failed"
                    if not result.error:
                        result.error = "Batch aborted — failed to delete one or more load balancers from the source namespace. A rollback was attempted to restore any already-deleted objects."
                results.append(result)
                if result.status == "reverted":
                    total_reverted += 1
                else:
                    total_failed += 1
                lbs_done += 1
                status_label = "REVERTED" if result.status == "reverted" else "FAILED"
                print(f"  [{lbs_done}/{total_lbs_in_batches}] {status_label}: '{lb_name}' — delete from source failed, rolled back")
            if not args.force_all:
                input("    Press Enter to continue...")
            continue

        # 3b. Pre-flight: re-check referring_objects for each dep.
        #
        # At this point all LBs in the batch have been deleted, so the
        # only remaining referrers are objects OUTSIDE our move set.
        # The referring_objects field on the GET may have been stale
        # before, but now that the LBs are gone any remaining entries
        # are genuine external blockers.
        #
        # We also try a DELETE with fail_if_referred=True as a second
        # check — if the API returns 409, something still holds a ref.
        # (This won't accidentally delete because there IS a referrer.)
        blocked_dep_key: tuple[str, str] | None = None
        for resource_type, dep_name, dep_ns in batch_deps_ordered:
            key = (resource_type, dep_name)
            friendly = _FRIENDLY_TYPE_NAMES.get(resource_type, resource_type)

            # Skip deps that were conflict-skipped (existing in target, not deleted)
            if key in conflict_skipped_deps:
                continue

            # Skip non-portable certificates — they stay in the source namespace
            if key in secret_cert_keys:
                batch_dep_results[key].status = "manual-rework"
                rw = manual_rework_items.get(key)
                if rw and rw.matched_cert_name:
                    batch_dep_results[key].error = (
                        f"Non-portable {rw.secret_type}. "
                        f"Matched to '{rw.matched_cert_name}' in '{rw.matched_cert_ns}'."
                    )
                else:
                    batch_dep_results[key].error = (
                        f"Non-portable {secret_cert_reasons.get(key, 'private key')}. "
                        f"Certificate stays in source namespace."
                    )
                logger.info(
                    "      Keeping %s '%s' in source (non-portable private key)",
                    friendly, dep_name,
                )
                continue

            # Re-fetch to get current referring_objects (LBs are now gone)
            try:
                fresh_config = client.get_config_object(dep_ns, resource_type, dep_name)
            except requests.RequestException:
                fresh_config = {}
            referring = XCClient.extract_referring_objects(fresh_config)

            # Filter: ignore system/shared, ignore objects in move_set
            external = [
                r for r in referring
                if r.get("namespace", "") not in ("system", "shared")
                and (r.get("namespace", ""), r.get("name", "")) not in move_set
            ]

            if not external:
                # referring_objects says clear — but it can be unreliable.
                # Do a probing delete with fail_if_referred=True as final check.
                # If there ARE referrers, 409 is returned (object NOT deleted).
                # If there are none, the object IS deleted — we note this so
                # the actual delete step can skip it.
                referrers = client.probe_delete_config_object(
                    dep_ns, resource_type, dep_name,
                )
                if not referrers:
                    # Probe succeeded = object was actually deleted by the probe
                    deleted_deps.append((resource_type, dep_name, batch_dep_configs[key]))
                    batch_dep_results[key].status = "moved"
                    logger.info("      Deleted %s '%s' from '%s' (pre-flight)", friendly, dep_name, dep_ns)
                    continue
                external = referrers

            # We have external referrers — this dep cannot be moved
            # Mark in graph data for visual indicator
            all_batch_graphs[batch_idx - 1].external_deps.add(key)

            ref_names = [
                f"{r.get('kind', '?')}/{r.get('namespace', '?')}/{r.get('name', '?')}"
                if 'raw' not in r else r['raw'][:80]
                for r in external
            ]
            ref_summary = ", ".join(ref_names[:5])
            if len(ref_names) > 5:
                ref_summary += f" (+{len(ref_names) - 5} more)"
            logger.info("      %s '%s' — BLOCKED: still referenced  by external object(s): %s", friendly, dep_name, ref_summary)
            batch_dep_results[key].status = "blocked"
            batch_dep_results[key].error = (
                f"Cannot move this dependency — it is still referenced by {len(external)} "
                f"external object(s) not included in the move list: {ref_summary}. "
                f"These external objects would break if the dependency were removed. "
                f"Either add the referencing objects to the move CSV or remove them first."
            )
            blocked_dep_key = key
            blocked_reason = (
                f"{friendly} '{dep_name}' is still referenced by objects "
                f"outside the move list ({ref_summary}). These objects "
                f"must be removed first or added to the move CSV."
            )
            break

        if blocked_dep_key is not None:
            logger.info("BLOCKED (after LB delete): %s", blocked_reason)
            logger.info("Rolling back...")
            src_ns = lb_src_ns[batch_lb_names[0]]
            rollback_batch(
                client, src_ns, target_namespace,
                deleted_lbs, deleted_deps, [], [],
                batch_results, batch_dep_results,
                
            )
            # Mark all deps that weren't touched yet as blocked
            for key, dep_result in batch_dep_results.items():
                if dep_result.status == "":
                    dep_result.status = "blocked"
                    dep_result.error = f"Batch blocked after LB deletion — a dependency is still referenced by external objects. All changes were rolled back. Details: {blocked_reason}"
            for lb_name, result in batch_results.items():
                if result.status != "reverted":
                    result.status = "blocked"
                    result.error = f"Batch blocked after LB deletion — a dependency could not be moved because it is still referenced by external objects. All changes were rolled back. Details: {blocked_reason}"
                results.append(result)
                if result.status == "reverted":
                    total_reverted += 1
                else:
                    total_failed += 1
                lbs_done += 1
                status_label = "REVERTED" if result.status == "reverted" else "BLOCKED"
                print(f"  [{lbs_done}/{total_lbs_in_batches}] {status_label}: '{lb_name}' — dependency blocked by external refs, rolled back")
            if not args.force_all:
                input("    Press Enter to continue...")
            continue

        # 3b-actual. Delete remaining deps not already deleted by the probe
        already_deleted = {(rt, dn) for rt, dn, _ in deleted_deps}
        for resource_type, dep_name, dep_ns in batch_deps_ordered:
            key = (resource_type, dep_name)
            if key in already_deleted:
                continue  # already removed by the pre-flight probe
            if key in conflict_skipped_deps:
                continue  # existing in target — do not delete from source
            if key in secret_cert_keys:
                continue  # non-portable cert — stays in source namespace
            friendly = _FRIENDLY_TYPE_NAMES.get(resource_type, resource_type)
            try:
                client.delete_config_object(dep_ns, resource_type, dep_name)
                deleted_deps.append((resource_type, dep_name, batch_dep_configs[key]))
                logger.info("      Deleted %s '%s' from '%s'", friendly, dep_name, dep_ns)
            except requests.RequestException as exc:
                logger.info("FAILED to delete %s '%s': %s", friendly, dep_name, exc)
                batch_dep_results[key].status = "failed"
                batch_dep_results[key].error = f"Failed to delete dependency from source namespace: {exc}"
                delete_failed = True
                break

        if delete_failed:
            logger.info("Dependency delete failed — rolling back batch...")
            src_ns = lb_src_ns[batch_lb_names[0]]
            rollback_batch(
                client, src_ns, target_namespace,
                deleted_lbs, deleted_deps, [], [],
                batch_results, batch_dep_results,
                
            )
            for key, dep_result in batch_dep_results.items():
                if dep_result.status == "":
                    dep_result.status = "failed"
                    dep_result.error = "Batch aborted — a dependency could not be deleted from the source namespace. A rollback was attempted to restore all objects to their original state."
            for lb_name, result in batch_results.items():
                if result.status != "reverted":
                    result.status = "failed"
                    if not result.error:
                        result.error = "Batch aborted — a dependency could not be deleted from the source namespace. A rollback was attempted to restore all objects (LBs and dependencies) to their original state."
                results.append(result)
                if result.status == "reverted":
                    total_reverted += 1
                else:
                    total_failed += 1
                lbs_done += 1
                status_label = "REVERTED" if result.status == "reverted" else "FAILED"
                print(f"  [{lbs_done}/{total_lbs_in_batches}] {status_label}: '{lb_name}' — dependency delete failed, rolled back")
            if not args.force_all:
                input("    Press Enter to continue...")
            continue

        # ==============================================================
        # Phase 4: CREATE — bottom-up (leaf deps first, then LBs last)
        # ==============================================================
        logger.info("    Phase 4: Creating in '%s' (bottom-up)...", target_namespace)

        created_deps: list[tuple[str, str]] = []
        created_lbs: list[str] = []
        create_failed = False

        # 4a. Create deps in reversed discovery order (bottom-up)
        for resource_type, dep_name, dep_ns in reversed(batch_deps_ordered):
            key = (resource_type, dep_name)
            friendly = _FRIENDLY_TYPE_NAMES.get(resource_type, resource_type)

            # If this dep was conflict-skipped, leave the existing one in target
            if key in conflict_skipped_deps:
                batch_dep_results[key].status = "skipped"
                batch_dep_results[key].error = f"Skipped due to name conflict — an object with the name '{dep_name}' already exists in the target namespace. The existing object in the target namespace will be referenced by the moved load balancer(s) instead."
                logger.info("      Skipped %s '%s' (exists in target, using existing)", friendly, dep_name)
                continue

            # Skip non-portable certificates — not created in target
            if key in secret_cert_keys:
                logger.info("      Skipped %s '%s' (non-portable private key, stays in source)", friendly, dep_name)
                continue

            src_ns = lb_src_ns[batch_lb_names[0]]
            dep_metadata, dep_spec = XCClient.prepare_for_move(
                batch_dep_configs[key], src_ns, target_namespace,
            )

            # Apply dep rename if needed
            actual_dep_name = dep_rename_map.get(key, dep_name)
            if key in dep_rename_map:
                dep_metadata["name"] = actual_dep_name
                batch_dep_results[key].new_name = actual_dep_name

            # Apply renames of sub-dependencies within this dep's spec
            for sub_key, new_sub_name in dep_rename_map.items():
                if sub_key != key:
                    dep_spec = rewrite_name_refs(dep_spec, sub_key[1], new_sub_name, target_namespace)

            try:
                client.create_config_object(
                    target_namespace, resource_type, dep_metadata, dep_spec,
                )
                created_deps.append((resource_type, actual_dep_name))
                batch_dep_results[key].status = "moved"
                if actual_dep_name != dep_name:
                    logger.info("Created %s '%s' as '%s' in '%s'", friendly, dep_name, actual_dep_name, target_namespace)
                else:
                    logger.info("Created %s '%s' in '%s'", friendly, dep_name, target_namespace)
            except requests.RequestException as exc:
                logger.info("FAILED to create %s '%s': %s", friendly, actual_dep_name, exc)
                batch_dep_results[key].status = "failed"
                batch_dep_results[key].error = f"Failed to create dependency in the target namespace: {exc}"
                create_failed = True
                break

        if create_failed:
            logger.info("Dep create failed — rolling back batch...")
            src_ns = lb_src_ns[batch_lb_names[0]]
            rollback_batch(
                client, src_ns, target_namespace,
                deleted_lbs, deleted_deps, created_deps, created_lbs,
                batch_results, batch_dep_results,
                
            )
            for key, dep_result in batch_dep_results.items():
                if dep_result.status == "":
                    dep_result.status = "failed"
                    dep_result.error = "Batch aborted — a dependency could not be created in the target namespace. A rollback was attempted to restore all objects to their original state in the source namespace."
            for lb_name, result in batch_results.items():
                if result.status != "reverted":
                    result.status = "failed"
                    if not result.error:
                        result.error = "Batch aborted — a dependency could not be created in the target namespace. A rollback was attempted to delete any already-created objects from the target and restore all objects in the source namespace."
                results.append(result)
                if result.status == "reverted":
                    total_reverted += 1
                else:
                    total_failed += 1
                lbs_done += 1
                status_label = "REVERTED" if result.status == "reverted" else "FAILED"
                print(f"  [{lbs_done}/{total_lbs_in_batches}] {status_label}: '{lb_name}' — dep create failed, rolled back")
            if not args.force_all:
                input("    Press Enter to continue...")
            continue

        # 4b. Create all LBs
        for lb_name in batch_lb_names:
            metadata, spec = lb_planned[lb_name]
            actual_lb_name = lb_rename_map.get(lb_name, lb_name)
            try:
                client.create_http_loadbalancer(target_namespace, metadata, spec)
                created_lbs.append(actual_lb_name)
                if actual_lb_name != lb_name:
                    logger.info("Created LB '%s' as '%s' in '%s'", lb_name, actual_lb_name, target_namespace)
                else:
                    logger.info("Created LB '%s' in '%s'", lb_name, target_namespace)
            except requests.RequestException as exc:
                logger.info("FAILED to create LB '%s': %s", actual_lb_name, exc)
                batch_results[lb_name].error = f"Failed to create load balancer in the target namespace: {exc}"
                create_failed = True
                break

        if create_failed:
            logger.info("LB create failed — rolling back batch...")
            src_ns = lb_src_ns[batch_lb_names[0]]
            rollback_batch(
                client, src_ns, target_namespace,
                deleted_lbs, deleted_deps, created_deps, created_lbs,
                batch_results, batch_dep_results,
                
            )
            for key, dep_result in batch_dep_results.items():
                if dep_result.status == "":
                    dep_result.status = "failed"
                    dep_result.error = "Batch aborted — the load balancer could not be created in the target namespace. A rollback was attempted to restore all objects to their original state in the source namespace."
            for lb_name, result in batch_results.items():
                if result.status != "reverted":
                    result.status = "failed"
                    if not result.error:
                        result.error = "Batch aborted — the load balancer could not be created in the target namespace. A rollback was attempted to delete any already-created objects from the target and restore all objects in the source namespace."
                results.append(result)
                if result.status == "reverted":
                    total_reverted += 1
                else:
                    total_failed += 1
                lbs_done += 1
                status_label = "REVERTED" if result.status == "reverted" else "FAILED"
                print(f"  [{lbs_done}/{total_lbs_in_batches}] {status_label}: '{lb_name}' — LB create failed, rolled back")
            if not args.force_all:
                input("    Press Enter to continue...")
            continue

        # ==============================================================
        # Phase 5: Verify — GET new configs for CNAMEs
        # ==============================================================
        for lb_name in batch_lb_names:
            result = batch_results[lb_name]
            actual_lb_name = lb_rename_map.get(lb_name, lb_name)
            is_le = "encrypt" in result.tls_mode.lower()
            try:
                new_config = client.get_http_loadbalancer(target_namespace, actual_lb_name)
                result.cname_new = XCClient.extract_cname(new_config)
                result.acme_cname_new = XCClient.extract_acme_cname(new_config)

                # For Let's Encrypt LBs the ACME challenge CNAME is
                # populated asynchronously.  Poll a few times so the
                # report can include the actual value.
                if is_le and not result.acme_cname_new:
                    _max_polls = 6  # up to ~30 s
                    sys.stdout.write(
                        f"    Waiting for Let's Encrypt ACME challenge CNAME for '{lb_name}' ..."
                    )
                    sys.stdout.flush()
                    for _poll in range(_max_polls):
                        time.sleep(5)
                        try:
                            new_config = client.get_http_loadbalancer(
                                target_namespace, actual_lb_name,
                            )
                            result.acme_cname_new = XCClient.extract_acme_cname(new_config)
                            if result.acme_cname_new:
                                logger.info(
                                    "ACME challenge CNAME for '%s' available after %ds",
                                    lb_name, (_poll + 1) * 5,
                                )
                                break
                        except requests.RequestException as _poll_exc:
                            logger.debug(
                                "ACME CNAME poll attempt %d for '%s' failed: %s",
                                _poll + 1, lb_name, _poll_exc,
                            )
                        # Progress dot so the user knows we're still working
                        sys.stdout.write(".")
                        sys.stdout.flush()
                    if result.acme_cname_new:
                        sys.stdout.write(" ready\n")
                    else:
                        sys.stdout.write(" not yet available (check XC Console)\n")
                        logger.warning(
                            "ACME challenge CNAME for '%s' not yet available "
                            "after 30s — check the XC Console.",
                            lb_name,
                        )
                    sys.stdout.flush()
            except requests.RequestException as exc:
                logger.warning("Could not fetch new CNAME for '%s': %s", actual_lb_name, exc)
                result.cname_new = "(fetch failed)"
                result.acme_cname_new = "(fetch failed)"
            result.status = "moved"
            # Mark shared dep references as moved too
            for d in result.dependencies:
                if d.status == "skipped":
                    d.status = "moved"
            results.append(result)
            total_moved += 1
            lbs_done += 1
            src_ns = lb_src_ns.get(lb_name, "?")
            print(f"  [{lbs_done}/{total_lbs_in_batches}] MOVED: '{lb_name}' ({src_ns} -> {target_namespace})")

        # Mark all batch deps as moved (the canonical ones)
        for key, dep_result in batch_dep_results.items():
            if dep_result.status == "":
                dep_result.status = "moved"

    # ==================================================================
    # Summary
    # ==================================================================
    print()
    blocked_count = sum(1 for r in results if r.status == "blocked")
    renamed_count = len(lb_rename_map) + len(dep_rename_map)
    rename_note = f"  Renamed: {renamed_count}" if renamed_count else ""
    if dry_run:
        print(
            f"Dry run complete. Planned: {total_moved}  Blocked: {blocked_count}  "
            f"Skipped: {total_skipped}{rename_note}"
        )
    else:
        print(
            f"Done. Moved: {total_moved}  Failed: {total_failed}  "
            f"Blocked: {blocked_count}  Reverted: {total_reverted}  "
            f"Skipped: {total_skipped}{rename_note}"
        )

    # Generate HTML report
    if results:
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M")
        report_prefix = "pre-migration" if dry_run else "mover"
        run_dir = os.path.join(report_dir, f"{report_prefix}_{timestamp}")
        os.makedirs(run_dir, exist_ok=True)
        report_filename = f"{report_prefix}_{timestamp}.html"
        report_path = os.path.join(run_dir, report_filename)

        generate_mover_report(
            results, tenant_name, target_namespace, report_path, dry_run=dry_run,
            batch_graphs=all_batch_graphs,
            manual_rework_items=list(manual_rework_items.values()) if manual_rework_items else None,
        )
        abs_report = os.path.abspath(report_path)
        file_url = f"file://{abs_report}"
        report_label = "Pre-migration report" if dry_run else "HTML report"
        print(f"{report_label} saved to: {file_url}")

    # Dry-run fingerprint management
    if dry_run:
        # Write fingerprint so the next real run can verify
        write_fingerprint(current_fingerprint)
        print(f"Dry-run fingerprint saved. Run without --dry-run to execute.")
    elif not dry_run and total_failed == 0:
        # Successful real run — consume the fingerprint (one-time use)
        delete_fingerprint()

    if total_failed:
        sys.exit(1)
