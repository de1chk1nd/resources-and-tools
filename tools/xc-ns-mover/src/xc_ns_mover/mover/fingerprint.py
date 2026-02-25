"""
Dry-run fingerprint management for the mover subcommand.

Ensures a ``--dry-run`` was executed before a real migration run by
storing a SHA-256 fingerprint of the current configuration (tenant,
target namespace, CSV content).  A real run verifies that the
fingerprint matches before proceeding.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime

from ..config import PROJECT_ROOT

__all__ = [
    "FINGERPRINT_FILE",
    "compute_fingerprint",
    "write_fingerprint",
    "read_fingerprint",
    "delete_fingerprint",
]

logger = logging.getLogger(__name__)

FINGERPRINT_FILE = os.path.join(PROJECT_ROOT, "config", ".mover_dryrun_fingerprint")


def compute_fingerprint(
    tenant: str, target_namespace: str, csv_path: str,
) -> str:
    """Compute a SHA-256 fingerprint of the current mover configuration.

    The fingerprint covers the tenant name, target namespace, and the
    sorted CSV content (namespace + lb_name pairs).  Any change to these
    inputs invalidates the fingerprint.
    """
    try:
        with open(csv_path, "r") as f:
            csv_content = f.read()
    except OSError:
        csv_content = ""
    # Normalize: sort lines, strip whitespace, ignore comments
    csv_lines = sorted(
        line.strip()
        for line in csv_content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    fp_input = f"{tenant}|{target_namespace}|{'|'.join(csv_lines)}"
    return hashlib.sha256(fp_input.encode()).hexdigest()[:16]


def write_fingerprint(fingerprint: str) -> None:
    """Write the dry-run fingerprint to disk."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(FINGERPRINT_FILE, "w") as f:
            f.write(f"{fingerprint}\n{timestamp}\n")
        logger.debug("Dry-run fingerprint written: %s", FINGERPRINT_FILE)
    except OSError as exc:
        logger.warning("Could not write dry-run fingerprint: %s", exc)


def read_fingerprint() -> tuple[str, str]:
    """Read a previously stored dry-run fingerprint.

    Returns ``(fingerprint, timestamp)`` or ``("", "")`` if no
    fingerprint file exists.
    """
    try:
        with open(FINGERPRINT_FILE, "r") as f:
            lines = f.read().strip().splitlines()
        if len(lines) >= 2:
            return lines[0].strip(), lines[1].strip()
        if lines:
            return lines[0].strip(), ""
    except OSError:
        pass
    return "", ""


def delete_fingerprint() -> None:
    """Remove the dry-run fingerprint file after a successful real run."""
    try:
        os.remove(FINGERPRINT_FILE)
        logger.debug("Dry-run fingerprint removed: %s", FINGERPRINT_FILE)
    except OSError:
        pass
