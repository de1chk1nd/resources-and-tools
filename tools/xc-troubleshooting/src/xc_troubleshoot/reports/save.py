"""
Report file I/O — save generated reports to disk.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

__all__ = ["save_report"]

logger = logging.getLogger(__name__)

# Only allow safe characters in filename components.
_SAFE_FILENAME = re.compile(r'[^\w\-.]')


def _sanitize_filename_part(value: str, max_len: int = 40) -> str:
    """Sanitise a value for use in a filename — remove unsafe chars."""
    return _SAFE_FILENAME.sub('_', value)[:max_len]


def save_report(
    content: str,
    req_id: str,
    src_ip: str,
    output_dir: str,
    fmt: str,
    fqdn: str = "",
    load_balancer: str = "",
) -> str:
    """Save report to disk and return the file path."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Use UTC for consistent timestamps everywhere
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    parts: list[str] = []
    if req_id:
        parts.append(_sanitize_filename_part(req_id[:16]))
    if src_ip:
        parts.append(f"ip_{_sanitize_filename_part(src_ip)}")
    if fqdn:
        parts.append(f"fqdn_{_sanitize_filename_part(fqdn)}")
    if load_balancer:
        parts.append(f"lb_{_sanitize_filename_part(load_balancer[:20])}")
    label = "_".join(parts) if parts else "query"

    ext = "html"
    filename = f"report_{label}_{timestamp}.{ext}"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        f.write(content)

    # Resolve to absolute path so callers can build clickable file:// URIs
    filepath = os.path.abspath(filepath)
    logger.debug("Wrote %d bytes to %s", len(content), filepath)
    return filepath
