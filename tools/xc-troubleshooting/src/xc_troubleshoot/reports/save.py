"""
Report file I/O — save generated reports to disk.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path

__all__ = ["save_report"]

logger = logging.getLogger(__name__)


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

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    parts: list[str] = []
    if req_id:
        parts.append(req_id[:16].replace("/", "_").replace(" ", "_"))
    if src_ip:
        parts.append(f"ip_{src_ip.replace('.', '-')}")
    if fqdn:
        parts.append(f"fqdn_{fqdn.replace('.', '-')}")
    if load_balancer:
        parts.append(f"lb_{load_balancer[:20].replace(' ', '_')}")
    label = "_".join(parts) if parts else "query"

    ext = {"markdown": "md", "html": "html", "json": "json"}.get(fmt, "md")
    filename = f"report_{label}_{timestamp}.{ext}"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        f.write(content)

    logger.debug("Wrote %d bytes to %s", len(content), filepath)
    return filepath
