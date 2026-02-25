"""
Shared logging configuration for xc-ns-mover subcommands.

Provides a file handler (always DEBUG) and a console handler (WARNING
by default, DEBUG when verbose).
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime

from .config import PROJECT_ROOT

# Log directory — always in logs/
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")


def setup_logging(verbose: bool = False, log_prefix: str = "xc_ns_mover") -> str:
    """Configure logging with a file handler and an optional console handler.

    - File handler: always DEBUG level, writes to logs/<prefix>_<timestamp>.log
    - Console handler: WARNING+ by default (errors/warnings always visible).
      When *verbose* is True, console level drops to DEBUG so all detail is
      printed to the terminal as well.

    Returns the path to the log file.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    log_path = os.path.join(LOG_DIR, f"{log_prefix}_{timestamp}.log")

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Remove any pre-existing handlers (e.g. from basicConfig)
    root_logger.handlers.clear()

    # File handler — always captures everything
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)
    root_logger.addHandler(file_handler)

    # Console handler — minimal unless verbose
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console_fmt = logging.Formatter(
        "%(levelname)-8s  %(message)s" if not verbose
        else "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    console_handler.setFormatter(console_fmt)
    root_logger.addHandler(console_handler)

    return log_path
