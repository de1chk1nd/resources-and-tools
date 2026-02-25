"""
Configuration loading and validation for the F5 XC Namespace LB Mover.
"""

import logging
import os
import re
from pathlib import Path

import yaml

__all__ = [
    "DEFAULT_CONFIG_PATH",
    "PROJECT_ROOT",
    "ConfigError",
    "load_config",
    "resolve_namespaces",
    "validate_xc_name",
]

# F5 XC object names: lowercase alphanumeric, hyphens, dots; 1-64 chars.
_XC_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{0,63}$")

logger = logging.getLogger(__name__)

# Default config path — relative to the project root (two levels up from this file)
DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config",
    "config.yaml",
)

# Project root directory
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


class ConfigError(Exception):
    """Raised when the configuration file is missing or invalid."""


def validate_xc_name(name: str, label: str = "name") -> None:
    """Validate that *name* is a legal F5 XC object/namespace identifier.

    XC names are typically lowercase alphanumeric with hyphens and dots,
    1-64 characters.  This prevents URL-injection via crafted namespace
    or resource names in CSV input.

    Raises:
        ConfigError: If the name is invalid.
    """
    if not name or not _XC_NAME_RE.match(name):
        raise ConfigError(
            f"Invalid {label}: {name!r} — must be 1-64 characters, "
            f"lowercase alphanumeric, hyphens, or dots."
        )


def load_config(config_path: str) -> dict:
    """Load and validate the YAML configuration file.

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
        cfg = yaml.safe_load(f)

    # Basic validation
    required = {
        "tenant.name": cfg.get("tenant", {}).get("name", ""),
        "auth.api_token": cfg.get("auth", {}).get("api_token", ""),
    }
    missing = [
        k
        for k, v in required.items()
        if not v or v.startswith("your-") or v == "REPLACE_WITH_YOUR_API_TOKEN"
    ]
    if missing:
        raise ConfigError(
            f"Missing or placeholder values in config: {', '.join(missing)}"
        )

    # Normalise namespace filter lists (ensure they are always plain lists)
    ns_cfg = cfg.get("namespaces", {}) or {}
    include = ns_cfg.get("include") or []
    exclude = ns_cfg.get("exclude") or []

    if not isinstance(include, list):
        raise ConfigError("namespaces.include must be a list")
    if not isinstance(exclude, list):
        raise ConfigError("namespaces.exclude must be a list")

    # Warn on overlap (same ns in both lists — exclude wins, but it's likely a mistake)
    overlap = set(include) & set(exclude)
    if overlap:
        logger.warning(
            "Namespaces appear in BOTH include and exclude lists (exclude wins): %s",
            ", ".join(sorted(overlap)),
        )

    # Normalise mover settings
    mover_cfg = cfg.get("mover", {}) or {}
    conflict_prefix = mover_cfg.get("conflict_prefix", "")
    if conflict_prefix and not isinstance(conflict_prefix, str):
        raise ConfigError("mover.conflict_prefix must be a string")

    logger.debug("Config loaded from %s", config_path)
    return cfg


def resolve_namespaces(
    all_namespaces: list[str],
    include: list[str],
    exclude: list[str],
) -> list[str]:
    """Apply include/exclude filtering to the full namespace list.

    Logic:
        - include only  -> start from include list (intersected with what exists)
        - exclude only  -> start from all, remove exclude entries
        - both          -> start from include list, then remove exclude entries
        - neither       -> all namespaces
    """
    has_include = len(include) > 0
    has_exclude = len(exclude) > 0
    all_set = set(all_namespaces)

    # Step 1: determine the base set
    if has_include:
        base = [ns for ns in all_namespaces if ns in set(include)]
        unknown = set(include) - all_set
        if unknown:
            logger.warning(
                "Namespaces in include list but not found on tenant: %s",
                ", ".join(sorted(unknown)),
            )
    else:
        base = list(all_namespaces)

    # Step 2: apply exclusions
    if has_exclude:
        exclude_set = set(exclude)
        base = [ns for ns in base if ns not in exclude_set]

    return base
