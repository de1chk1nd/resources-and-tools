"""
Configuration loading and validation for the F5 XC WAAP Troubleshooting Tool.
"""

import logging
import os
from pathlib import Path

import yaml

__all__ = ["DEFAULT_CONFIG_PATH", "PROJECT_ROOT", "ConfigError", "load_config"]

logger = logging.getLogger(__name__)

# Default config path — relative to the project root (two levels up from this file)
DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config",
    "config.yaml",
)

# Project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ConfigError(Exception):
    """Raised when the configuration file is missing or invalid."""


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
        "request.namespace": cfg.get("request", {}).get("namespace", ""),
    }
    missing = [
        k for k, v in required.items()
        if not v or v.startswith("your-") or v == "REPLACE_WITH_YOUR_API_TOKEN"
    ]
    if missing:
        raise ConfigError(f"Missing or placeholder values in config: {', '.join(missing)}")

    logger.debug("Config loaded from %s", config_path)
    return cfg
