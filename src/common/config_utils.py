"""Shared runtime configuration helpers."""

import json
import logging
import os

logger = logging.getLogger(__name__)


def load_runtime_config(config_path):
    """Load JSON runtime config if present."""
    if not config_path:
        return {}
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(
            "Failed to load runtime config '%s' (%s). Using safe defaults.",
            config_path,
            exc,
        )
        return {}

    if not isinstance(config, dict):
        logger.warning(
            "Runtime config '%s' must be a JSON object. Using safe defaults.",
            config_path,
        )
        return {}
    return config


def cfg_get(config, key, default=None):
    """Get nested config values with dot notation."""
    value = config
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value
