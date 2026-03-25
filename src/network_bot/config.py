import copy
import logging
from pathlib import Path
from typing import Any, Dict

import yaml

logger = logging.getLogger(__name__)

# Default config file location relative to this file
_PACKAGE_DIR = Path(__file__).parent
_REPO_ROOT = _PACKAGE_DIR.parent.parent
_DEFAULT_CONFIG_PATH = _REPO_ROOT / "config" / "default.yaml"
_DEFAULT_TARGETS_PATH = _REPO_ROOT / "config" / "targets.yaml"
_EXAMPLE_TARGETS_PATH = _REPO_ROOT / "config" / "targets.example.yaml"


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge override dict into base dict."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _load_yaml(path: Path) -> Dict[str, Any]:
    """Load a YAML file and return its contents as a dict."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        logger.debug("Config file not found: %s", path)
        return {}
    except yaml.YAMLError as exc:
        logger.error("Failed to parse YAML file %s: %s", path, exc)
        raise


def load_config(
    config_path: str | None = None,
    targets_path: str | None = None,
) -> Dict[str, Any]:
    """Load and merge configuration files.

    Args:
        config_path: Path to an optional user config YAML that overrides defaults.
        targets_path: Path to the targets YAML file. Falls back to
                      config/targets.yaml, then config/targets.example.yaml.

    Returns:
        Dict with keys:
          - 'config': merged scanner configuration
          - 'targets': list of target dicts
    """
    # Load default config
    default_cfg = _load_yaml(_DEFAULT_CONFIG_PATH)
    if not default_cfg:
        logger.warning("Default config not found at %s; using empty defaults", _DEFAULT_CONFIG_PATH)

    # Load user override config if provided
    if config_path:
        user_cfg = _load_yaml(Path(config_path))
        merged_cfg = _deep_merge(default_cfg, user_cfg)
        logger.debug("Merged user config from %s", config_path)
    else:
        merged_cfg = default_cfg

    # Load targets
    targets_file: Path | None = None
    if targets_path:
        targets_file = Path(targets_path)
    elif _DEFAULT_TARGETS_PATH.exists():
        targets_file = _DEFAULT_TARGETS_PATH
    elif _EXAMPLE_TARGETS_PATH.exists():
        targets_file = _EXAMPLE_TARGETS_PATH
        logger.info(
            "No targets.yaml found; using example targets from %s. "
            "Copy to config/targets.yaml and customize.",
            _EXAMPLE_TARGETS_PATH,
        )
    else:
        logger.warning("No targets file found. Provide --targets or create config/targets.yaml.")

    targets_data: Dict[str, Any] = {}
    if targets_file:
        targets_data = _load_yaml(targets_file)

    targets = targets_data.get("targets", [])

    return {
        "config": merged_cfg,
        "targets": targets,
    }
