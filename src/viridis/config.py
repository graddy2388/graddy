import copy
import ipaddress
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

import yaml

logger = logging.getLogger(__name__)

# Resolve config root: env var > /app (Docker) > repo root (dev)
_PACKAGE_DIR = Path(__file__).parent
_DEV_ROOT = _PACKAGE_DIR.parent.parent
_REPO_ROOT = Path(os.environ.get("VIRIDIS_ROOT", os.environ.get("NETWORK_BOT_ROOT", "/app")))
if not (_REPO_ROOT / "config" / "default.yaml").exists():
    _REPO_ROOT = _DEV_ROOT

_DEFAULT_CONFIG_PATH = _REPO_ROOT / "config" / "default.yaml"
_DEFAULT_TARGETS_PATH = _REPO_ROOT / "config" / "targets.yaml"
_EXAMPLE_TARGETS_PATH = _REPO_ROOT / "config" / "targets.example.yaml"


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _load_yaml(path: Path) -> Dict[str, Any]:
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
    default_cfg = _load_yaml(_DEFAULT_CONFIG_PATH)
    if not default_cfg:
        logger.warning("Default config not found at %s", _DEFAULT_CONFIG_PATH)

    if config_path:
        merged_cfg = _deep_merge(default_cfg, _load_yaml(Path(config_path)))
    else:
        merged_cfg = default_cfg

    targets_file: Path | None = None
    if targets_path:
        targets_file = Path(targets_path)
    elif _DEFAULT_TARGETS_PATH.exists():
        targets_file = _DEFAULT_TARGETS_PATH
    elif _EXAMPLE_TARGETS_PATH.exists():
        targets_file = _EXAMPLE_TARGETS_PATH
    else:
        logger.warning("No targets file found.")

    targets_data: Dict[str, Any] = {}
    if targets_file:
        targets_data = _load_yaml(targets_file)

    return {
        "config": merged_cfg,
        "targets": _expand_cidr_targets(targets_data.get("targets", [])),
    }


_MAX_CIDR_HOSTS = 256


def _expand_cidr_targets(targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    expanded: List[Dict[str, Any]] = []
    for target in targets:
        host = target.get("host", "")
        if "/" in str(host):
            try:
                network = ipaddress.ip_network(host, strict=False)
            except ValueError as exc:
                logger.warning("Could not parse '%s' as CIDR: %s", host, exc)
                expanded.append(target)
                continue
            host_addrs = [str(ip) for ip in network.hosts()] or [str(network.network_address)]
            if len(host_addrs) > _MAX_CIDR_HOSTS:
                logger.warning("CIDR %s capped at %d hosts", host, _MAX_CIDR_HOSTS)
                host_addrs = host_addrs[:_MAX_CIDR_HOSTS]
            base_name = target.get("name", str(host))
            for ip_str in host_addrs:
                t = copy.deepcopy(target)
                t["host"] = ip_str
                t["name"] = f"{base_name} ({ip_str})"
                expanded.append(t)
        else:
            expanded.append(target)
    return expanded
