"""Carga targets.yaml con recarga ligera."""
import os
import yaml

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "targets.yaml")
CONFIG_PATH = os.path.abspath(CONFIG_PATH)

_cache = {}
_cache_mtime = 0

DEFAULTS = {
    "http_targets": [],
    "network": {"subnets": [], "ports": [80, 443], "timeout": 0.5},
    "automations": [],
    "check_intervals": {"http_seconds": 30, "system_seconds": 10, "automation_seconds": 60},
}

def load_config(force=False):
    global _cache, _cache_mtime
    try:
        mtime = os.path.getmtime(CONFIG_PATH)
    except OSError:
        return DEFAULTS
    if not force and _cache and mtime == _cache_mtime:
        return _cache
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    merged = {**DEFAULTS, **data}
    _cache = merged
    _cache_mtime = mtime
    return merged
