import os
from typing import Any, Dict
import yaml


def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """
    Load YAML configuration and return it as a Python dictionary.

    :param config_path: Path to YAML config file.
    :return: Dictionary with config values.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    # Here you can validate required keys, apply defaults, etc.
    return data
