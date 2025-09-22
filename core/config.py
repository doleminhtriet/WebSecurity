import os, yaml
from typing import Any, Dict

def load_config(path: str = None) -> Dict[str, Any]:
    cfg_path = path or os.getenv("PHISH_CFG", "config/base.yaml")
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
