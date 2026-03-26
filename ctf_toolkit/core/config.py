"""
Configuration management for CTF Toolkit.
Loads settings from config.yaml and .env files.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dotenv import load_dotenv

# Load .env file if present
load_dotenv()

DEFAULT_CONFIG = {
    "toolkit": {
        "version": "1.0.0",
        "output_dir": "output",
        "log_level": "INFO",
        "log_file": "logs/toolkit.log",
        "plugins_dir": "plugins_external",
        "auto_save": True,
        "color_output": True,
    },
    "binary": {
        "default_arch": "amd64",
        "rop_depth": 5,
        "overflow_padding": 512,
    },
    "crypto": {
        "xor_max_keylen": 32,
        "freq_analysis_top": 10,
    },
    "stego": {
        "lsb_bits": 1,
        "temp_dir": "/tmp/ctf_stego",
    },
    "web": {
        "timeout": 10,
        "threads": 10,
        "user_agent": "CTF-Toolkit/1.0 (Security Research)",
        "wordlist_dir": "wordlists",
        "default_wordlist": "common.txt",
        "sqli_delay": 0.5,
    },
}


class Config:
    """Central configuration manager."""

    _instance: Optional["Config"] = None
    _config: Dict[str, Any] = {}

    def __new__(cls) -> "Config":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load()
        return cls._instance

    def _load(self) -> None:
        """Load configuration from file and environment."""
        self._config = dict(DEFAULT_CONFIG)

        config_path = Path(os.getenv("CTF_CONFIG", "config.yaml"))
        if config_path.exists():
            with open(config_path) as f:
                file_config = yaml.safe_load(f) or {}
            self._deep_merge(self._config, file_config)

        # Environment overrides
        env_overrides = {
            "CTF_OUTPUT_DIR": ("toolkit", "output_dir"),
            "CTF_LOG_LEVEL": ("toolkit", "log_level"),
            "CTF_PLUGINS_DIR": ("toolkit", "plugins_dir"),
            "CTF_WEB_TIMEOUT": ("web", "timeout"),
            "CTF_WEB_THREADS": ("web", "threads"),
        }
        for env_key, config_path_tuple in env_overrides.items():
            value = os.getenv(env_key)
            if value:
                section, key = config_path_tuple
                self._config[section][key] = value

    def _deep_merge(self, base: dict, override: dict) -> None:
        """Recursively merge override into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def get(self, *keys: str, default: Any = None) -> Any:
        """Get a nested config value. e.g., config.get('web', 'timeout')"""
        value = self._config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key, default)
            else:
                return default
        return value

    def set(self, *keys: str, value: Any) -> None:
        """Set a nested config value."""
        target = self._config
        for key in keys[:-1]:
            target = target.setdefault(key, {})
        target[keys[-1]] = value

    def all(self) -> Dict[str, Any]:
        """Return full config dict."""
        return self._config


# Singleton instance
config = Config()
