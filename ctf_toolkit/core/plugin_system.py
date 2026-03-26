"""
Plugin system for CTF Toolkit.
Dynamically discovers and loads external plugin modules.
"""

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type

from ctf_toolkit.core.base_module import BaseModule
from ctf_toolkit.core.logger import get_logger

logger = get_logger("ctf_toolkit.plugins")


class PluginRegistry:
    """Registry for all loaded toolkit modules (built-in + plugins)."""

    _registry: Dict[str, Type[BaseModule]] = {}

    @classmethod
    def register(cls, module_class: Type[BaseModule]) -> None:
        """Register a module class by its MODULE_NAME."""
        name = module_class.MODULE_NAME
        cls._registry[name] = module_class
        logger.debug(f"Registered module: [cyan]{name}[/cyan]")

    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseModule]]:
        """Retrieve a module class by name."""
        return cls._registry.get(name)

    @classmethod
    def list_modules(cls) -> List[str]:
        """List all registered module names."""
        return sorted(cls._registry.keys())

    @classmethod
    def load_builtin_modules(cls) -> None:
        """Import and register all built-in modules."""
        builtin = [
            "ctf_toolkit.modules.binary.binary_module",
            "ctf_toolkit.modules.crypto.crypto_module",
            "ctf_toolkit.modules.stego.stego_module",
            "ctf_toolkit.modules.web.web_module",
        ]
        for module_path in builtin:
            try:
                importlib.import_module(module_path)
                logger.debug(f"Loaded built-in: {module_path}")
            except ImportError as e:
                logger.warning(f"Could not load built-in module '{module_path}': {e}")

    @classmethod
    def load_plugin_dir(cls, plugin_dir: str) -> int:
        """
        Scan a directory for plugin files and load them.

        Returns:
            Number of plugins successfully loaded
        """
        path = Path(plugin_dir)
        if not path.exists():
            logger.debug(f"Plugin directory '{plugin_dir}' does not exist, skipping.")
            return 0

        loaded = 0
        for plugin_file in path.glob("*.py"):
            if plugin_file.stem.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"ctf_plugins.{plugin_file.stem}", plugin_file
                )
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules[spec.name] = mod
                    spec.loader.exec_module(mod)
                    loaded += 1
                    logger.info(f"Loaded plugin: [cyan]{plugin_file.name}[/cyan]")
            except Exception as e:
                logger.error(f"Failed to load plugin '{plugin_file.name}': {e}")

        return loaded


def module(cls: Type[BaseModule]) -> Type[BaseModule]:
    """
    Decorator to auto-register a module class.

    Usage:
        @module
        class MyModule(BaseModule):
            MODULE_NAME = "mymodule"
    """
    PluginRegistry.register(cls)
    return cls
