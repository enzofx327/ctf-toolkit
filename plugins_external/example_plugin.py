"""
Example external plugin for CTF Toolkit.

To create your own plugin:
1. Copy this file to the plugins_external/ directory
2. Rename it (e.g., my_module.py)
3. Implement your module class
4. The toolkit will auto-load it on startup

Plugins are auto-discovered from the plugins_external/ directory.
"""

from typing import List
from ctf_toolkit.core.base_module import BaseModule
from ctf_toolkit.core.plugin_system import module


@module
class ExamplePlugin(BaseModule):
    """Example plugin module — replace with your own implementation."""

    MODULE_NAME = "example"
    MODULE_DESCRIPTION = "Example plugin — shows how to extend the toolkit"

    def get_actions(self) -> List[str]:
        return ["hello", "echo"]

    def hello(self, **kwargs) -> None:
        """Simple hello world action."""
        self._result.add_finding("Hello from the example plugin!")
        self._result.add_finding("You can extend this toolkit by creating plugins.")
        self._result.set_data("plugin", "example")

    def echo(self, message: str = "No message provided", **kwargs) -> None:
        """Echo a message back."""
        self._result.add_finding(f"Echo: {message}")
