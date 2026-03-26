"""
Base module class that all CTF Toolkit modules inherit from.
Provides shared output saving, logging, and result formatting.
"""

import json
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ctf_toolkit.core.config import config
from ctf_toolkit.core.logger import get_logger

console = Console()


class ModuleResult:
    """Structured result from a module action."""

    def __init__(self, module: str, action: str, success: bool = True):
        self.module = module
        self.action = action
        self.success = success
        self.data: Dict[str, Any] = {}
        self.findings: List[str] = []
        self.errors: List[str] = []
        self.timestamp = datetime.utcnow().isoformat()
        self.elapsed: float = 0.0

    def add_finding(self, finding: str) -> None:
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        self.errors.append(error)
        self.success = False

    def set_data(self, key: str, value: Any) -> None:
        self.data[key] = value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "action": self.action,
            "success": self.success,
            "timestamp": self.timestamp,
            "elapsed_seconds": round(self.elapsed, 3),
            "findings": self.findings,
            "errors": self.errors,
            "data": self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class BaseModule(ABC):
    """Abstract base class for all CTF Toolkit modules."""

    MODULE_NAME: str = "base"
    MODULE_DESCRIPTION: str = "Base module"

    def __init__(self) -> None:
        self.logger = get_logger(
            f"ctf_toolkit.{self.MODULE_NAME}",
            log_file=config.get("toolkit", "log_file"),
            level=config.get("toolkit", "log_level", default="INFO"),
        )
        self.output_dir = Path(config.get("toolkit", "output_dir", default="output"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._result: Optional[ModuleResult] = None

    def run(self, action: str, **kwargs) -> ModuleResult:
        """
        Execute a module action with timing and error handling.

        Args:
            action: Action name to execute
            **kwargs: Action-specific arguments

        Returns:
            ModuleResult with findings and data
        """
        self._result = ModuleResult(self.MODULE_NAME, action)
        start = time.monotonic()

        try:
            method_name = action.replace("-", "_")
            method = getattr(self, method_name, None)
            if method is None:
                self._result.add_error(
                    f"Unknown action '{action}' for module '{self.MODULE_NAME}'. "
                    f"Available: {', '.join(self.get_actions())}"
                )
            else:
                method(**kwargs)
        except KeyboardInterrupt:
            self._result.add_error("Interrupted by user.")
        except Exception as e:
            self._result.add_error(f"Unhandled error: {type(e).__name__}: {e}")
            self.logger.exception(f"Error in {self.MODULE_NAME}.{action}")
        finally:
            self._result.elapsed = time.monotonic() - start

        return self._result

    @abstractmethod
    def get_actions(self) -> List[str]:
        """Return list of supported action names."""
        ...

    def save_result(self, result: ModuleResult, filename: Optional[str] = None) -> Path:
        """Save a ModuleResult to a JSON file in the output directory."""
        if filename is None:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"{result.module}_{result.action}_{ts}.json"
        path = self.output_dir / filename
        path.write_text(result.to_json())
        self.logger.info(f"Results saved to [cyan]{path}[/cyan]")
        return path

    def save_raw(self, content: str, filename: str) -> Path:
        """Save raw text content to the output directory."""
        path = self.output_dir / filename
        path.write_text(content)
        self.logger.info(f"Output saved to [cyan]{path}[/cyan]")
        return path

    def print_findings(self, result: ModuleResult) -> None:
        """Pretty-print findings table to console."""
        if result.findings:
            table = Table(title=f"[bold green]{result.module.upper()} → {result.action}[/]")
            table.add_column("#", style="dim", width=4)
            table.add_column("Finding", style="green")
            for i, f in enumerate(result.findings, 1):
                table.add_row(str(i), f)
            console.print(table)

        if result.errors:
            for err in result.errors:
                console.print(f"[bold red][ERROR][/] {err}")

        console.print(
            f"\n[dim]Elapsed: {result.elapsed:.3f}s | "
            f"Success: {'✓' if result.success else '✗'}[/]"
        )
