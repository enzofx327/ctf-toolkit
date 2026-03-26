"""
Shared pytest fixtures and configuration.
"""

import pytest
from pathlib import Path


@pytest.fixture(scope="session")
def output_dir(tmp_path_factory):
    """Shared output directory for all tests."""
    path = tmp_path_factory.mktemp("output")
    return path


@pytest.fixture(autouse=True)
def patch_config_output(tmp_path, monkeypatch):
    """Redirect all module output to tmp_path during tests."""
    from ctf_toolkit.core import config as cfg_module
    monkeypatch.setattr(
        cfg_module.config, "get",
        lambda *keys, default=None: (
            str(tmp_path) if keys == ("toolkit", "output_dir") else
            "DEBUG" if keys == ("toolkit", "log_level") else
            default
        )
    )
