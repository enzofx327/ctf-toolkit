"""
CTF Toolkit - setup.py
Allows installation via: pip install -e .
"""

from setuptools import setup, find_packages
from pathlib import Path

long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="ctf-toolkit",
    version="1.0.0",
    author="CTF Toolkit",
    description="Modular CTF framework for binary exploitation, cryptography, steganography, and web exploitation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.9",
    install_requires=[
        "rich>=13.7.0",
        "python-dotenv>=1.0.0",
        "PyYAML>=6.0.1",
        "requests>=2.31.0",
        "urllib3>=2.0.7",
        "Pillow>=10.2.0",
    ],
    extras_require={
        "pwn": ["pwntools>=4.12.0"],
        "dev": ["pytest>=8.1.0", "pytest-cov>=5.0.0"],
    },
    entry_points={
        "console_scripts": [
            "toolkit=ctf_toolkit.core.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Intended Audience :: Developers",
    ],
    include_package_data=True,
    package_data={
        "ctf_toolkit": ["py.typed"],
    },
)
