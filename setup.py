"""
setup.py — full setuptools configuration for cyberscanner.

This file contains all project metadata so the package can be built and
installed with both modern tools (pip install / python -m build via
pyproject.toml) and older tools that still call setup.py directly.

All metadata here must stay in sync with pyproject.toml.
"""
from __future__ import annotations

import os
from pathlib import Path

from setuptools import find_packages, setup

HERE = Path(__file__).parent

# Read the long description from README.md
long_description = (HERE / "README.md").read_text(encoding="utf-8")

setup(
    # -------------------------------------------------------------------
    # Identity
    # -------------------------------------------------------------------
    name="cyberscanner",
    version="0.1.0",
    description=(
        "Open-source vulnerability scanner for Python and JavaScript projects "
        "— CLI tool and Python library"
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",

    # -------------------------------------------------------------------
    # Author
    # -------------------------------------------------------------------
    author="Subham Divakar",
    author_email="shubham.divakar@gmail.com",

    # -------------------------------------------------------------------
    # License
    # -------------------------------------------------------------------
    license="MIT",
    license_files=["LICENSE"],

    # -------------------------------------------------------------------
    # URLs (shown as sidebar links on PyPI)
    # -------------------------------------------------------------------
    url="https://github.com/shubham10divakar/cyberscanner",
    project_urls={
        "Homepage":      "https://github.com/shubham10divakar/cyberscanner",
        "Repository":    "https://github.com/shubham10divakar/cyberscanner",
        "Documentation": "https://github.com/shubham10divakar/cyberscanner#readme",
        "Bug Tracker":   "https://github.com/shubham10divakar/cyberscanner/issues",
        "Changelog":     "https://github.com/shubham10divakar/cyberscanner/releases",
    },

    # -------------------------------------------------------------------
    # PyPI classifiers
    # https://pypi.org/classifiers/
    # -------------------------------------------------------------------
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Systems Administration",
        "Environment :: Console",
        "Typing :: Typed",
    ],

    # -------------------------------------------------------------------
    # Search keywords (shown on PyPI)
    # -------------------------------------------------------------------
    keywords=[
        "security", "vulnerability", "scanner", "CVE", "GHSA",
        "dependencies", "secrets", "sast", "osv", "pypi", "npm",
        "dependency-scanning", "secret-detection", "supply-chain",
    ],

    # -------------------------------------------------------------------
    # Package discovery — src/ layout
    # -------------------------------------------------------------------
    package_dir={"": "src"},
    packages=find_packages(where="src"),

    # -------------------------------------------------------------------
    # Include non-Python files (see also MANIFEST.in)
    # -------------------------------------------------------------------
    include_package_data=True,

    # -------------------------------------------------------------------
    # Python version requirement
    # -------------------------------------------------------------------
    python_requires=">=3.8",

    # -------------------------------------------------------------------
    # Runtime dependencies
    # -------------------------------------------------------------------
    install_requires=[
        "typer[all]>=0.9.0",
        "httpx>=0.24.0",
        "pydantic>=2.0.0",
        "packaging>=21.0",
        'tomli>=1.1.0; python_version < "3.11"',
    ],

    # -------------------------------------------------------------------
    # Optional / development dependencies
    # Install with:  pip install cyberscanner[dev]
    # -------------------------------------------------------------------
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-asyncio>=0.21",
            "respx>=0.20",
            "build>=1.0",
            "twine>=5.0",
        ],
    },

    # -------------------------------------------------------------------
    # CLI entry points
    # After install: `cyberscanner` is available as a command
    # -------------------------------------------------------------------
    entry_points={
        "console_scripts": [
            "cyberscanner=cyberscanner.cli:app",
        ],
    },

    # -------------------------------------------------------------------
    # Zip safety — don't install as a zip/egg
    # -------------------------------------------------------------------
    zip_safe=False,
)
