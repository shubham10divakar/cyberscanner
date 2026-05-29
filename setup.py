from setuptools import setup, find_packages
import io

# --- Read README.md safely (UTF-8 encoding fixes emoji/Unicode errors) ---
with io.open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cyberscanner",
    version="0.1.0",
    author="Subham Divakar",
    author_email="shubham.divakar@gmail.com",
    description="Open-source vulnerability scanner for Python and JavaScript projects — CLI tool and Python library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shubham10divakar/cyberscanner",
    project_urls={
        "Bug Tracker":   "https://github.com/shubham10divakar/cyberscanner/issues",
        "Documentation": "https://github.com/shubham10divakar/cyberscanner#readme",
        "Changelog":     "https://github.com/shubham10divakar/cyberscanner/releases",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    install_requires=[
        "typer[all]>=0.9.0",
        "httpx>=0.24.0",
        "pydantic>=2.0.0",
        "packaging>=21.0",
        'tomli>=1.1.0; python_version < "3.11"',
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-asyncio>=0.21",
            "respx>=0.20",
            "build>=1.0",
            "twine>=5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cyberscanner=cyberscanner.cli:app",
        ],
    },
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
        "Environment :: Console",
    ],
    keywords=[
        "security", "vulnerability", "scanner", "CVE", "GHSA",
        "dependencies", "secrets", "sast", "osv", "pypi", "npm",
    ],
    python_requires=">=3.8",
)
