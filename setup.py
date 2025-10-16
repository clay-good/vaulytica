"""Setup configuration for Vaulytica."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

# Read requirements
requirements = []
with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

dev_requirements = []
with open("requirements-dev.txt") as f:
    dev_requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="vaulytica",
    version="0.4.0",
    description="AI-powered security event analysis framework with intelligent agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Vaulytica Team",
    author_email="team@vaulytica.com",
    url="https://github.com/clay-good/vaulytica",
    packages=find_packages(exclude=["tests", "tests.*", "test_data"]),
    install_requires=requirements,
    extras_require={
        "dev": dev_requirements,
    },
    entry_points={
        "console_scripts": [
            "vaulytica=vaulytica.cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    keywords="security analysis ai incident-response threat-intelligence soar",
    project_urls={
        "Bug Reports": "https://github.com/clay-good/vaulytica/issues",
        "Source": "https://github.com/clay-good/vaulytica",
        "Documentation": "https://github.com/clay-good/vaulytica#readme",
    },
)

