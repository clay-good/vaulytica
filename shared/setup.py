"""Setup file for the shared models package."""

from setuptools import setup, find_packages

setup(
    name="vaulytica-shared",
    version="0.1.0",
    description="Shared models and utilities for Vaulytica CLI and Web",
    author="Vaulytica Team",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "sqlalchemy>=2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "mypy>=1.0.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
