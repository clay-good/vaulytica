"""
Vaulytica API Client SDK - Setup
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="vaulytica-client",
    version="1.0.0",
    author="Vaulytica Team",
    author_email="support@vaulytica.com",
    description="Python client SDK for the Vaulytica API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/vaulytica",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.24.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "respx>=0.20.0",
        ],
    },
)
