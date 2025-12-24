#!/usr/bin/env python3
"""
FRAGMENTUM Setup
"""

from setuptools import setup, find_packages
from pathlib import Path

# Lê README
readme = Path("README.md")
long_description = readme.read_text() if readme.exists() else ""

setup(
    name="fragmentum",
    version="2.0.0",
    author="FRAGMENTUM Team",
    description="AI-Powered Penetration Testing Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fragmentum/fragmentum",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "python-dotenv>=1.0.0",
        "pexpect>=4.8.0",
        "langchain>=0.1.0",
        "langchain-core>=0.1.0",
        "mcp>=0.9.0",
        "fastapi>=0.109.0",
        "uvicorn>=0.27.0",
        "rich>=13.0.0",
        "pydantic>=2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "ruff>=0.1.0",
        ],
        "all": [
            "langchain-google-genai>=1.0.0",
            "langchain-openai>=0.1.0",
            "langchain-anthropic>=0.1.0",
            "langchain-groq>=0.1.0",
            "chromadb>=0.4.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "fragmentum=fragmentum.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords="pentesting, security, ai, automation, mcp",
)
