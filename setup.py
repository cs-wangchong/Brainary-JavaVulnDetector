"""
Setup script for Java Security Detector
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="brainary-java-security",
    version="1.0.0",
    author="Brainary Team",
    description="Intelligent Java vulnerability detection powered by Brainary's multi-agent architecture",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cs-wangchong/Brainary",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Note: This requires the local Brainary SDK to be installed
        # Install from the parent project: python -m pip install -e /path/to/Brainary-DEV
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=22.0",
            "flake8>=5.0",
            "mypy>=0.990",
        ],
        "codeql": [
            # CodeQL CLI should be installed separately
            # See: https://github.com/github/codeql-cli-binaries
        ],
    },
    entry_points={
        "console_scripts": [
            "java-security-scan=java_security_detector.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
