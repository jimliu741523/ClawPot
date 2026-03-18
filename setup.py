from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="clawpot",
    version="0.1.0",
    author="ClawPot Contributors",
    description="OpenClaw 非法行為監控蜜罐系統",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jimliu741523/ClawPot",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "full": [
            "psutil>=5.9.0",
            "watchdog>=3.0.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "clawpot=clawpot.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="honeypot, security, monitoring, openclaw, detection",
)
