"""Scaffold smoke tests.

These exist so the skeleton is verifiable: the package imports from the src
layout and pytest is wired up correctly. Real tests arrive with real logic.
"""

import sys

import graphgate


def test_package_imports():
    assert graphgate.__version__ == "0.1.0"


def test_running_on_supported_python():
    """CLAUDE.md pins Python 3.12; catch an accidental 3.11 env early."""
    assert sys.version_info >= (3, 12), (
        f"GraphGate requires Python 3.12+, running {sys.version_info.major}."
        f"{sys.version_info.minor}"
    )
