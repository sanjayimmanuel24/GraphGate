"""The security gate: static analysis of a change, and later its triage.

``findings`` and ``analysers`` (BUILD_PLAN 3.1) run Semgrep and Bandit over the
files a turn changed and say which findings the change introduced. They are
the first stage of every gate condition and know nothing about the graph.
"""
