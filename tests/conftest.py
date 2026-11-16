"""Shared pytest hooks for the whole test suite."""

from __future__ import annotations

# What each character in pytest's progress line means.
_LEGEND = [
    (".", "passed"),
    ("F", "failed (an assert was wrong)"),
    ("E", "error (crashed in setup/teardown, before or after the test)"),
    ("s", "skipped (not run, e.g. a needed service or tool is missing)"),
    ("x", "xfail: expected to fail, and it did"),
    ("X", "xpass: expected to fail, but it passed"),
]


def pytest_report_header(config):
    """Show a short key for the progress characters before the test runs"""
    lines = ["key:"]
    for char, meaning in _LEGEND:
        lines.append(f" {char} {meaning}")
    return lines