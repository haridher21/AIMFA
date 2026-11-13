"""E2E fixtures: re-export the in-process stack helpers.

Pytest only auto-loads conftest files from a test's own directory and its parents.
"""

from tests.integration.conftest import (  # noqa: F401
    clock,
    h,
    settings,
    stack,
)
