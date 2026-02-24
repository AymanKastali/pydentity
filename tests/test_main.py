"""Tests for pydentity.main."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest

from pydentity.main import main


def test_main(caplog: pytest.LogCaptureFixture) -> None:
    """Test that main() logs the expected greeting."""
    with caplog.at_level(logging.INFO):
        main()
    assert "pydentity" in caplog.text
    assert "is running" in caplog.text
