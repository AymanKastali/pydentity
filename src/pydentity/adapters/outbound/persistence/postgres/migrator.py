from __future__ import annotations

import asyncio
from pathlib import Path

from alembic import command
from alembic.config import Config


async def run_migrations() -> None:
    """Run all pending Alembic migrations (upgrade to head)."""
    ini_path = Path(__file__).parents[6] / "alembic.ini"
    cfg = Config(str(ini_path))
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, command.upgrade, cfg, "head")
