"""
utils.py

Shared utility functions used across multiple backend modules.
"""

import logging
import os
from datetime import datetime
from typing import Optional


def setup_logging(level: int = logging.INFO) -> None:
    """Configure root logger with a standard format."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def now_iso() -> str:
    """Return the current UTC datetime as an ISO 8601 string."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")


def ensure_dir(path: str) -> None:
    """Create directory (and parents) if it does not exist."""
    os.makedirs(path, exist_ok=True)


def safe_int(value, default: int = 0) -> int:
    """Convert a value to int safely, returning default on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def clamp(value: int, min_val: int = 0, max_val: int = 100) -> int:
    """Clamp an integer between min_val and max_val."""
    return max(min_val, min(max_val, value))
