"""
dotenv_utils.py

Minimal .env file loader and writer — no third-party dependencies.
Reads KEY=VALUE pairs from a .env file and sets them as environment variables.
Also provides a function to write/update individual keys in the .env file.
"""

import os
import logging

logger = logging.getLogger(__name__)

_ENV_PATH = os.path.join(os.path.dirname(__file__), ".env")


def load_env(path: str = _ENV_PATH) -> None:
    """
    Load KEY=VALUE pairs from a .env file into os.environ.
    Skips blank lines and comments (#).
    Does NOT override variables already set in the environment.
    """
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key   = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    logger.info(f"Loaded .env from {path}")


def save_env_vars(updates: dict, path: str = _ENV_PATH) -> None:
    """
    Write or update KEY=VALUE pairs in the .env file.
    Existing keys are updated in place; new keys are appended.
    Other keys in the file are left untouched.
    """
    # Read existing lines
    lines = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    # Update existing keys in place
    remaining = dict(updates)
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        key = stripped.partition("=")[0].strip()
        if key in remaining:
            new_lines.append(f'{key}="{remaining.pop(key)}"\n')
        else:
            new_lines.append(line)

    # Append any new keys not already in file
    for key, value in remaining.items():
        new_lines.append(f'{key}="{value}"\n')

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    logger.info(f"Saved {list(updates.keys())} to {path}")
