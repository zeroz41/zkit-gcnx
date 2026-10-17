"""Where the toolkit keeps its own files: config, cache and state, per the XDG variables.

Folders from before the rename (gcn-zkit) are moved once to the new names, so project registrations, handoff
notes and baselines carry over.
"""

from __future__ import annotations

import os
from pathlib import Path

NAME = "zkit"
LEGACY = "gcn-zkit"


def _home(variable: str, default: Path) -> Path:
    base = Path(os.environ.get(variable) or default)
    new, old = base / NAME, base / LEGACY
    if not new.exists() and old.is_dir():
        try:
            old.rename(new)
        except OSError:
            return old
    return new


def config_home() -> Path:
    return _home("XDG_CONFIG_HOME", Path.home() / ".config")


def cache_home() -> Path:
    return _home("XDG_CACHE_HOME", Path.home() / ".cache")


def state_home() -> Path:
    return _home("XDG_STATE_HOME", Path.home() / ".local" / "state")
