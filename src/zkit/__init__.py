"""Fast local evidence for AI agents decompiling GameCube games and porting them with matching behavior."""

import os

__version__ = "0.11.1"
# GitHub owner/name used by `setup` and in hints. ZKIT_REPOSITORY overrides it (a fork, or a local folder).
REPOSITORY = os.environ.get("ZKIT_REPOSITORY") or "zeroz41/zkit-gcnx"
