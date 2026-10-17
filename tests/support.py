"""Imported first by every test module: the run never touches the user's real config, cache or state."""

import atexit
import os
import shutil
import tempfile

_ROOT = tempfile.mkdtemp(prefix="zkit-tests-")
for _name in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"):
    os.environ[_name] = os.path.join(_ROOT, _name.lower())
atexit.register(shutil.rmtree, _ROOT, ignore_errors=True)
