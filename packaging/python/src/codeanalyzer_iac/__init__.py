"""Prebuilt ``caniac`` (codeanalyzer-iac) backend binary for CLDK.

This package carries the platform-specific, self-contained ``caniac``
executable (cross-compiled from this repo with CGO disabled) and exposes its
filesystem path. CLDK's Python SDK depends on this package and calls
:func:`bin_path` to locate the analyzer, exactly as it imports
``codeanalyzer-python`` for the Python backend.

Each published wheel is platform-tagged and contains the single binary for that
platform; pip resolves the correct wheel at install time.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

__version__ = "0.1.0"

__all__ = ["bin_path", "__version__"]

_BINARY_NAME = "caniac" + (".exe" if sys.platform == "win32" else "")


def bin_path() -> Path:
    """Return the absolute path to the bundled ``caniac`` binary.

    Raises:
        FileNotFoundError: if the wheel for this platform did not include a binary
            (e.g. an unsupported platform, or a source/dev install with no build run).
    """
    # The wheel is always installed unzipped, so the binary sits next to this
    # module. importlib.resources.as_file() would be the general answer, but it
    # deletes an extracted temp copy when its context exits -- and this function
    # returns a path the caller executes later.
    path = Path(__file__).resolve().parent / "_bin" / _BINARY_NAME

    if not path.exists():
        raise FileNotFoundError(
            f"Bundled caniac binary not found at {path}. "
            "This usually means there is no prebuilt wheel for your platform; "
            "build the binary with `make build` and point CLDK at it via "
            "analysis_backend_path."
        )

    # Wheels may not preserve the executable bit on POSIX; restore it best-effort.
    if os.name == "posix":
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    return path
